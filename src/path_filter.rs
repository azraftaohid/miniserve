use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use globset::{GlobBuilder, GlobMatcher};

/// Access state of a path relative to the served root directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Path is fully accessible (read, list, view, upload, delete).
    Allowed,
    /// Directory is an excluded ancestor of an explicitly included descendant.
    /// Navigable as a directory stub (lists only Allowed/PassThrough subdirectories;
    /// all direct files, READMEs, archives, uploads, and deletions are blocked).
    PassThrough,
    /// Path is completely restricted across all gates (404 on read/list, 403 on write/delete).
    Denied,
}

#[derive(Debug, Clone)]
pub struct IgnoreRule {
    matcher: GlobMatcher,
    /// Matches any descendant under the matched directory (e.g. `foo/bar/**`).
    /// `None` for wildcard or unanchored `dir_only` include rules like `!*/` so they only
    /// allow directory traversal without whitelisting all nested files.
    descendant_matcher: Option<GlobMatcher>,
    /// Matchers for strict ancestor directories of an anchored include rule.
    ancestor_dir_matchers: Vec<GlobMatcher>,
    is_include: bool,
    dir_only: bool,
    /// For anchored rules without wildcards in the first segment, stores the leading literal
    /// prefix so `can_delete_path` can determine affected subtrees.
    anchored_prefix: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PrefixRules {
    pub excludes: Vec<PathBuf>,
    pub includes: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct IgnoreFileRules {
    pub rules: Vec<IgnoreRule>,
    pub auto_denied: Option<PathBuf>,
}

/// Path filtering engine supporting either CLI exact path-prefixes or a `.gitignore`-style file.
#[derive(Debug, Clone, Default)]
pub enum PathFilter {
    #[default]
    None,
    Prefixes(Arc<PrefixRules>),
    IgnoreFile(Arc<IgnoreFileRules>),
}

/// Normalizes a path into a clean relative `PathBuf` with only `Component::Normal` segments.
pub fn normalize_rel_path(path: impl AsRef<Path>) -> PathBuf {
    let mut buf = PathBuf::new();
    for comp in path.as_ref().components() {
        match comp {
            Component::Normal(c) => buf.push(c),
            Component::ParentDir => {
                buf.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    buf
}

fn has_parent_dir(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
}

fn contains_glob_metachar(s: &str) -> bool {
    s.contains(['*', '?', '[', '{'])
}

impl PathFilter {
    /// Returns `true` if no filtering rules are active.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Constructs a `PathFilter::Prefixes` from CLI `--exclude` and `--include` arguments.
    pub fn from_prefixes(
        raw_excludes: &[impl AsRef<Path>],
        raw_includes: &[impl AsRef<Path>],
    ) -> Result<Self> {
        if raw_excludes.is_empty() && raw_includes.is_empty() {
            return Ok(Self::None);
        }

        if raw_excludes.is_empty() && !raw_includes.is_empty() {
            bail!("'--include' cannot be used without '--exclude'");
        }

        let mut excludes = Vec::with_capacity(raw_excludes.len());
        for raw in raw_excludes {
            let p = raw.as_ref();
            if p.as_os_str().is_empty() || has_parent_dir(p) {
                bail!("Invalid or empty '--exclude' path: {p:?}");
            }
            let norm = normalize_rel_path(p);
            if norm.as_os_str().is_empty() {
                bail!("'--exclude' path cannot resolve to the root directory: {p:?}");
            }
            excludes.push(norm);
        }

        let mut includes = Vec::with_capacity(raw_includes.len());
        for raw in raw_includes {
            let p = raw.as_ref();
            if p.as_os_str().is_empty() || has_parent_dir(p) {
                bail!("Invalid or empty '--include' path: {p:?}");
            }
            let norm = normalize_rel_path(p);
            if norm.as_os_str().is_empty() {
                bail!("'--include' path cannot resolve to the root directory: {p:?}");
            }
            if !excludes
                .iter()
                .any(|exc| norm.starts_with(exc) && &norm != exc)
            {
                bail!(
                    "'--include' path {:?} must be a subpath underneath an '--exclude' path",
                    p
                );
            }
            includes.push(norm);
        }

        Ok(Self::Prefixes(Arc::new(PrefixRules { excludes, includes })))
    }

    /// Constructs a `PathFilter::IgnoreFile` by parsing a `.gitignore`-style file.
    pub fn from_ignore_file(
        file_path: impl AsRef<Path>,
        serve_root: Option<&Path>,
    ) -> Result<Self> {
        let file_path = file_path.as_ref();
        let file = File::open(file_path)
            .with_context(|| format!("Failed to open ignore file {file_path:?}"))?;
        let reader = BufReader::new(file);

        let auto_denied = if let (Some(root), Ok(canon_ignore)) =
            (serve_root, file_path.canonicalize())
            && let Ok(canon_root) = root.canonicalize()
            && let Ok(rel) = canon_ignore.strip_prefix(&canon_root)
        {
            let norm = normalize_rel_path(rel);
            (!norm.as_os_str().is_empty()).then_some(norm)
        } else {
            None
        };

        let mut rules = Vec::new();
        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res
                .with_context(|| format!("Failed to read line {} of {file_path:?}", idx + 1))?;
            if let Some(rule) = Self::parse_ignore_line(&line)
                .with_context(|| format!("Invalid pattern on line {} of {file_path:?}", idx + 1))?
            {
                rules.push(rule);
            }
        }

        if rules.is_empty() && auto_denied.is_none() {
            Ok(Self::None)
        } else {
            Ok(Self::IgnoreFile(Arc::new(IgnoreFileRules {
                rules,
                auto_denied,
            })))
        }
    }

    fn trim_unescaped_trailing_spaces(s: &str) -> &str {
        let bytes = s.as_bytes();
        let mut end = bytes.len();
        while end > 0 && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
            if end >= 2 && bytes[end - 2] == b'\\' {
                break;
            }
            end -= 1;
        }
        &s[..end]
    }

    fn parse_ignore_line(raw_line: &str) -> Result<Option<IgnoreRule>> {
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let trimmed = Self::trim_unescaped_trailing_spaces(line);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(None);
        }

        let (is_include, pattern) = if let Some(rest) = trimmed.strip_prefix('!') {
            (true, rest)
        } else if trimmed.starts_with(r"\#") || trimmed.starts_with(r"\!") {
            (false, &trimmed[1..])
        } else {
            (false, trimmed)
        };

        if pattern.is_empty() {
            return Ok(None);
        }

        #[cfg(windows)]
        let normalized = pattern.replace('\\', "/");
        #[cfg(not(windows))]
        let normalized = pattern.to_string();

        let dir_only = normalized.ends_with('/');
        let stripped = normalized.trim_matches('/');

        if stripped.is_empty() {
            bail!("Pattern cannot be empty or root-only '/'");
        }

        // In gitignore, a pattern with no slash (after stripping trailing slash) can match at any depth,
        // whereas a pattern with a leading or internal slash is anchored to the root.
        let anchored = normalized.starts_with('/') || stripped.contains('/');

        let glob_expr = if anchored {
            stripped.to_string()
        } else {
            format!("**/{stripped}")
        };

        let matcher = GlobBuilder::new(&glob_expr)
            .literal_separator(true)
            .build()
            .map_err(|e| anyhow!(e))?
            .compile_matcher();

        // Do not cascade `descendant_matcher` for `dir_only` include rules that are unanchored
        // or end with a wildcard segment (such as `!*/` or `!/foo/*/`), so `!*/` only permits
        // traversing directories without whitelisting all files inside them.
        let last_segment_is_wildcard = stripped
            .rsplit('/')
            .next()
            .is_some_and(contains_glob_metachar);
        let skip_descendant_cascade =
            is_include && dir_only && (!anchored || last_segment_is_wildcard);

        let descendant_matcher = if skip_descendant_cascade {
            None
        } else {
            let descendant_expr = format!("{glob_expr}/**");
            Some(
                GlobBuilder::new(&descendant_expr)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| anyhow!(e))?
                    .compile_matcher(),
            )
        };

        // Build ancestor directory matchers for anchored include rules so intermediate
        // directories become PassThrough.
        let mut ancestor_dir_matchers = Vec::new();
        if is_include && anchored {
            let parts: Vec<&str> = stripped.split('/').filter(|s| !s.is_empty()).collect();
            let max_ancestor_len = parts.len().saturating_sub(1);
            let mut acc = String::new();
            for part in parts.iter().take(max_ancestor_len) {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(part);
                let anc_matcher = GlobBuilder::new(&acc)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| anyhow!(e))?
                    .compile_matcher();
                ancestor_dir_matchers.push(anc_matcher);
            }
        }

        let anchored_prefix = if anchored {
            let prefix = Self::extract_literal_prefix(stripped);
            (!prefix.as_os_str().is_empty()).then_some(prefix)
        } else {
            None
        };

        Ok(Some(IgnoreRule {
            matcher,
            descendant_matcher,
            ancestor_dir_matchers,
            is_include,
            dir_only,
            anchored_prefix,
        }))
    }

    fn extract_literal_prefix(pattern: &str) -> PathBuf {
        let mut prefix = PathBuf::new();
        for part in pattern.split('/') {
            if part.is_empty() || contains_glob_metachar(part) {
                break;
            }
            prefix.push(part);
        }
        prefix
    }

    fn rule_matches(rule: &IgnoreRule, norm_str: &str, is_dir: bool) -> bool {
        let direct_match = if rule.dir_only {
            is_dir && rule.matcher.is_match(norm_str)
        } else {
            rule.matcher.is_match(norm_str)
        };
        let ancestor_match = rule
            .descendant_matcher
            .as_ref()
            .is_some_and(|dm| dm.is_match(norm_str));
        direct_match || ancestor_match
    }

    fn eval_ignore_rules_single(rules: &[IgnoreRule], norm_str: &str, is_dir: bool) -> PathState {
        let mut state = PathState::Allowed;
        for rule in rules {
            if Self::rule_matches(rule, norm_str, is_dir) {
                state = if rule.is_include {
                    PathState::Allowed
                } else {
                    PathState::Denied
                };
            }
        }
        state
    }

    fn eval_ignore_single_step(ignore: &IgnoreFileRules, norm: &Path, is_dir: bool) -> PathState {
        if let Some(ref auto_denied) = ignore.auto_denied
            && norm == auto_denied
        {
            return PathState::Denied;
        }

        let norm_str = norm.to_string_lossy();
        if norm_str.is_empty() {
            // Evaluate root directory: if a wildcard rule like `*` denies root files, root is
            // PassThrough if any include rule exists, or Denied if everything is excluded.
            let probe_file_allowed =
                Self::eval_ignore_rules_single(&ignore.rules, "__root_probe__", false)
                    == PathState::Allowed;
            if probe_file_allowed {
                return PathState::Allowed;
            }
            let has_any_include = ignore.rules.iter().any(|r| r.is_include);
            return if has_any_include {
                PathState::PassThrough
            } else {
                PathState::Denied
            };
        }

        if Self::eval_ignore_rules_single(&ignore.rules, &norm_str, is_dir) == PathState::Allowed {
            return PathState::Allowed;
        }

        if is_dir {
            for (idx, rule) in ignore.rules.iter().enumerate() {
                if !rule.is_include {
                    continue;
                }
                let matches_ancestor = rule
                    .ancestor_dir_matchers
                    .iter()
                    .any(|anc_m| anc_m.is_match(norm_str.as_ref()));
                if !matches_ancestor {
                    continue;
                }

                // Ensure no subsequent exclude rule in `rules[idx + 1..]` re-excludes this ancestor
                // or the include rule's anchored target prefix without a later re-include.
                let mut overridden_later = false;
                for later in &ignore.rules[idx + 1..] {
                    let hits_current = Self::rule_matches(later, &norm_str, true);
                    let hits_target = rule
                        .anchored_prefix
                        .as_ref()
                        .is_some_and(|p| Self::rule_matches(later, &p.to_string_lossy(), true));
                    if hits_current || hits_target {
                        overridden_later = !later.is_include;
                    }
                }

                if !overridden_later {
                    return PathState::PassThrough;
                }
            }
        }

        PathState::Denied
    }

    fn more_restrictive(a: PathState, b: PathState) -> PathState {
        match (a, b) {
            (PathState::Denied, _) | (_, PathState::Denied) => PathState::Denied,
            (PathState::PassThrough, _) | (_, PathState::PassThrough) => PathState::PassThrough,
            (PathState::Allowed, PathState::Allowed) => PathState::Allowed,
        }
    }

    /// Evaluates the access state of `rel_path` (relative to the served root).
    pub fn evaluate(&self, rel_path: impl AsRef<Path>, is_dir: bool) -> PathState {
        let norm = normalize_rel_path(rel_path);

        match self {
            Self::None => PathState::Allowed,
            Self::Prefixes(prefixes) => {
                let matched_inc = prefixes
                    .includes
                    .iter()
                    .filter(|inc| norm.starts_with(inc.as_path()))
                    .map(|inc| inc.components().count())
                    .max();

                let matched_exc = prefixes
                    .excludes
                    .iter()
                    .filter(|exc| norm.starts_with(exc.as_path()))
                    .map(|exc| exc.components().count())
                    .max();

                let is_allowed = match (matched_inc, matched_exc) {
                    (Some(inc_len), Some(exc_len)) => inc_len >= exc_len,
                    (Some(_), None) => true,
                    (None, Some(_)) => false,
                    (None, None) => true,
                };

                if is_allowed {
                    return PathState::Allowed;
                }

                if is_dir
                    && prefixes
                        .includes
                        .iter()
                        .any(|inc| inc.starts_with(&norm) && inc != &norm)
                {
                    return PathState::PassThrough;
                }

                PathState::Denied
            }
            Self::IgnoreFile(ignore) => {
                if norm.as_os_str().is_empty() {
                    return Self::eval_ignore_single_step(ignore, &norm, true);
                }

                // Enforce the Ancestor Invariant: every parent directory along `norm` must be
                // `Allowed` or `PassThrough` (never `Denied`).
                let mut cur = PathBuf::new();
                let mut components = norm.components().peekable();
                while let Some(comp) = components.next() {
                    cur.push(comp);
                    if components.peek().is_some() {
                        if Self::eval_ignore_single_step(ignore, &cur, true) == PathState::Denied {
                            return PathState::Denied;
                        }
                    } else {
                        return Self::eval_ignore_single_step(ignore, &cur, is_dir);
                    }
                }

                PathState::Allowed
            }
        }
    }

    /// Returns `true` if a file at `rel_path` is allowed to be read, viewed, or downloaded.
    pub fn is_file_allowed(&self, rel_path: impl AsRef<Path>) -> bool {
        self.evaluate(rel_path, false) == PathState::Allowed
    }

    /// Returns the `PathState` for a directory at `rel_path`.
    pub fn dir_state(&self, rel_path: impl AsRef<Path>) -> PathState {
        self.evaluate(rel_path, true)
    }

    /// Evaluates the effective `PathState` of a directory at `rel_path`, intersecting it with
    /// the canonical target's state when `full_path` is a symlink resolving inside `canon_root`.
    pub fn effective_dir_state(
        &self,
        canon_root: &Path,
        full_path: &Path,
        rel_path: impl AsRef<Path>,
    ) -> PathState {
        let lexical = self.dir_state(rel_path);
        if self.is_none() || lexical == PathState::Denied {
            return lexical;
        }
        if let Ok(canon_target) = full_path.canonicalize()
            && let Ok(canon_rel) = canon_target.strip_prefix(canon_root)
        {
            return Self::more_restrictive(lexical, self.dir_state(canon_rel));
        }
        lexical
    }

    /// Verifies that if `full_path` resolves (via symlinks) to a location inside `canon_root`,
    /// the canonical target path is also permitted by `self`.
    pub fn check_canonical_target(&self, canon_root: &Path, full_path: &Path) -> bool {
        if self.is_none() {
            return true;
        }
        let Ok(canon_target) = full_path.canonicalize() else {
            return true;
        };
        let Ok(canon_rel) = canon_target.strip_prefix(canon_root) else {
            // Target is outside served root; allowed when `--no-symlinks` is false.
            return true;
        };
        let is_dir = canon_target.is_dir();
        match self.evaluate(canon_rel, is_dir) {
            PathState::Allowed => true,
            PathState::PassThrough => is_dir,
            PathState::Denied => false,
        }
    }

    /// Returns `true` if `rel_dir` can be downloaded as a tar/zip archive (both lexically and
    /// at its canonical target if it resolves inside `canon_root`).
    ///
    /// Any directory that is `Allowed` or `PassThrough` can be archived; excluded entries inside
    /// it are filtered out during archive creation.
    pub fn effective_can_archive_dir(
        &self,
        canon_root: &Path,
        full_path: &Path,
        rel_dir: impl AsRef<Path>,
    ) -> bool {
        self.effective_dir_state(canon_root, full_path, rel_dir) != PathState::Denied
    }

    /// Returns `true` if `rel_path` is permitted to be deleted via `/rm` based on static rules.
    /// (Note: `rm_file` also scans the directory on disk for any excluded descendants.)
    pub fn can_delete_path(&self, rel_path: impl AsRef<Path>, is_dir: bool) -> bool {
        let norm = normalize_rel_path(rel_path);
        if is_dir {
            if self.dir_state(&norm) != PathState::Allowed {
                return false;
            }
            match self {
                Self::None => true,
                Self::Prefixes(prefixes) => {
                    for exc in &prefixes.excludes {
                        if exc.starts_with(&norm) {
                            let overridden_at_same_path =
                                prefixes.includes.iter().any(|inc| inc == exc);
                            if !overridden_at_same_path {
                                return false;
                            }
                        }
                    }
                    true
                }
                Self::IgnoreFile(ignore) => {
                    if let Some(ref auto_denied) = ignore.auto_denied
                        && auto_denied.starts_with(&norm)
                    {
                        return false;
                    }
                    // Block if any anchored exclude prefix lies inside `norm` and has an active
                    // PassThrough subtree or Denied directory.
                    for rule in &ignore.rules {
                        if !rule.is_include
                            && let Some(ref exc_prefix) = rule.anchored_prefix
                            && exc_prefix.starts_with(&norm)
                            && self.dir_state(exc_prefix) != PathState::Allowed
                        {
                            return false;
                        }
                    }
                    true
                }
            }
        } else {
            self.is_file_allowed(&norm)
        }
    }

    /// Evaluates `can_delete_path` for both `rel_path` and its canonical target inside `canon_root`.
    pub fn effective_can_delete_path(
        &self,
        canon_root: &Path,
        full_path: &Path,
        rel_path: impl AsRef<Path>,
        is_dir: bool,
    ) -> bool {
        if !self.can_delete_path(&rel_path, is_dir) {
            return false;
        }
        if self.is_none() {
            return true;
        }
        if let Ok(canon_target) = full_path.canonicalize()
            && let Ok(canon_rel) = canon_target.strip_prefix(canon_root)
        {
            return self.can_delete_path(canon_rel, canon_target.is_dir());
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn test_prefixes_hierarchy_and_passthrough() {
        let filter = PathFilter::from_prefixes(&["/abc/def"], &["/abc/def/ghi/jkl"]).unwrap();

        assert_eq!(filter.dir_state(""), PathState::Allowed);
        assert_eq!(filter.dir_state("abc"), PathState::Allowed);
        assert_eq!(filter.dir_state("abc/def"), PathState::PassThrough);
        assert_eq!(filter.dir_state("abc/def/ghi"), PathState::PassThrough);
        assert_eq!(filter.dir_state("abc/def/ghi/jkl"), PathState::Allowed);
        assert_eq!(filter.dir_state("abc/def/other"), PathState::Denied);

        assert!(filter.is_file_allowed("public.txt"));
        assert!(filter.is_file_allowed("abc/visible.txt"));
        assert!(!filter.is_file_allowed("abc/def/secret.txt"));
        assert!(!filter.is_file_allowed("abc/def/ghi/mid_secret.txt"));
        assert!(filter.is_file_allowed("abc/def/ghi/jkl/allowed.txt"));
        assert!(filter.is_file_allowed("abc/def/ghi/jkl/sub/nested.txt"));
    }

    #[test]
    fn test_from_prefixes_validation() {
        assert!(PathFilter::from_prefixes(&[""], &[] as &[&str]).is_err());
        assert!(PathFilter::from_prefixes(&["/"], &[] as &[&str]).is_err());
        assert!(PathFilter::from_prefixes(&["../foo"], &[] as &[&str]).is_err());
        assert!(PathFilter::from_prefixes(&[] as &[&str], &["/abc"]).is_err());
        assert!(PathFilter::from_prefixes(&["/abc"], &[""]).is_err());
        assert!(PathFilter::from_prefixes(&["/abc"], &["/other/path"]).is_err());
        assert!(PathFilter::from_prefixes(&["/abc"], &["/abc"]).is_err());
    }

    #[test]
    fn test_can_archive_and_delete() {
        let filter = PathFilter::from_prefixes(&["/abc/def"], &["/abc/def/ghi/jkl"]).unwrap();

        assert_ne!(filter.dir_state(""), PathState::Denied);
        assert_ne!(filter.dir_state("abc"), PathState::Denied);
        assert_ne!(filter.dir_state("abc/def"), PathState::Denied);
        assert_ne!(filter.dir_state("abc/def/ghi"), PathState::Denied);
        assert_ne!(filter.dir_state("abc/def/ghi/jkl"), PathState::Denied);
        assert_ne!(filter.dir_state("other_clean_dir"), PathState::Denied);
        assert_eq!(filter.dir_state("abc/def/other"), PathState::Denied);

        assert!(!filter.can_delete_path("abc", true));
        assert!(!filter.can_delete_path("abc/def", true));
        assert!(!filter.can_delete_path("abc/def/secret.txt", false));
        assert!(filter.can_delete_path("abc/def/ghi/jkl", true));
        assert!(filter.can_delete_path("abc/def/ghi/jkl/allowed.txt", false));
    }

    #[test]
    fn test_ignore_file_rules_and_reinclusion() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "# Comment").unwrap();
        writeln!(tmp, "*.log").unwrap();
        writeln!(tmp, "/abc/def/").unwrap();
        writeln!(tmp, "!/abc/def/ghi/jkl/").unwrap();
        tmp.flush().unwrap();

        let filter = PathFilter::from_ignore_file(tmp.path(), None).unwrap();

        assert!(!filter.is_file_allowed("debug.log"));
        assert!(!filter.is_file_allowed("nested/app.log"));
        assert!(filter.is_file_allowed("readme.md"));

        assert_eq!(filter.dir_state("abc/def"), PathState::PassThrough);
        assert_eq!(filter.dir_state("abc/def/ghi"), PathState::PassThrough);
        assert_eq!(filter.dir_state("abc/def/ghi/jkl"), PathState::Allowed);
        assert!(!filter.is_file_allowed("abc/def/secret.txt"));
        assert!(filter.is_file_allowed("abc/def/ghi/jkl/allowed.txt"));

        // Clean directory deletion is statically allowed even with *.log present
        assert!(filter.can_delete_path("clean_dir", true));
        assert!(!filter.can_delete_path("abc", true));
    }

    #[test]
    fn test_ignore_file_wildcard_reinclusion_and_reexclusion() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "/abc/def/").unwrap();
        writeln!(tmp, "!/abc/def/ghi/jkl/*.txt").unwrap();
        writeln!(tmp, "!/abc/def/dead_parent/dead_branch/").unwrap();
        writeln!(tmp, "/abc/def/dead_parent/dead_branch/").unwrap();
        tmp.flush().unwrap();

        let filter = PathFilter::from_ignore_file(tmp.path(), None).unwrap();

        assert_eq!(filter.dir_state("abc/def"), PathState::PassThrough);
        assert_eq!(filter.dir_state("abc/def/ghi"), PathState::PassThrough);
        assert_eq!(filter.dir_state("abc/def/ghi/jkl"), PathState::PassThrough);
        assert!(filter.is_file_allowed("abc/def/ghi/jkl/notes.txt"));
        assert!(!filter.is_file_allowed("abc/def/ghi/jkl/secret.pdf"));

        // Re-excluded branch should not leave empty PassThrough stubs
        assert_eq!(filter.dir_state("abc/def/dead_parent"), PathState::Denied);
        assert_eq!(
            filter.dir_state("abc/def/dead_parent/dead_branch"),
            PathState::Denied
        );
    }

    #[test]
    fn test_ignore_file_whitelist_idiom_and_ancestor_invariant() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "*").unwrap();
        writeln!(tmp, "!*/").unwrap();
        writeln!(tmp, "!*.pdf").unwrap();
        tmp.flush().unwrap();

        let filter = PathFilter::from_ignore_file(tmp.path(), None).unwrap();

        assert_eq!(filter.dir_state(""), PathState::PassThrough);
        assert!(!filter.is_file_allowed("public.txt"));
        assert!(filter.is_file_allowed("root.pdf"));
        assert_eq!(filter.dir_state("abc"), PathState::Allowed);
        assert_eq!(filter.dir_state("abc/def"), PathState::Allowed);
        assert!(!filter.is_file_allowed("abc/visible.txt"));
        assert!(!filter.is_file_allowed("abc/def/secret.txt"));
        assert!(filter.is_file_allowed("abc/def/doc.pdf"));

        // Ancestor invariant: unanchored include cannot pierce Denied parent dir
        let mut tmp2 = NamedTempFile::new().unwrap();
        writeln!(tmp2, "/private/").unwrap();
        writeln!(tmp2, "!*.pdf").unwrap();
        tmp2.flush().unwrap();

        let filter2 = PathFilter::from_ignore_file(tmp2.path(), None).unwrap();
        assert_eq!(filter2.dir_state("private"), PathState::Denied);
        assert!(!filter2.is_file_allowed("private/secret.pdf"));
        assert!(filter2.is_file_allowed("public/doc.pdf"));
    }

    #[test]
    fn test_ignore_file_auto_denies_self_when_inside_serve_root() {
        let dir = TempDir::new().unwrap();
        let ignore_path = dir.path().join(".miniserveignore");
        {
            let mut f = File::create(&ignore_path).unwrap();
            writeln!(f, "/secret/").unwrap();
        }
        let canon_dir = dir.path().canonicalize().unwrap();
        let filter = PathFilter::from_ignore_file(&ignore_path, Some(dir.path())).unwrap();
        assert!(!filter.is_file_allowed(".miniserveignore"));
        assert!(filter.effective_can_archive_dir(&canon_dir, &canon_dir, ""));
        assert!(!filter.effective_can_archive_dir(&canon_dir, &canon_dir.join("secret"), "secret"));
        assert!(!filter.can_delete_path("", true));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_unix_backslash_preserved_in_prefixes_and_ignore_escapes() {
        let filter = PathFilter::from_prefixes(&["/foo"], &[] as &[&str]).unwrap();
        assert!(filter.is_file_allowed(r"foo\bar.txt"));
        assert!(!filter.is_file_allowed("foo/bar.txt"));

        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, r"\#hash.txt").unwrap();
        writeln!(tmp, r"foo\ bar.txt").unwrap();
        tmp.flush().unwrap();

        let ignore_filter = PathFilter::from_ignore_file(tmp.path(), None).unwrap();
        assert!(!ignore_filter.is_file_allowed("#hash.txt"));
        assert!(!ignore_filter.is_file_allowed("foo bar.txt"));
        assert!(ignore_filter.is_file_allowed("normal.txt"));
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_normalize_rel_path_treats_backslashes_as_separators() {
        assert_eq!(
            normalize_rel_path(r"abc\def\..\ghi\jkl"),
            PathBuf::from("abc/ghi/jkl")
        );
    }
}
