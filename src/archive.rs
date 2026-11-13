use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use libflate::gzip::Encoder;
use serde::Deserialize;
use strum::{Display, EnumIter, EnumString};
use tar::Builder;
use zip::{ZipWriter, write};

use crate::errors::RuntimeError;
use crate::path_filter::{PathFilter, PathState};

/// Context for filtering and symlink handling during archive creation.
#[derive(Clone, Copy)]
pub struct ArchiveContext<'a> {
    /// Normalized path of the archived directory relative to the served root.
    pub rel_dir: &'a Path,
    /// Canonicalized served root directory.
    pub canon_root: &'a Path,
    /// Whether `--no-symlinks` is enabled.
    pub skip_symlinks: bool,
    /// Active path exclusion/inclusion filter.
    pub path_filter: &'a PathFilter,
}

enum WalkStep {
    Enter {
        dir: PathBuf,
        in_symlink: bool,
        canon_to_pop: Option<PathBuf>,
    },
    Exit(PathBuf),
}

/// Available archive methods
#[derive(Deserialize, Clone, Copy, EnumIter, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ArchiveMethod {
    /// Gzipped tarball
    TarGz,

    /// Regular tarball
    Tar,

    /// Regular zip
    Zip,
}

impl ArchiveMethod {
    pub fn extension(self) -> String {
        match self {
            Self::TarGz => "tar.gz",
            Self::Tar => "tar",
            Self::Zip => "zip",
        }
        .to_string()
    }

    pub fn content_type(self) -> String {
        match self {
            Self::TarGz => "application/gzip",
            Self::Tar => "application/tar",
            Self::Zip => "application/zip",
        }
        .to_string()
    }

    pub fn is_enabled(self, tar_enabled: bool, tar_gz_enabled: bool, zip_enabled: bool) -> bool {
        match self {
            Self::TarGz => tar_gz_enabled,
            Self::Tar => tar_enabled,
            Self::Zip => zip_enabled,
        }
    }

    /// Make an archive out of the given directory, and write the output to the given writer.
    ///
    /// Recursively includes allowed files and subdirectories while respecting `ctx.path_filter`.
    ///
    /// If `ctx.skip_symlinks` is `true`, symlinks will not be followed and will just be ignored.
    pub fn create_archive<T, W>(
        self,
        dir: T,
        ctx: ArchiveContext<'_>,
        out: W,
    ) -> Result<(), RuntimeError>
    where
        T: AsRef<Path>,
        W: std::io::Write,
    {
        let dir = dir.as_ref();
        match self {
            Self::TarGz => tar_gz(dir, ctx, out),
            Self::Tar => tar_dir(dir, ctx, out),
            Self::Zip => zip_dir(dir, ctx, out),
        }
    }
}

/// Resolves the top-level folder name used inside the archive and in `Content-Disposition`.
pub fn resolve_archive_root_name(dir: &Path) -> Result<String, RuntimeError> {
    if let Some(name) = dir.file_name() {
        return name.to_str().map(str::to_string).ok_or_else(|| {
            RuntimeError::InvalidPathError(
                "Directory name contains invalid UTF-8 characters".to_string(),
            )
        });
    }
    if let Ok(canon) = dir.canonicalize() {
        if let Some(name) = canon.file_name() {
            return name.to_str().map(str::to_string).ok_or_else(|| {
                RuntimeError::InvalidPathError(
                    "Directory name contains invalid UTF-8 characters".to_string(),
                )
            });
        }
        return Ok("archive".to_string());
    }
    Err(RuntimeError::InvalidPathError(
        "Directory name terminates in \"..\"".to_string(),
    ))
}

fn init_filtered_walk(src_dir: &Path, ctx: ArchiveContext<'_>) -> (bool, HashSet<PathBuf>) {
    let mut active_symlink_ancestors = HashSet::new();
    if ctx.path_filter.is_none() {
        return (false, active_symlink_ancestors);
    }

    let expected_canon = if ctx.rel_dir.as_os_str().is_empty() {
        ctx.canon_root.to_path_buf()
    } else {
        ctx.canon_root.join(ctx.rel_dir)
    };
    let canon_src = src_dir.canonicalize().ok();
    if let Some(ref canon) = canon_src {
        active_symlink_ancestors.insert(canon.clone());
    }
    let root_in_symlink = (!ctx.rel_dir.as_os_str().is_empty() && src_dir.is_symlink())
        || canon_src.is_none_or(|canon| canon != expected_canon);
    (root_in_symlink, active_symlink_ancestors)
}

fn is_symlink_cycle(
    current_dir: &Path,
    entry_path: &Path,
    active_symlink_ancestors: &mut HashSet<PathBuf>,
) -> Option<PathBuf> {
    let Ok(canon_child) = entry_path.canonicalize() else {
        return None;
    };
    if let Ok(canon_cur) = current_dir.canonicalize()
        && canon_cur.starts_with(&canon_child)
    {
        return None;
    }
    if !active_symlink_ancestors.insert(canon_child.clone()) {
        return None;
    }
    Some(canon_child)
}

/// Write a gzipped tarball of `dir` in `out`.
fn tar_gz<W>(dir: &Path, ctx: ArchiveContext<'_>, out: W) -> Result<(), RuntimeError>
where
    W: std::io::Write,
{
    let mut out = Encoder::new(out).map_err(|e| RuntimeError::IoError("GZIP".to_string(), e))?;

    tar_dir(dir, ctx, &mut out)?;

    out.finish()
        .into_result()
        .map_err(|e| RuntimeError::IoError("GZIP finish".to_string(), e))?;

    Ok(())
}

/// Write a tarball of `dir` in `out`.
///
/// The target directory will be saved as a top-level directory in the archive.
///
/// For example, consider this directory structure:
///
/// ```ignore
/// a
/// └── b
///     └── c
///         ├── e
///         ├── f
///         └── g
/// ```
///
/// Making a tarball out of `"a/b/c"` will result in this archive content:
///
/// ```ignore
/// c
/// ├── e
/// ├── f
/// └── g
/// ```
fn tar_dir<W>(dir: &Path, ctx: ArchiveContext<'_>, out: W) -> Result<(), RuntimeError>
where
    W: std::io::Write,
{
    let directory = resolve_archive_root_name(dir)?;

    tar(dir, directory, ctx, out)
        .map_err(|e| RuntimeError::ArchiveCreationError("tarball".to_string(), Box::new(e)))
}

/// Writes a tarball of `src_dir` in `out`.
///
/// The content of `src_dir` will be saved in the archive as a folder named `inner_folder`.
fn tar<W>(
    src_dir: &Path,
    inner_folder: String,
    ctx: ArchiveContext<'_>,
    out: W,
) -> Result<(), RuntimeError>
where
    W: std::io::Write,
{
    let mut tar_builder = Builder::new(out);
    tar_builder.follow_symlinks(!ctx.skip_symlinks);

    if ctx.path_filter.is_none() {
        // Recursively adds the content of src_dir into the archive stream
        tar_builder
            .append_dir_all(inner_folder, src_dir)
            .map_err(|e| {
                RuntimeError::IoError(
                    format!(
                        "Failed to append the content of '{}' to the TAR archive",
                        src_dir.to_str().unwrap_or("file")
                    ),
                    e,
                )
            })?;
    } else {
        tar_builder
            .append_dir(&inner_folder, src_dir)
            .map_err(|e| {
                RuntimeError::IoError(
                    format!(
                        "Failed to append directory '{}' to the TAR archive",
                        src_dir.display()
                    ),
                    e,
                )
            })?;

        let (root_in_symlink, mut active_symlink_ancestors) = init_filtered_walk(src_dir, ctx);
        let mut stack = vec![WalkStep::Enter {
            dir: src_dir.to_path_buf(),
            in_symlink: root_in_symlink,
            canon_to_pop: None,
        }];

        while let Some(step) = stack.pop() {
            let (current_dir, in_symlink) = match step {
                WalkStep::Exit(canon) => {
                    active_symlink_ancestors.remove(&canon);
                    continue;
                }
                WalkStep::Enter {
                    dir,
                    in_symlink,
                    canon_to_pop,
                } => {
                    if let Some(canon) = canon_to_pop {
                        stack.push(WalkStep::Exit(canon));
                    }
                    (dir, in_symlink)
                }
            };

            let dir_iter = std::fs::read_dir(&current_dir)
                .map_err(|e| RuntimeError::IoError("Could not read directory".to_string(), e))?;

            for entry in dir_iter {
                let entry_path = entry
                    .map_err(|e| {
                        RuntimeError::IoError("Could not read directory entry".to_string(), e)
                    })?
                    .path();

                let Ok(sym_meta) = std::fs::symlink_metadata(&entry_path) else {
                    continue;
                };
                let is_symlink = sym_meta.file_type().is_symlink();
                if is_symlink && ctx.skip_symlinks {
                    continue;
                }

                let rel_in_archive = entry_path.strip_prefix(src_dir).map_err(|_| {
                    RuntimeError::ArchiveCreationDetailError(
                        "Could not strip archive base directory".to_string(),
                    )
                })?;
                let rel_to_serve_root = ctx.rel_dir.join(rel_in_archive);

                if (in_symlink || is_symlink)
                    && !ctx
                        .path_filter
                        .check_canonical_target(ctx.canon_root, &entry_path)
                {
                    continue;
                }

                let entry_metadata = if is_symlink {
                    let Ok(meta) = std::fs::metadata(&entry_path) else {
                        // Skip dangling symlinks cleanly when filtering
                        continue;
                    };
                    meta
                } else {
                    sym_meta
                };

                let archive_entry_path = Path::new(&inner_folder).join(rel_in_archive);

                if entry_metadata.is_dir() {
                    let dir_state = if in_symlink || is_symlink {
                        ctx.path_filter.effective_dir_state(
                            ctx.canon_root,
                            &entry_path,
                            &rel_to_serve_root,
                        )
                    } else {
                        ctx.path_filter.dir_state(&rel_to_serve_root)
                    };
                    if dir_state == PathState::Denied {
                        continue;
                    }

                    let child_in_symlink = in_symlink || is_symlink;
                    let canon_to_pop = if child_in_symlink {
                        let Some(canon_child) = is_symlink_cycle(
                            &current_dir,
                            &entry_path,
                            &mut active_symlink_ancestors,
                        ) else {
                            continue;
                        };
                        Some(canon_child)
                    } else {
                        None
                    };

                    tar_builder
                        .append_dir(&archive_entry_path, &entry_path)
                        .map_err(|e| {
                            RuntimeError::IoError(
                                format!(
                                    "Failed to append directory '{}' to the TAR archive",
                                    entry_path.display()
                                ),
                                e,
                            )
                        })?;
                    stack.push(WalkStep::Enter {
                        dir: entry_path,
                        in_symlink: child_in_symlink,
                        canon_to_pop,
                    });
                } else if entry_metadata.is_file() {
                    if !ctx.path_filter.is_file_allowed(&rel_to_serve_root) {
                        continue;
                    }
                    tar_builder
                        .append_path_with_name(&entry_path, &archive_entry_path)
                        .map_err(|e| {
                            RuntimeError::IoError(
                                format!(
                                    "Failed to append file '{}' to the TAR archive",
                                    entry_path.display()
                                ),
                                e,
                            )
                        })?;
                }
            }
        }
    }

    // Finish the archive
    tar_builder.into_inner().map_err(|e| {
        RuntimeError::IoError("Failed to finish writing the TAR archive".to_string(), e)
    })?;

    Ok(())
}

/// Write a zip of `dir` in `out`.
///
/// The target directory will be saved as a top-level directory in the archive.
///
/// For example, consider this directory structure:
///
/// ```ignore
/// a
/// └── b
///     └── c
///         ├── e
///         ├── f
///         └── g
/// ```
///
/// Making a zip out of `"a/b/c"` will result in this archive content:
///
/// ```ignore
/// c
/// ├── e
/// ├── f
/// └── g
/// ```
fn create_zip_from_directory<W>(
    out: W,
    directory: &Path,
    ctx: ArchiveContext<'_>,
) -> Result<(), RuntimeError>
where
    W: std::io::Write + std::io::Seek,
{
    let options =
        write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let zip_root_folder_name = resolve_archive_root_name(directory)?;

    let (root_in_symlink, mut active_symlink_ancestors) = init_filtered_walk(directory, ctx);
    let mut stack = vec![WalkStep::Enter {
        dir: directory.to_path_buf(),
        in_symlink: root_in_symlink,
        canon_to_pop: None,
    }];

    let mut zip_writer = ZipWriter::new(out);
    let mut buffer = Vec::new();
    while let Some(step) = stack.pop() {
        let (current_dir, in_symlink) = match step {
            WalkStep::Exit(canon) => {
                active_symlink_ancestors.remove(&canon);
                continue;
            }
            WalkStep::Enter {
                dir,
                in_symlink,
                canon_to_pop,
            } => {
                if let Some(canon) = canon_to_pop {
                    stack.push(WalkStep::Exit(canon));
                }
                (dir, in_symlink)
            }
        };

        let directory_entry_iterator = std::fs::read_dir(&current_dir)
            .map_err(|e| RuntimeError::IoError("Could not read directory".to_string(), e))?;
        let rel_dir_in_archive = current_dir.strip_prefix(directory).map_err(|_| {
            RuntimeError::ArchiveCreationDetailError("Could not append base directory".to_string())
        })?;
        let zip_directory = Path::new(&zip_root_folder_name).join(rel_dir_in_archive);

        for entry in directory_entry_iterator {
            let entry_path = entry
                .ok()
                .ok_or_else(|| {
                    RuntimeError::InvalidPathError(
                        "Directory name terminates in \"..\"".to_string(),
                    )
                })?
                .path();

            let sym_meta = std::fs::symlink_metadata(&entry_path).map_err(|e| {
                RuntimeError::IoError(
                    format!(
                        "Could not get file metadata of '{}'",
                        entry_path.to_string_lossy()
                    ),
                    e,
                )
            })?;
            let is_symlink = sym_meta.file_type().is_symlink();
            if is_symlink && ctx.skip_symlinks {
                continue;
            }

            let current_entry_name = entry_path.file_name().ok_or_else(|| {
                RuntimeError::InvalidPathError("Invalid file or directory name".to_string())
            })?;

            let rel_in_archive = rel_dir_in_archive.join(current_entry_name);
            let rel_to_serve_root = ctx.rel_dir.join(&rel_in_archive);

            if !ctx.path_filter.is_none()
                && (in_symlink || is_symlink)
                && !ctx
                    .path_filter
                    .check_canonical_target(ctx.canon_root, &entry_path)
            {
                continue;
            }

            let entry_metadata = if is_symlink {
                match std::fs::metadata(&entry_path) {
                    Ok(meta) => meta,
                    // When PathFilter is active, skip dangling symlinks cleanly; when
                    // PathFilter::None, propagate the error to preserve existing tests/archive.rs behavior.
                    Err(_) if !ctx.path_filter.is_none() => continue,
                    Err(e) => {
                        return Err(RuntimeError::IoError(
                            format!(
                                "Could not get file metadata of '{}'",
                                entry_path.to_string_lossy()
                            ),
                            e,
                        ));
                    }
                }
            } else {
                sym_meta
            };

            // To let every software correctly parse the file structure in ZIP files that are produced
            // on any platform (esp. Windows), always use forward slashes. The documentation:
            // https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
            let relative_path = if cfg!(windows) {
                let branch = zip_directory
                    .as_os_str()
                    .to_string_lossy()
                    .trim_end_matches(r"\") // every branch ends with two backslashes "\\".
                    .replace(r"\", "/"); // every branch uses backslash "\" as path separators.
                let leaf = current_entry_name.to_string_lossy();
                format!("{branch}/{leaf}") // construct a Unix-style path in the simplest way.
            } else {
                zip_directory
                    .join(current_entry_name)
                    .into_os_string()
                    .to_string_lossy()
                    .into_owned()
            };

            if entry_metadata.is_file() {
                if !ctx.path_filter.is_none()
                    && !ctx.path_filter.is_file_allowed(&rel_to_serve_root)
                {
                    continue;
                }
                let mut f = File::open(&entry_path)
                    .map_err(|e| RuntimeError::IoError("Could not open file".to_string(), e))?;
                f.read_to_end(&mut buffer).map_err(|e| {
                    RuntimeError::IoError("Could not read from file".to_string(), e)
                })?;
                zip_writer.start_file(relative_path, options).map_err(|_| {
                    RuntimeError::ArchiveCreationDetailError(
                        "Could not add file path to ZIP".to_string(),
                    )
                })?;
                zip_writer.write_all(buffer.as_ref()).map_err(|_| {
                    RuntimeError::ArchiveCreationDetailError(
                        "Could not write file to ZIP".to_string(),
                    )
                })?;
                buffer.clear();
            } else if entry_metadata.is_dir() {
                if !ctx.path_filter.is_none() {
                    let dir_state = if in_symlink || is_symlink {
                        ctx.path_filter.effective_dir_state(
                            ctx.canon_root,
                            &entry_path,
                            &rel_to_serve_root,
                        )
                    } else {
                        ctx.path_filter.dir_state(&rel_to_serve_root)
                    };
                    if dir_state == PathState::Denied {
                        continue;
                    }
                }

                let child_in_symlink = in_symlink || is_symlink;
                let canon_to_pop = if !ctx.path_filter.is_none() && child_in_symlink {
                    let Some(canon_child) =
                        is_symlink_cycle(&current_dir, &entry_path, &mut active_symlink_ancestors)
                    else {
                        continue;
                    };
                    Some(canon_child)
                } else {
                    None
                };

                zip_writer
                    .add_directory(relative_path, options)
                    .map_err(|_| {
                        RuntimeError::ArchiveCreationDetailError(
                            "Could not add directory path to ZIP".to_string(),
                        )
                    })?;
                stack.push(WalkStep::Enter {
                    dir: entry_path,
                    in_symlink: child_in_symlink,
                    canon_to_pop,
                });
            }
        }
    }

    zip_writer.finish().map_err(|_| {
        RuntimeError::ArchiveCreationDetailError("Could not finish writing ZIP archive".to_string())
    })?;
    Ok(())
}

/// Writes a zip of `src_dir` in `out`.
fn zip_data<W>(src_dir: &Path, ctx: ArchiveContext<'_>, mut out: W) -> Result<(), RuntimeError>
where
    W: std::io::Write,
{
    let mut data = Vec::new();
    let memory_file = Cursor::new(&mut data);
    create_zip_from_directory(memory_file, src_dir, ctx).map_err(|e| {
        RuntimeError::ArchiveCreationError(
            "Failed to create the ZIP archive".to_string(),
            Box::new(e),
        )
    })?;

    out.write_all(data.as_mut_slice())
        .map_err(|e| RuntimeError::IoError("Failed to write the ZIP archive".to_string(), e))?;

    Ok(())
}

fn zip_dir<W>(dir: &Path, ctx: ArchiveContext<'_>, out: W) -> Result<(), RuntimeError>
where
    W: std::io::Write,
{
    resolve_archive_root_name(dir)?;

    zip_data(dir, ctx, out)
        .map_err(|e| RuntimeError::ArchiveCreationError("zip".to_string(), Box::new(e)))
}
