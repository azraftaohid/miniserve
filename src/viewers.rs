use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::Metadata;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;
use std::time::UNIX_EPOCH;

use actix_files::NamedFile;
use actix_web::{
    HttpMessage, HttpRequest, HttpResponse,
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::{
        Method, Uri,
        header::{self, ContentDisposition, DispositionType, HeaderValue},
    },
    middleware::Next,
    web::{self, Query},
};
use bytesize::ByteSize;
use comrak::{
    Arena, Options as ComrakOptions,
    adapters::SyntaxHighlighterAdapter,
    format_html_with_plugins,
    nodes::NodeValue,
    options::Plugins,
    parse_document,
    plugins::syntect::{SyntectAdapter, SyntectAdapterBuilder},
};
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use regex::Regex;
use serde::Deserialize;

use crate::{
    MiniserveConfig,
    auth::CurrentUser,
    file_utils::sanitize_path,
    listing::{Breadcrumb, percent_encode_sets::COMPONENT},
    renderer::{self, ViewerContent},
};

/// Maximum file size (2 MiB) to render into syntax-highlighted HTML before falling back to raw serving.
const MAX_TEXT_RENDER_SIZE: u64 = 2 * 1024 * 1024;

/// Number of initial bytes inspected for NUL (`\0`) to detect binary files.
const BINARY_SNIFF_LEN: usize = 8192;

/// Global cached Syntect adapter so syntax sets and themes are loaded only once.
static SYNTECT_ADAPTER: LazyLock<SyntectAdapter> = LazyLock::new(|| {
    SyntectAdapterBuilder::new()
        .theme("base16-ocean.dark")
        .build()
});

#[derive(Deserialize, Default)]
pub struct ViewerQueryParams {
    pub raw: Option<bool>,
    pub download: Option<bool>,
}

/// Classification of a file eligible for an inline HTML viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerKind {
    Markdown,
    Code { lang: Option<&'static str> },
}

static MATH_CODEBLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)<pre><code[^>]*data-math-style="display"[^>]*>(.*?)</code></pre>"#).unwrap()
});

static MATH_SPAN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)<(?:span|code) data-math-style="(inline|display)">(.*?)</(?:span|code)>"#)
        .unwrap()
});

fn unescape_html_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn convert_math_to_mathml(html: &str) -> String {
    if !html.contains("data-math-style") {
        return html.to_string();
    }

    let stage1 = MATH_CODEBLOCK_RE.replace_all(html, |caps: &regex::Captures| {
        let unescaped = unescape_html_entities(caps[1].trim());
        match latex2mathml::latex_to_mathml(&unescaped, latex2mathml::DisplayStyle::Block) {
            Ok(mathml) => mathml,
            Err(_) => caps[0].to_string(),
        }
    });

    let stage2 = MATH_SPAN_RE.replace_all(&stage1, |caps: &regex::Captures| {
        let style = if &caps[1] == "display" {
            latex2mathml::DisplayStyle::Block
        } else {
            latex2mathml::DisplayStyle::Inline
        };
        let unescaped = unescape_html_entities(&caps[2]);
        match latex2mathml::latex_to_mathml(&unescaped, style) {
            Ok(mathml) => mathml,
            Err(_) => caps[0].to_string(),
        }
    });

    stage2.into_owned()
}

fn is_br_tag(s: &str) -> bool {
    let s = s.trim();
    if !s.starts_with('<') || !s.ends_with('>') || s.starts_with("</") {
        return false;
    }
    let inner = s[1..s.len() - 1].trim();
    if inner.len() < 2 {
        return false;
    }
    let (tag_name, rest) = inner.split_at(2);
    if !tag_name.eq_ignore_ascii_case("br") {
        return false;
    }
    rest.is_empty()
        || rest.starts_with('/')
        || rest.chars().next().is_some_and(|c| c.is_ascii_whitespace())
}

/// Renders a Markdown string into HTML with GFM extensions and Syntect syntax highlighting.
pub fn render_markdown_to_html(markdown: &str) -> String {
    let mut options = ComrakOptions::default();
    options.extension.strikethrough = true;
    options.extension.table = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    options.extension.footnotes = true;
    options.extension.math_dollars = true;
    options.extension.math_latex = true;
    options.extension.math_code = true;
    // Keep options.render.r#unsafe = false (default) so raw HTML/scripts are escaped.

    let mut plugins = Plugins::default();
    plugins.render.codefence_syntax_highlighter = Some(&*SYNTECT_ADAPTER);

    let arena = Arena::new();
    let root = parse_document(&arena, markdown, &options);

    // CommonMark treats <br> as raw HTML inline, which causes safe renderers to omit it as
    // `<!-- raw HTML omitted -->`. In Markdown (especially tables), `<br>` is standard for
    // intentional hard line breaks. Convert safe `<br>` variants into AST line breaks.
    for node in root.descendants() {
        let mut data = node.data.borrow_mut();
        match data.value {
            NodeValue::HtmlInline(ref tag) if is_br_tag(tag) => {
                data.value = NodeValue::LineBreak;
            }
            NodeValue::HtmlBlock(ref block) if is_br_tag(&block.literal) => {
                data.value = NodeValue::LineBreak;
            }
            _ => {}
        }
    }

    let mut out = String::new();
    format_html_with_plugins(root, &options, &mut out, &plugins).unwrap();
    convert_math_to_mathml(&out)
}

/// Renders source code / plaintext into HTML with a line-number gutter and Syntect syntax highlighting.
pub fn render_code_to_html(code: &str, lang: Option<&str>) -> String {
    let line_count = code.lines().count().max(1);
    let mut out = String::with_capacity(code.len().saturating_mul(2) + line_count * 35 + 128);

    out.push_str("<div class=\"code-container\"><div class=\"line-numbers\" aria-hidden=\"true\">");
    for i in 1..=line_count {
        let _ = write!(out, "<a id=\"L{i}\" href=\"#L{i}\" tabindex=\"-1\">{i}</a>");
    }
    out.push_str("</div>");

    let mut pre_attrs = HashMap::new();
    if let Some(l) = lang {
        pre_attrs.insert("lang", Cow::Owned(l.to_string()));
    }
    let _ = SYNTECT_ADAPTER.write_pre_tag(&mut out, pre_attrs);

    let mut code_attrs = HashMap::new();
    if let Some(l) = lang {
        code_attrs.insert("class", Cow::Owned(format!("language-{l}")));
    }
    let _ = SYNTECT_ADAPTER.write_code_tag(&mut out, code_attrs);
    let _ = SYNTECT_ADAPTER.write_highlighted(&mut out, lang, code);
    out.push_str("</code></pre></div>");
    out
}

fn is_markdown_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("markdown"))
}

fn is_pdf_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pdf"))
}

fn match_extension_syntax(ext: &str) -> Option<&'static str> {
    match ext {
        // Plain text / logs / config
        "txt" | "text" | "log" => Some("txt"),
        "yaml" | "yml" => Some("yaml"),
        "json" | "jsonc" | "jsonl" => Some("json"),
        "toml" | "lock" => Some("toml"),
        "xml" | "plist" | "svg" => Some("xml"),
        "csv" => Some("csv"),
        "tsv" => Some("tsv"),
        "ini" | "cfg" | "conf" | "properties" | "env" | "editorconfig" | "gitignore"
        | "gitattributes" | "dockerignore" | "npmrc" => Some("ini"),
        // Programming & scripting languages
        "rs" => Some("rs"),
        "py" | "pyw" | "pyi" => Some("py"),
        "js" | "mjs" | "cjs" | "jsx" => Some("js"),
        "ts" | "mts" | "cts" | "tsx" => Some("ts"),
        "c" | "h" => Some("c"),
        "cpp" | "hpp" | "cc" | "cxx" | "c++" | "h++" | "hh" => Some("cpp"),
        "go" => Some("go"),
        "java" => Some("java"),
        "kt" | "kts" => Some("kotlin"),
        "sh" | "bash" | "zsh" | "fish" => Some("sh"),
        "css" => Some("css"),
        "scss" | "sass" => Some("scss"),
        "less" => Some("less"),
        "sql" => Some("sql"),
        "rb" => Some("rb"),
        "php" => Some("php"),
        "lua" => Some("lua"),
        "swift" => Some("swift"),
        "dart" => Some("dart"),
        "r" => Some("r"),
        "scala" => Some("scala"),
        "pl" | "pm" => Some("perl"),
        "zig" => Some("zig"),
        "nix" => Some("nix"),
        "proto" => Some("proto"),
        "graphql" | "gql" => Some("graphql"),
        "hcl" | "tf" | "tfvars" => Some("hcl"),
        "vue" | "svelte" => Some("html"),
        "cmake" => Some("cmake"),
        "diff" | "patch" => Some("diff"),
        "dockerfile" | "containerfile" => Some("dockerfile"),
        _ => None,
    }
}

fn classify_textual_path(path: &Path) -> Option<Option<&'static str>> {
    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = file_name.to_ascii_lowercase();
        match lower.as_str() {
            "makefile" | "gnumakefile" | "justfile" => return Some(Some("makefile")),
            "dockerfile" | "containerfile" => return Some(Some("dockerfile")),
            "cmakelists.txt" => return Some(Some("cmake")),
            "cargo.lock" | "poetry.lock" | "pipfile" => return Some(Some("toml")),
            "gemfile" | "rakefile" | "vagrantfile" => return Some(Some("rb")),
            ".gitignore" | ".gitattributes" | ".dockerignore" | ".editorconfig" | ".npmrc"
            | ".nvmrc" | ".prettierrc" | ".eslintrc" => return Some(Some("ini")),
            "license" | "licence" | "authors" | "contributors" | "changelog" | "news" | "todo"
            | "readme" | "readme.txt" => return Some(Some("txt")),
            _ if lower.starts_with(".env") => return Some(Some("ini")),
            _ => (),
        }
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let lower_ext = ext.to_ascii_lowercase();
        if let Some(token) = match_extension_syntax(&lower_ext) {
            return Some(Some(token));
        }
    }

    // Check mime_guess for any other text/* formats (excluding HTML/Markdown)
    if !is_markdown_path(path)
        && let Some(ct) = mime_guess::from_path(path).first()
        && ct.type_() == mime::TEXT
        && ct.subtype() != mime::HTML
    {
        return Some(None);
    }

    None
}

/// Determines which viewer (if any) should handle `path` under the active configuration.
fn classify_viewer_target(path: &Path, conf: &MiniserveConfig) -> Option<ViewerKind> {
    if conf.render_markdown && is_markdown_path(path) {
        return Some(ViewerKind::Markdown);
    }
    if conf.render_text
        && let Some(lang) = classify_textual_path(path)
    {
        return Some(ViewerKind::Code { lang });
    }
    None
}

/// Resolves the requested HTTP path to a verified filesystem path and metadata under `conf.path`.
/// Returns `None` if the path is invalid, hidden (when `!conf.show_hidden`), traverses symlinks
/// (when `conf.no_symlinks`), or does not point to an existing regular file.
fn resolve_target_file(req: &HttpRequest, conf: &MiniserveConfig) -> Option<(PathBuf, Metadata)> {
    if conf.path.is_file() {
        let req_path = req.path();
        let stripped = req_path
            .strip_prefix(&conf.route_prefix)
            .unwrap_or(req_path);
        if stripped.is_empty() || stripped == "/" {
            let metadata = std::fs::metadata(&conf.path).ok()?;
            return Some((conf.path.clone(), metadata));
        }
        return None;
    }

    let req_path = req.path();
    let rel_encoded = req_path
        .strip_prefix(&conf.route_prefix)
        .unwrap_or(req_path);
    let decoded = percent_decode_str(rel_encoded).decode_utf8().ok()?;
    let sanitized = sanitize_path(Path::new(&*decoded), conf.show_hidden)?;
    if sanitized.as_os_str().is_empty() {
        return None;
    }

    let mut full_path = conf.path.clone();
    for component in sanitized.components() {
        full_path.push(component);
        if conf.no_symlinks && full_path.is_symlink() {
            return None;
        }
    }

    let metadata = std::fs::metadata(&full_path).ok()?;
    if !metadata.is_file() {
        return None;
    }

    Some((full_path, metadata))
}

/// Computes a weak ETag for a rendered viewer page based on file size and modification timestamp.
fn compute_viewer_etag(metadata: &Metadata, kind: ViewerKind) -> Option<String> {
    let modified = metadata.modified().ok()?;
    let dur = modified.duration_since(UNIX_EPOCH).ok()?;
    let kind_tag = match kind {
        ViewerKind::Markdown => "md",
        ViewerKind::Code { .. } => "code",
    };
    Some(format!(
        "W/\"{:x}-{:x}-{:x}-{kind_tag}\"",
        metadata.len(),
        dur.as_secs(),
        dur.subsec_nanos()
    ))
}

/// Checks whether the request's `If-None-Match` header matches `etag`.
fn if_none_match_matches(req: &HttpRequest, etag: &str) -> bool {
    req.headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|val| {
            val.split(',')
                .any(|part| part.trim() == etag || part.trim() == "*")
        })
}

/// Builds breadcrumbs for the file viewer page, including the filename when serving a single file.
fn build_file_breadcrumbs(req: &HttpRequest, conf: &MiniserveConfig) -> Vec<Breadcrumb> {
    let title = conf
        .title
        .clone()
        .unwrap_or_else(|| req.connection_info().host().into());

    let req_path = req.path();
    let rel_encoded = req_path
        .strip_prefix(&conf.route_prefix)
        .unwrap_or(req_path);
    let decoded = percent_decode_str(rel_encoded).decode_utf8_lossy();

    let mut res: Vec<Breadcrumb> = Vec::new();
    let mut link_accumulator = format!("{}/", conf.route_prefix);
    let mut components = Path::new(&*decoded).components().peekable();

    while let Some(c) = components.next() {
        let name = match c {
            Component::RootDir => title.clone(),
            Component::Normal(s) => {
                let name_str = s.to_string_lossy().to_string();
                if components.peek().is_some() {
                    link_accumulator
                        .push_str(&(utf8_percent_encode(&name_str, COMPONENT).to_string() + "/"));
                } else {
                    link_accumulator
                        .push_str(&utf8_percent_encode(&name_str, COMPONENT).to_string());
                }
                name_str
            }
            _ => String::new(),
        };

        res.push(Breadcrumb::new(
            name,
            if components.peek().is_some() {
                link_accumulator.clone()
            } else {
                ".".to_string()
            },
        ));
    }

    if conf.path.is_file()
        && res.len() == 1
        && let Some(file_name) = conf.path.file_name().and_then(|n| n.to_str())
    {
        res[0].link = link_accumulator;
        res.push(Breadcrumb::new(file_name.to_string(), ".".to_string()));
    }

    res
}

/// Serves a file directly using `NamedFile` with the given `DispositionType` and optional MIME override.
fn serve_named_file(
    target_file: &Path,
    http_req: HttpRequest,
    disposition: DispositionType,
    override_ct: Option<mime::Mime>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let mut named_file = NamedFile::open(target_file)?;
    if let Some(ct) = override_ct {
        named_file = named_file.set_content_type(ct);
    }
    let mut cd = named_file.content_disposition().clone();
    cd.disposition = disposition;
    named_file = named_file.set_content_disposition(cd);
    let res = named_file.into_response(&http_req).map_into_boxed_body();
    Ok(ServiceResponse::new(http_req, res))
}

/// Middleware that intercepts Markdown and textual/code requests (when viewers are enabled)
/// and rewrites PDF `Content-Disposition` headers to `inline` (when `render_pdf` is enabled).
pub async fn viewer_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let conf = req.app_data::<web::Data<MiniserveConfig>>().cloned();

    let Some(conf) = conf else {
        return Ok(next.call(req).await?.map_into_boxed_body());
    };

    if !conf.render_markdown && !conf.render_pdf && !conf.render_text {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let is_get_or_head = *req.method() == Method::GET || *req.method() == Method::HEAD;
    if !is_get_or_head {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let query = Query::<ViewerQueryParams>::from_query(req.query_string())
        .map(|q| q.0)
        .unwrap_or_default();

    // 1. Handle Markdown and Textual/Code viewers in a single resolution pass
    if (conf.render_markdown || conf.render_text)
        && let Some((target_file, metadata)) = resolve_target_file(req.request(), &conf)
        && let Some(viewer_kind) = classify_viewer_target(&target_file, &conf)
    {
        if query.download == Some(true) {
            return serve_named_file(
                &target_file,
                req.request().clone(),
                DispositionType::Attachment,
                None,
            );
        }

        if query.raw == Some(true) {
            return serve_named_file(
                &target_file,
                req.request().clone(),
                DispositionType::Inline,
                Some(mime::TEXT_PLAIN_UTF_8),
            );
        }

        if metadata.len() <= MAX_TEXT_RENDER_SIZE {
            let http_req = req.request().clone();
            let etag = compute_viewer_etag(&metadata, viewer_kind);

            // Handle conditional If-None-Match (304 Not Modified)
            if let Some(ref etag_val) = etag
                && if_none_match_matches(&http_req, etag_val)
            {
                let res = HttpResponse::NotModified()
                    .insert_header((header::ETAG, etag_val.as_str()))
                    .finish()
                    .map_into_boxed_body();
                return Ok(ServiceResponse::new(http_req, res));
            }

            // Handle HEAD requests without reading or rendering the file body (RFC 9110)
            if *http_req.method() == Method::HEAD {
                let mut builder = HttpResponse::Ok();
                builder.content_type(mime::TEXT_HTML_UTF_8);
                if let Some(ref etag_val) = etag {
                    builder.insert_header((header::ETAG, etag_val.as_str()));
                }
                let res = builder.finish().map_into_boxed_body();
                return Ok(ServiceResponse::new(http_req, res));
            }

            // Offload synchronous file read, binary sniff, and syntax highlighting to blocking pool
            let file_len = metadata.len();
            let target_clone = target_file.clone();
            let render_result =
                web::block(move || -> io::Result<Option<(String, String, String)>> {
                    let bytes = std::fs::read(&target_clone)?;
                    // Reject binary files that contain a NUL byte in the initial sniff window
                    let sniff_len = bytes.len().min(BINARY_SNIFF_LEN);
                    if bytes[..sniff_len].contains(&0) {
                        return Ok(None);
                    }

                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    let line_count = text.lines().count().max(1);
                    let meta_badge = format!(
                        "{line_count} {} · {}",
                        if line_count == 1 { "line" } else { "lines" },
                        ByteSize::b(file_len)
                    );

                    let rendered = match viewer_kind {
                        ViewerKind::Markdown => render_markdown_to_html(&text),
                        ViewerKind::Code { lang } => render_code_to_html(&text, lang),
                    };

                    Ok(Some((rendered, meta_badge, text)))
                })
                .await?;

            if let Ok(Some((rendered_html, meta_badge, raw_text))) = render_result {
                let breadcrumbs = build_file_breadcrumbs(&http_req, &conf);
                let abs_uri = Uri::builder()
                    .scheme(http_req.connection_info().scheme())
                    .authority(http_req.connection_info().host())
                    .path_and_query(http_req.path())
                    .build()
                    .unwrap_or_else(|_| http_req.uri().clone());

                let viewer_content = match viewer_kind {
                    ViewerKind::Markdown => ViewerContent::Markdown(&rendered_html),
                    ViewerKind::Code { .. } => ViewerContent::Code(&rendered_html),
                };

                let page = {
                    let extensions = http_req.extensions();
                    let current_user = extensions.get::<CurrentUser>();

                    renderer::viewer_page(
                        viewer_content,
                        Some(&raw_text),
                        Some(&meta_badge),
                        &abs_uri,
                        &breadcrumbs,
                        &conf,
                        current_user,
                    )
                };

                let mut builder = HttpResponse::Ok();
                builder.content_type(mime::TEXT_HTML_UTF_8);
                if let Some(ref etag_val) = etag {
                    builder.insert_header((header::ETAG, etag_val.as_str()));
                }
                let res = builder.body(page.into_string()).map_into_boxed_body();
                return Ok(ServiceResponse::new(http_req, res));
            }
        }
    }

    // 2. Delegate to downstream service and adjust PDF Content-Disposition if enabled
    let mut res = next.call(req).await?.map_into_boxed_body();

    if conf.render_pdf && res.status().is_success() {
        let is_pdf_response = res
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/pdf"))
            || is_pdf_path(Path::new(res.request().path()));

        if is_pdf_response
            && query.download != Some(true)
            && let Some(existing_cd) = res.headers().get(header::CONTENT_DISPOSITION).cloned()
        {
            if let Ok(mut parsed_cd) = ContentDisposition::from_raw(&existing_cd) {
                parsed_cd.disposition = DispositionType::Inline;
                if let Ok(val) = HeaderValue::from_str(&parsed_cd.to_string()) {
                    res.headers_mut().insert(header::CONTENT_DISPOSITION, val);
                }
            } else if let Ok(cd_str) = existing_cd.to_str()
                && let Some(rest) = cd_str.strip_prefix("attachment")
                && let Ok(val) = HeaderValue::from_str(&format!("inline{rest}"))
            {
                res.headers_mut().insert(header::CONTENT_DISPOSITION, val);
            }
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markdown_table_with_br() {
        let md = "| Col 1 | Col 2 |\n|---|---|\n| Line 1<br>Line 2<br/>Line 3<br />Line 4<BR>Line 5 | Other |";
        let html = render_markdown_to_html(md);
        println!("RENDERED TABLE HTML:\n{}", html);
        assert!(!html.contains("<!-- raw HTML omitted -->"));
        assert!(html.contains("Line 1<br />\nLine 2<br />\nLine 3<br />\nLine 4<br />\nLine 5"));

        // Standalone <br> block between paragraphs
        let md_blocks = "Paragraph 1\n\n<br>\n\nParagraph 2";
        let html_blocks = render_markdown_to_html(md_blocks);
        println!("RENDERED BLOCKS HTML:\n{}", html_blocks);
        assert!(html_blocks.contains("Paragraph 1"));
        assert!(html_blocks.contains("Paragraph 2"));

        // Script tags must still be stripped
        let md_xss = "| Col |\n|---|\n| <script>alert(1)</script><br>Safe |";
        let html_xss = render_markdown_to_html(md_xss);
        println!("RENDERED XSS HTML:\n{}", html_xss);
        assert!(!html_xss.contains("<script"));
        assert!(html_xss.contains("Safe"));
    }

    #[test]
    fn test_markdown_math_rendering() {
        // 1. Inline and display math with dollar and LaTeX delimiters
        let md = "Inline: $E = mc^2$ and \\(a^2 + b^2 = c^2\\).\n\nDisplay:\n$$\\int_0^\\infty e^{-x} dx = 1$$\n\n\\[\\sum_{i=1}^n i\\]";
        let html = render_markdown_to_html(md);
        assert!(html.contains("<math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"inline\"><mi>E</mi><mo>=</mo><mi>m</mi><msup><mi>c</mi><mn>2</mn></msup></math>"));
        assert!(html.contains("<math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"inline\"><msup><mi>a</mi><mn>2</mn></msup><mo>+</mo><msup><mi>b</mi><mn>2</mn></msup><mo>=</mo><msup><mi>c</mi><mn>2</mn></msup></math>"));
        assert!(
            html.contains("<math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"block\">")
        );

        // 2. Code block math
        let md_code = "```math\n\\frac{a}{b}\n```";
        let html_code = render_markdown_to_html(md_code);
        assert!(
            html_code
                .contains("<math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"block\">")
        );
        assert!(html_code.contains("<mfrac><mi>a</mi><mi>b</mi></mfrac>"));

        // 3. Inequalities with < and > inside math
        let md_ineq = "Formula: $x < y \\land y > z$";
        let html_ineq = render_markdown_to_html(md_ineq);
        assert!(
            html_ineq
                .contains("<math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"inline\">")
        );
        assert!(!html_ineq.contains("&lt;"));

        // 4. Currency amounts must not be converted to math
        let md_currency = "The book costs $50 and shipping is $10.";
        let html_currency = render_markdown_to_html(md_currency);
        assert!(html_currency.contains("$50"));
        assert!(html_currency.contains("$10"));
        assert!(!html_currency.contains("<math"));

        // 5. Malformed LaTeX does not panic and preserves content
        let md_bad = "Invalid: $\\frac{incomplete$";
        let html_bad = render_markdown_to_html(md_bad);
        assert!(html_bad.contains("\\frac{incomplete"));

        // 6. Math inside tables with <br> breaks
        let md_table =
            "| Formula | Details |\n|---|---|\n| $x^2 + y^2 = 1$<br>$z = 0$ | Unit circle |";
        let html_table = render_markdown_to_html(md_table);
        assert!(
            html_table
                .contains("<math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"inline\">")
        );
        assert!(html_table.contains("<br />"));
        assert!(html_table.contains("Unit circle"));

        // 7. Matrix and complex expressions
        let md_matrix = "$$\\begin{pmatrix} a & b \\\\ c & d \\end{pmatrix}$$";
        let html_matrix = render_markdown_to_html(md_matrix);
        assert!(html_matrix.contains("<mtable>"));
    }
}
