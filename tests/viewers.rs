use std::fs::File;
use std::io::Write;

use reqwest::blocking::Client;
use reqwest::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use rstest::rstest;
use select::document::Document;
use select::predicate::{Attr, Class, Name};

mod fixtures;

use fixtures::{Error, TestServer, reqwest_client, server};

const SAMPLE_MARKDOWN: &str = r#"# Sample Document

Hello **world**!

| Col 1 | Col 2 |
| --- | --- |
| Line 1<br>Line 2 | Value |

```rust
fn main() {
    println!("Hello, miniserve!");
}
```

<script>alert("xss")</script>
"#;

const SAMPLE_YAML: &str = r#"server:
  port: 8080
  name: "miniserve"
  enabled: true
"#;

const SAMPLE_JSON: &str = r#"{
  "name": "miniserve",
  "version": "0.35.0",
  "keywords": ["serve", "http"]
}
"#;

const SAMPLE_TXT: &str = "Hello Plain Text!\n<script>alert('plain')</script>\n";

#[rstest]
fn viewers_disabled_by_default(server: TestServer, reqwest_client: Client) -> Result<(), Error> {
    let md_path = server.path().join("notes.md");
    File::create(&md_path)?.write_all(SAMPLE_MARKDOWN.as_bytes())?;

    let pdf_path = server.path().join("doc.pdf");
    File::create(&pdf_path)?.write_all(b"%PDF-1.4 mock pdf")?;

    let yaml_path = server.path().join("config.yaml");
    File::create(&yaml_path)?.write_all(SAMPLE_YAML.as_bytes())?;

    // Markdown is served raw when flag is not enabled
    let md_resp = reqwest_client
        .get(server.url().join("notes.md")?)
        .send()?
        .error_for_status()?;
    let md_ct = md_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(md_ct.starts_with("text/markdown"));
    assert_eq!(md_resp.text()?, SAMPLE_MARKDOWN);

    // PDF has attachment disposition by default
    let pdf_resp = reqwest_client
        .get(server.url().join("doc.pdf")?)
        .send()?
        .error_for_status()?;
    let pdf_cd = pdf_resp
        .headers()
        .get(CONTENT_DISPOSITION)
        .unwrap()
        .to_str()?;
    assert!(pdf_cd.starts_with("attachment"));

    // YAML is served raw when flag is not enabled
    let yaml_resp = reqwest_client
        .get(server.url().join("config.yaml")?)
        .send()?
        .error_for_status()?;
    let yaml_ct = yaml_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(
        yaml_ct.contains("yaml") || yaml_ct.starts_with("text/plain"),
        "Unexpected Content-Type: {yaml_ct}"
    );
    assert_eq!(yaml_resp.text()?, SAMPLE_YAML);

    Ok(())
}

#[rstest]
#[case(&["--render-markdown"])]
#[case(&["--viewers"])]
fn markdown_viewer_renders_html_and_highlights_syntax(
    #[case] _flags: &[&str],
    #[with(_flags)] server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    let md_path = server.path().join("guide.md");
    File::create(&md_path)?.write_all(SAMPLE_MARKDOWN.as_bytes())?;

    let resp = reqwest_client
        .get(server.url().join("guide.md")?)
        .send()?
        .error_for_status()?;
    let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(ct.starts_with("text/html"));

    let body = resp.text()?;
    // Raw script tag must be escaped to prevent XSS
    assert!(!body.contains("<script>alert(\"xss\")</script>"));

    let parsed = Document::from(body.as_str());
    assert!(parsed.find(Attr("id", "readme-contents")).next().is_some());
    assert!(parsed.find(Class("markdown-toolbar")).next().is_some());
    assert!(
        parsed
            .find(Attr("id", "markdown-raw-link"))
            .next()
            .is_some()
    );
    assert!(
        parsed
            .find(Attr("id", "markdown-download-link"))
            .next()
            .is_some()
    );

    // Verify raw-file-content textarea contains original markdown
    let raw_area = parsed
        .find(Attr("id", "raw-file-content"))
        .next()
        .expect("Expected raw-file-content textarea");
    assert_eq!(raw_area.text().trim(), SAMPLE_MARKDOWN.trim());

    // Verify Syntect syntax highlighting produced styled spans inside <pre>
    let pre = parsed
        .find(Name("pre"))
        .next()
        .expect("Expected <pre> block");
    assert!(pre.find(Name("span")).next().is_some());

    // Verify <br> inside markdown table is interpreted as line break
    assert!(body.contains("Line 1<br />\nLine 2"));

    // Verify ?raw=true returns unrendered markdown as text/plain
    let raw_resp = reqwest_client
        .get(server.url().join("guide.md?raw=true")?)
        .send()?
        .error_for_status()?;
    let raw_ct = raw_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(raw_ct.starts_with("text/plain"));
    assert_eq!(raw_resp.text()?, SAMPLE_MARKDOWN);

    // Verify ?download=true forces attachment disposition
    let dl_resp = reqwest_client
        .get(server.url().join("guide.md?download=true")?)
        .send()?
        .error_for_status()?;
    let dl_cd = dl_resp
        .headers()
        .get(CONTENT_DISPOSITION)
        .unwrap()
        .to_str()?;
    assert!(dl_cd.starts_with("attachment"));

    Ok(())
}

#[rstest]
#[case(&["--render-pdf"])]
#[case(&["--viewers"])]
fn pdf_viewer_serves_inline_full_tab(
    #[case] _flags: &[&str],
    #[with(_flags)] server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    let pdf_path = server.path().join("manual.pdf");
    File::create(&pdf_path)?.write_all(b"%PDF-1.4 mock pdf content")?;

    let resp = reqwest_client
        .get(server.url().join("manual.pdf")?)
        .send()?
        .error_for_status()?;

    let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert_eq!(ct, "application/pdf");

    let cd = resp.headers().get(CONTENT_DISPOSITION).unwrap().to_str()?;
    assert!(
        cd.starts_with("inline"),
        "Expected inline Content-Disposition for PDF, got: {cd}"
    );
    assert!(cd.contains("manual.pdf"));

    // Verify ?download=true still forces attachment
    let dl_resp = reqwest_client
        .get(server.url().join("manual.pdf?download=true")?)
        .send()?
        .error_for_status()?;
    let dl_cd = dl_resp
        .headers()
        .get(CONTENT_DISPOSITION)
        .unwrap()
        .to_str()?;
    assert!(dl_cd.starts_with("attachment"));

    Ok(())
}

#[rstest]
#[case(&["--render-text"])]
#[case(&["--viewers"])]
fn text_viewer_renders_yaml_json_txt_with_syntax_highlighting(
    #[case] _flags: &[&str],
    #[with(_flags)] server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    // 1. YAML test
    let yaml_path = server.path().join("config.yaml");
    File::create(&yaml_path)?.write_all(SAMPLE_YAML.as_bytes())?;

    let yaml_resp = reqwest_client
        .get(server.url().join("config.yaml")?)
        .send()?
        .error_for_status()?;
    let ct = yaml_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(ct.starts_with("text/html"));

    let yaml_body = yaml_resp.text()?;
    let parsed_yaml = Document::from(yaml_body.as_str());
    assert!(parsed_yaml.find(Class("code-viewer")).next().is_some());
    assert!(parsed_yaml.find(Class("markdown-toolbar")).next().is_some());
    assert!(parsed_yaml.find(Class("line-numbers")).next().is_some());
    assert!(parsed_yaml.find(Class("viewer-meta")).next().is_some());
    assert!(
        parsed_yaml
            .find(Attr("id", "viewer-copy-btn"))
            .next()
            .is_some()
    );
    let raw_area = parsed_yaml
        .find(Attr("id", "raw-file-content"))
        .next()
        .expect("Expected raw-file-content textarea for YAML");
    assert_eq!(raw_area.text().trim(), SAMPLE_YAML.trim());

    let line1 = parsed_yaml
        .find(Attr("id", "L1"))
        .next()
        .expect("Expected #L1 line number anchor");
    assert_eq!(line1.text(), "1");
    assert_eq!(line1.attr("href"), Some("#L1"));
    assert_eq!(line1.attr("tabindex"), Some("-1"));

    let pre = parsed_yaml
        .find(Name("pre"))
        .next()
        .expect("Expected <pre> block for YAML");
    assert!(pre.find(Name("span")).next().is_some());

    // ?raw=true for YAML
    let raw_resp = reqwest_client
        .get(server.url().join("config.yaml?raw=true")?)
        .send()?
        .error_for_status()?;
    assert_eq!(raw_resp.text()?, SAMPLE_YAML);

    // ?download=true for YAML
    let dl_resp = reqwest_client
        .get(server.url().join("config.yaml?download=true")?)
        .send()?
        .error_for_status()?;
    let dl_cd = dl_resp
        .headers()
        .get(CONTENT_DISPOSITION)
        .unwrap()
        .to_str()?;
    assert!(dl_cd.starts_with("attachment"));

    // 2. JSON test
    let json_path = server.path().join("data.json");
    File::create(&json_path)?.write_all(SAMPLE_JSON.as_bytes())?;

    let json_resp = reqwest_client
        .get(server.url().join("data.json")?)
        .send()?
        .error_for_status()?;
    assert!(
        json_resp
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()?
            .starts_with("text/html")
    );
    let json_body = json_resp.text()?;
    let parsed_json = Document::from(json_body.as_str());
    assert!(parsed_json.find(Class("code-viewer")).next().is_some());
    let pre_json = parsed_json
        .find(Name("pre"))
        .next()
        .expect("Expected <pre> block for JSON");
    assert!(pre_json.find(Name("span")).next().is_some());

    // 3. TXT test (verifying escaping)
    let txt_path = server.path().join("notes.txt");
    File::create(&txt_path)?.write_all(SAMPLE_TXT.as_bytes())?;

    let txt_resp = reqwest_client
        .get(server.url().join("notes.txt")?)
        .send()?
        .error_for_status()?;
    assert!(
        txt_resp
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()?
            .starts_with("text/html")
    );
    let txt_body = txt_resp.text()?;
    assert!(!txt_body.contains("<script>alert('plain')</script>"));
    assert!(txt_body.contains("&lt;script&gt;alert(&#39;plain&#39;)&lt;/script&gt;"));

    Ok(())
}

#[rstest]
fn viewer_supports_etag_304_head_and_dotfiles(
    #[with(&["--viewers", "--hidden"])] server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    // 1. Dotfiles (.gitignore and .env.example)
    let gitignore_path = server.path().join(".gitignore");
    File::create(&gitignore_path)?.write_all(b"target/\n*.log\n")?;

    let resp = reqwest_client
        .get(server.url().join(".gitignore")?)
        .send()?
        .error_for_status()?;
    assert!(
        resp.headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()?
            .starts_with("text/html")
    );
    let etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .expect("Expected ETag header on viewer response")
        .to_str()?
        .to_string();

    // 2. Conditional GET with If-None-Match returns 304 Not Modified with empty body
    let cond_resp = reqwest_client
        .get(server.url().join(".gitignore")?)
        .header(reqwest::header::IF_NONE_MATCH, &etag)
        .send()?;
    assert_eq!(cond_resp.status(), reqwest::StatusCode::NOT_MODIFIED);
    assert!(cond_resp.text()?.is_empty());

    // 3. HEAD request returns 200 OK with text/html, ETag, and empty body
    let head_resp = reqwest_client
        .head(server.url().join(".gitignore")?)
        .send()?
        .error_for_status()?;
    assert!(
        head_resp
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()?
            .starts_with("text/html")
    );
    assert_eq!(
        head_resp
            .headers()
            .get(reqwest::header::ETAG)
            .unwrap()
            .to_str()?,
        etag
    );
    assert!(head_resp.text()?.is_empty());

    // 4. Non-UTF8 text file renders via lossy UTF-8 instead of failing, while NUL-byte binary falls back to raw
    let latin1_path = server.path().join("legacy.txt");
    File::create(&latin1_path)?.write_all(b"Caf\xe9 menu\n")?;
    let latin1_resp = reqwest_client
        .get(server.url().join("legacy.txt")?)
        .send()?
        .error_for_status()?;
    assert!(
        latin1_resp
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()?
            .starts_with("text/html")
    );
    assert!(latin1_resp.text()?.contains("Caf\u{fffd} menu"));

    let bin_path = server.path().join("binary.txt");
    File::create(&bin_path)?.write_all(b"ELF\x00\x01\x02binary")?;
    let bin_resp = reqwest_client
        .get(server.url().join("binary.txt")?)
        .send()?
        .error_for_status()?;
    assert_eq!(bin_resp.bytes()?.as_ref(), b"ELF\x00\x01\x02binary");

    Ok(())
}

#[rstest]
fn viewers_with_no_render_text_disables_only_text(
    #[with(&["--viewers", "--no-render-text"])] server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    let md_path = server.path().join("notes.md");
    File::create(&md_path)?.write_all(SAMPLE_MARKDOWN.as_bytes())?;

    let pdf_path = server.path().join("doc.pdf");
    File::create(&pdf_path)?.write_all(b"%PDF-1.4 mock pdf")?;

    let yaml_path = server.path().join("config.yaml");
    File::create(&yaml_path)?.write_all(SAMPLE_YAML.as_bytes())?;

    // Markdown is still rendered as HTML
    let md_resp = reqwest_client
        .get(server.url().join("notes.md")?)
        .send()?
        .error_for_status()?;
    let md_ct = md_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(md_ct.starts_with("text/html"));

    // PDF is still served inline
    let pdf_resp = reqwest_client
        .get(server.url().join("doc.pdf")?)
        .send()?
        .error_for_status()?;
    let pdf_cd = pdf_resp
        .headers()
        .get(CONTENT_DISPOSITION)
        .unwrap()
        .to_str()?;
    assert!(pdf_cd.starts_with("inline"));

    // Text (YAML) is NOT rendered as HTML; served raw
    let yaml_resp = reqwest_client
        .get(server.url().join("config.yaml")?)
        .send()?
        .error_for_status()?;
    let yaml_ct = yaml_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(!yaml_ct.starts_with("text/html"));
    assert_eq!(yaml_resp.text()?, SAMPLE_YAML);

    Ok(())
}

#[rstest]
fn viewers_with_no_render_markdown_disables_only_markdown(
    #[with(&["--viewers", "--no-render-markdown"])] server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    let md_path = server.path().join("notes.md");
    File::create(&md_path)?.write_all(SAMPLE_MARKDOWN.as_bytes())?;

    let pdf_path = server.path().join("doc.pdf");
    File::create(&pdf_path)?.write_all(b"%PDF-1.4 mock pdf")?;

    let yaml_path = server.path().join("config.yaml");
    File::create(&yaml_path)?.write_all(SAMPLE_YAML.as_bytes())?;

    // Markdown is NOT rendered as HTML; served raw
    let md_resp = reqwest_client
        .get(server.url().join("notes.md")?)
        .send()?
        .error_for_status()?;
    let md_ct = md_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(!md_ct.starts_with("text/html"));
    assert_eq!(md_resp.text()?, SAMPLE_MARKDOWN);

    // PDF is still served inline
    let pdf_resp = reqwest_client
        .get(server.url().join("doc.pdf")?)
        .send()?
        .error_for_status()?;
    let pdf_cd = pdf_resp
        .headers()
        .get(CONTENT_DISPOSITION)
        .unwrap()
        .to_str()?;
    assert!(pdf_cd.starts_with("inline"));

    // Text (YAML) is still rendered as HTML
    let yaml_resp = reqwest_client
        .get(server.url().join("config.yaml")?)
        .send()?
        .error_for_status()?;
    let yaml_ct = yaml_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(yaml_ct.starts_with("text/html"));

    Ok(())
}

#[rstest]
fn viewers_with_no_render_pdf_disables_only_pdf(
    #[with(&["--viewers", "--no-render-pdf"])] server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    let md_path = server.path().join("notes.md");
    File::create(&md_path)?.write_all(SAMPLE_MARKDOWN.as_bytes())?;

    let pdf_path = server.path().join("doc.pdf");
    File::create(&pdf_path)?.write_all(b"%PDF-1.4 mock pdf")?;

    let yaml_path = server.path().join("config.yaml");
    File::create(&yaml_path)?.write_all(SAMPLE_YAML.as_bytes())?;

    // Markdown is still rendered as HTML
    let md_resp = reqwest_client
        .get(server.url().join("notes.md")?)
        .send()?
        .error_for_status()?;
    let md_ct = md_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(md_ct.starts_with("text/html"));

    // PDF is served as attachment (not inline)
    let pdf_resp = reqwest_client
        .get(server.url().join("doc.pdf")?)
        .send()?
        .error_for_status()?;
    let pdf_cd = pdf_resp
        .headers()
        .get(CONTENT_DISPOSITION)
        .unwrap()
        .to_str()?;
    assert!(pdf_cd.starts_with("attachment"));

    // Text (YAML) is still rendered as HTML
    let yaml_resp = reqwest_client
        .get(server.url().join("config.yaml")?)
        .send()?
        .error_for_status()?;
    let yaml_ct = yaml_resp.headers().get(CONTENT_TYPE).unwrap().to_str()?;
    assert!(yaml_ct.starts_with("text/html"));

    Ok(())
}
