mod fixtures;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::process::Command;

use assert_cmd::cargo;
use assert_cmd::prelude::*;
use assert_fs::TempDir;
use predicates::prelude::*;
use reqwest::StatusCode;
use reqwest::blocking::{Client, multipart};
use reqwest_dav::{ClientBuilder as DavClientBuilder, list_cmd::ListEntity};
use rstest::rstest;
use select::document::Document;
use select::predicate::{Attr, Class, Text};
use tempfile::NamedTempFile;

use crate::fixtures::{Error, TestServer, reqwest_client, server};

fn create_test_hierarchy(root: &std::path::Path) -> Result<(), Error> {
    create_dir_all(root.join("abc/def/other_dir"))?;
    create_dir_all(root.join("abc/def/ghi/jkl"))?;
    create_dir_all(root.join("clean_dir"))?;

    File::create(root.join("public.txt"))?.write_all(b"public")?;
    File::create(root.join("debug.log"))?.write_all(b"root log")?;
    File::create(root.join("abc/visible.txt"))?.write_all(b"visible")?;
    File::create(root.join("abc/def/secret.txt"))?.write_all(b"secret")?;
    File::create(root.join("abc/def/secret.md"))?.write_all(b"# Secret")?;
    File::create(root.join("abc/def/README.md"))?.write_all(b"# Excluded README")?;
    File::create(root.join("abc/def/other_dir/hidden.txt"))?.write_all(b"hidden")?;
    File::create(root.join("abc/def/ghi/mid_secret.txt"))?.write_all(b"mid secret")?;
    File::create(root.join("abc/def/ghi/jkl/allowed.txt"))?.write_all(b"allowed")?;
    File::create(root.join("abc/def/ghi/jkl/allowed.md"))?.write_all(b"# Allowed MD")?;
    File::create(root.join("abc/def/ghi/jkl/README.md"))?.write_all(b"# Included README")?;
    File::create(root.join("clean_dir/item.txt"))?.write_all(b"clean item")?;

    Ok(())
}

#[test]
fn cli_conflict_between_ignore_file_and_exclude_include_fails() -> Result<(), Error> {
    let tmp = TempDir::new()?;
    let ignore_file = NamedTempFile::new()?;

    Command::new(cargo::cargo_bin!("miniserve"))
        .arg(tmp.path())
        .arg("--ignore-file")
        .arg(ignore_file.path())
        .arg("--exclude")
        .arg("/abc/def")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));

    Command::new(cargo::cargo_bin!("miniserve"))
        .arg(tmp.path())
        .arg("--ignore-file")
        .arg(ignore_file.path())
        .arg("--include")
        .arg("/abc/def/ghi")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));

    Ok(())
}

#[rstest]
fn exclude_and_include_hierarchy_with_passthrough_navigation(
    #[with(&["--readme", "--exclude", "/abc/def", "--include", "/abc/def/ghi/jkl"])]
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    create_test_hierarchy(server.path())?;

    // 1. Root lists public.txt and abc/
    let root_html = reqwest_client
        .get(server.url())
        .send()?
        .error_for_status()?
        .text()?;
    let root_doc = Document::from(root_html.as_str());
    assert!(root_doc.find(Text).any(|n| n.text() == "public.txt"));
    assert!(root_doc.find(Text).any(|n| n.text() == "abc/"));

    // 2. /abc/ lists visible.txt and def/
    let abc_html = reqwest_client
        .get(server.url().join("abc/")?)
        .send()?
        .error_for_status()?
        .text()?;
    let abc_doc = Document::from(abc_html.as_str());
    assert!(abc_doc.find(Text).any(|n| n.text() == "visible.txt"));
    assert!(abc_doc.find(Text).any(|n| n.text() == "def/"));

    // 3. /abc/def/ is PassThrough: lists ONLY ghi/, hides secret.txt, other_dir/, and README.md
    let def_html = reqwest_client
        .get(server.url().join("abc/def/")?)
        .send()?
        .error_for_status()?
        .text()?;
    let def_doc = Document::from(def_html.as_str());
    assert!(def_doc.find(Text).any(|n| n.text() == "ghi/"));
    assert!(!def_doc.find(Text).any(|n| n.text() == "secret.txt"));
    assert!(!def_doc.find(Text).any(|n| n.text() == "other_dir/"));
    assert!(!def_doc.find(Text).any(|n| n.text() == "README.md"));
    assert!(!def_html.contains("Excluded README"));

    // 4. Direct access to excluded files/dirs returns 404
    assert_eq!(
        reqwest_client
            .get(server.url().join("abc/def/secret.txt")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        reqwest_client
            .get(server.url().join("abc/def/other_dir/")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        reqwest_client
            .get(server.url().join("abc/def/other_dir/hidden.txt")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );

    // 5. /abc/def/ghi/ is PassThrough: lists ONLY jkl/, hides mid_secret.txt
    let ghi_html = reqwest_client
        .get(server.url().join("abc/def/ghi/")?)
        .send()?
        .error_for_status()?
        .text()?;
    let ghi_doc = Document::from(ghi_html.as_str());
    assert!(ghi_doc.find(Text).any(|n| n.text() == "jkl/"));
    assert!(!ghi_doc.find(Text).any(|n| n.text() == "mid_secret.txt"));
    assert_eq!(
        reqwest_client
            .get(server.url().join("abc/def/ghi/mid_secret.txt")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );

    // 6. /abc/def/ghi/jkl/ is Allowed: lists allowed.txt, README.md, and renders Included README
    let jkl_html = reqwest_client
        .get(server.url().join("abc/def/ghi/jkl/")?)
        .send()?
        .error_for_status()?
        .text()?;
    let jkl_doc = Document::from(jkl_html.as_str());
    assert!(jkl_doc.find(Text).any(|n| n.text() == "allowed.txt"));
    assert!(jkl_doc.find(Text).any(|n| n.text() == "README.md"));
    assert!(jkl_html.contains("Included README"));

    let allowed_txt = reqwest_client
        .get(server.url().join("abc/def/ghi/jkl/allowed.txt")?)
        .send()?
        .error_for_status()?
        .text()?;
    assert_eq!(allowed_txt, "allowed");

    Ok(())
}

#[rstest]
fn viewers_respect_exclude_and_include(
    #[with(&["--viewers", "--exclude", "/abc/def", "--include", "/abc/def/ghi/jkl"])]
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    create_test_hierarchy(server.path())?;

    assert_eq!(
        reqwest_client
            .get(server.url().join("abc/def/secret.md")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );

    let resp = reqwest_client
        .get(server.url().join("abc/def/ghi/jkl/allowed.md")?)
        .send()?
        .error_for_status()?;
    let body = resp.text()?;
    assert!(body.contains("Allowed MD"));

    Ok(())
}

#[rstest]
fn archive_downloads_disabled_on_excluded_and_passthrough_trees(
    #[with(&["-r", "-g", "-z", "--exclude", "/abc/def", "--include", "/abc/def/ghi/jkl"])]
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    create_test_hierarchy(server.path())?;

    // Root, /abc/, and /abc/def/ contain excluded subtrees -> 403 Forbidden
    assert_eq!(
        reqwest_client
            .get(server.url().join("?download=tar")?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        reqwest_client
            .get(server.url().join("abc/?download=tar_gz")?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        reqwest_client
            .get(server.url().join("abc/def/?download=zip")?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );

    // /abc/def/ghi/jkl/ has no exclusions inside it -> 200 OK
    assert_eq!(
        reqwest_client
            .get(server.url().join("abc/def/ghi/jkl/?download=tar")?)
            .send()?
            .status(),
        StatusCode::OK
    );

    // /clean_dir/ has no exclusions -> 200 OK and archive buttons are rendered
    let clean_html = reqwest_client
        .get(server.url().join("clean_dir/")?)
        .send()?
        .error_for_status()?
        .text()?;
    let clean_doc = Document::from(clean_html.as_str());
    assert!(clean_doc.find(Class("download_tools")).next().is_some());

    // /abc/def/ hides archive buttons
    let def_html = reqwest_client
        .get(server.url().join("abc/def/")?)
        .send()?
        .error_for_status()?
        .text()?;
    let def_doc = Document::from(def_html.as_str());
    assert!(def_doc.find(Class("download_tools")).next().is_none());

    Ok(())
}

#[rstest]
fn upload_mkdir_and_rm_blocked_on_excluded_and_passthrough_paths(
    #[with(&["-u", "-U", "-R", "--exclude", "/abc/def", "--include", "/abc/def/ghi/jkl"])]
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    create_test_hierarchy(server.path())?;

    // 1. Uploading to PassThrough /abc/def is 403 Forbidden
    let form = multipart::Form::new().part(
        "file_to_upload",
        multipart::Part::text("hack").file_name("evil.txt"),
    );
    let upload_def_resp = reqwest_client
        .post(server.url().join("upload?path=/abc/def")?)
        .multipart(form)
        .send()?;
    assert_eq!(upload_def_resp.status(), StatusCode::FORBIDDEN);
    assert!(!server.path().join("abc/def/evil.txt").exists());

    // 2. mkdir inside PassThrough /abc/def is 403 Forbidden
    let mkdir_form = multipart::Form::new().text("mkdir", "new_subdir");
    let mkdir_def_resp = reqwest_client
        .post(server.url().join("upload?path=/abc/def")?)
        .multipart(mkdir_form)
        .send()?;
    assert_eq!(mkdir_def_resp.status(), StatusCode::FORBIDDEN);
    assert!(!server.path().join("abc/def/new_subdir").exists());

    // 3. Uploading a file into /abc/def/ghi/jkl succeeds
    let ok_form = multipart::Form::new().part(
        "file_to_upload",
        multipart::Part::text("new content").file_name("uploaded.txt"),
    );
    let upload_jkl_resp = reqwest_client
        .post(server.url().join("upload?path=/abc/def/ghi/jkl")?)
        .multipart(ok_form)
        .send()?;
    assert!(upload_jkl_resp.status().is_success());
    assert!(server.path().join("abc/def/ghi/jkl/uploaded.txt").exists());

    // 4. Deleting /abc/def or /abc (which contain exclusions) is 403 Forbidden
    assert_eq!(
        reqwest_client
            .post(server.url().join("rm?path=/abc/def")?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        reqwest_client
            .post(server.url().join("rm?path=/abc")?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        reqwest_client
            .post(server.url().join("rm?path=/abc/def/secret.txt")?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(server.path().join("abc/def/secret.txt").exists());

    // 5. Deleting an allowed file inside /abc/def/ghi/jkl succeeds
    let rm_ok_resp = reqwest_client
        .post(server.url().join("rm?path=/abc/def/ghi/jkl/uploaded.txt")?)
        .send()?;
    assert!(rm_ok_resp.status().is_success());
    assert!(!server.path().join("abc/def/ghi/jkl/uploaded.txt").exists());

    // 6. PassThrough page does not render upload/mkdir forms
    let def_html = reqwest_client
        .get(server.url().join("abc/def/")?)
        .send()?
        .error_for_status()?
        .text()?;
    let def_doc = Document::from(def_html.as_str());
    assert!(def_doc.find(Attr("id", "file_submit")).next().is_none());

    Ok(())
}

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_server_with_args<I, S>(
    root: &std::path::Path,
    extra_args: I,
) -> Result<(KillOnDrop, url::Url), Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let port = port_check::free_local_port().unwrap();
    let child = Command::new(cargo::cargo_bin!("miniserve"))
        .arg(root)
        .arg("-p")
        .arg(port.to_string())
        .args(extra_args)
        .spawn()?;
    let guard = KillOnDrop(child);

    let start = std::time::Instant::now();
    while !port_check::is_port_reachable(format!("127.0.0.1:{port}")) {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if start.elapsed().as_secs() > 5 {
            panic!("timeout waiting for port {port}");
        }
    }

    let base = url::Url::parse(&format!("http://127.0.0.1:{port}/"))?;
    Ok((guard, base))
}

#[test]
fn ignore_file_filtering_and_reinclusion() -> Result<(), Error> {
    let tmp = TempDir::new()?;
    create_test_hierarchy(tmp.path())?;

    let mut ignore_file = NamedTempFile::new()?;
    writeln!(ignore_file, "# Ignore logs and secret tree")?;
    writeln!(ignore_file, "*.log")?;
    writeln!(ignore_file, "/abc/def/")?;
    writeln!(ignore_file, "!/abc/def/ghi/jkl/")?;
    ignore_file.flush()?;

    let (_guard, base) = spawn_server_with_args(
        tmp.path(),
        [OsStr::new("--ignore-file"), ignore_file.path().as_os_str()],
    )?;
    let client = reqwest_client();

    assert_eq!(
        client.get(base.join("debug.log")?).send()?.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .get(base.join("abc/def/secret.txt")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client.get(base.join("abc/def/")?).send()?.status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(base.join("abc/def/ghi/jkl/allowed.txt")?)
            .send()?
            .status(),
        StatusCode::OK
    );

    Ok(())
}

#[rstest]
fn webdav_respects_path_filter(
    #[with(&["--enable-webdav", "--exclude", "/abc/def", "--include", "/abc/def/ghi/jkl"])]
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    create_test_hierarchy(server.path())?;

    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let dav_client = DavClientBuilder::new()
        .set_host(server.url().to_string())
        .build()?;
    let rt = tokio::runtime::Runtime::new()?;

    // PROPFIND on /abc/def returns only /abc/def/ and /abc/def/ghi/ (not secret.txt or other_dir)
    let entities = rt.block_on(async {
        dav_client
            .list("abc/def", reqwest_dav::Depth::Number(1))
            .await
    })?;
    let folder_names: Vec<String> = entities
        .iter()
        .filter_map(|e| match e {
            ListEntity::Folder(f) => Some(f.href.clone()),
            ListEntity::File(_) => None,
        })
        .collect();
    let file_names: Vec<String> = entities
        .iter()
        .filter_map(|e| match e {
            ListEntity::File(f) => Some(f.href.clone()),
            ListEntity::Folder(_) => None,
        })
        .collect();

    assert!(folder_names.iter().any(|h| h.ends_with("/abc/def/ghi/")));
    assert!(!folder_names.iter().any(|h| h.contains("other_dir")));
    assert!(file_names.is_empty());

    // Direct GET on excluded file returns 404
    assert_eq!(
        reqwest_client
            .get(server.url().join("abc/def/secret.txt")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );

    Ok(())
}

#[rstest]
fn route_prefix_works_with_exclude_and_include(
    #[with(&["--route-prefix", "my-prefix", "--exclude", "/abc/def", "--include", "/abc/def/ghi/jkl"])]
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    create_test_hierarchy(server.path())?;

    let def_html = reqwest_client
        .get(server.url().join("my-prefix/abc/def/")?)
        .send()?
        .error_for_status()?
        .text()?;
    let def_doc = Document::from(def_html.as_str());
    assert!(def_doc.find(Text).any(|n| n.text() == "ghi/"));
    assert!(!def_doc.find(Text).any(|n| n.text() == "secret.txt"));

    assert_eq!(
        reqwest_client
            .get(server.url().join("my-prefix/abc/def/secret.txt")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        reqwest_client
            .get(server.url().join("my-prefix/abc/def/ghi/jkl/allowed.txt")?)
            .send()?
            .status(),
        StatusCode::OK
    );

    Ok(())
}

#[rstest]
fn index_file_cannot_bypass_passthrough_or_exclude(
    #[with(&["--index", "index.html", "--exclude", "/abc/def", "--include", "/abc/def/ghi/jkl"])]
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    create_test_hierarchy(server.path())?;
    File::create(server.path().join("abc/def/index.html"))?.write_all(b"SECRET INDEX")?;
    File::create(server.path().join("abc/def/ghi/jkl/index.html"))?.write_all(b"ALLOWED INDEX")?;

    // PassThrough /abc/def/ must NOT serve index.html; it must render pruned listing with ghi/
    let def_html = reqwest_client
        .get(server.url().join("abc/def/")?)
        .send()?
        .error_for_status()?
        .text()?;
    assert!(!def_html.contains("SECRET INDEX"));
    let def_doc = Document::from(def_html.as_str());
    assert!(def_doc.find(Text).any(|n| n.text() == "ghi/"));

    // Allowed /abc/def/ghi/jkl/ serves its index.html normally
    let jkl_html = reqwest_client
        .get(server.url().join("abc/def/ghi/jkl/")?)
        .send()?
        .error_for_status()?
        .text()?;
    assert_eq!(jkl_html, "ALLOWED INDEX");

    Ok(())
}

#[test]
fn ignore_file_whitelist_idiom_star_not_star_slash_not_pdf() -> Result<(), Error> {
    let tmp = TempDir::new()?;
    create_test_hierarchy(tmp.path())?;
    File::create(tmp.path().join("abc/def/doc.pdf"))?.write_all(b"%PDF-1.4")?;

    let mut ignore_file = NamedTempFile::new()?;
    writeln!(ignore_file, "*")?;
    writeln!(ignore_file, "!*/")?;
    writeln!(ignore_file, "!*.pdf")?;
    ignore_file.flush()?;

    let (_guard, base) = spawn_server_with_args(
        tmp.path(),
        [OsStr::new("--ignore-file"), ignore_file.path().as_os_str()],
    )?;
    let client = reqwest_client();

    assert_eq!(
        client.get(base.join("public.txt")?).send()?.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client.get(base.join("abc/visible.txt")?).send()?.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .get(base.join("abc/def/secret.txt")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client.get(base.join("abc/")?).send()?.status(),
        StatusCode::OK
    );
    assert_eq!(
        client.get(base.join("abc/def/")?).send()?.status(),
        StatusCode::OK
    );
    let pdf_resp = client.get(base.join("abc/def/doc.pdf")?).send()?;
    assert_eq!(pdf_resp.status(), StatusCode::OK);
    assert_eq!(pdf_resp.text()?, "%PDF-1.4");

    Ok(())
}

#[test]
fn unanchored_include_cannot_pierce_excluded_parent_dir() -> Result<(), Error> {
    let tmp = TempDir::new()?;
    create_test_hierarchy(tmp.path())?;

    let mut ignore_file = NamedTempFile::new()?;
    writeln!(ignore_file, "/abc/def/")?;
    writeln!(ignore_file, "!*.txt")?;
    ignore_file.flush()?;

    let (_guard, base) = spawn_server_with_args(
        tmp.path(),
        [OsStr::new("--ignore-file"), ignore_file.path().as_os_str()],
    )?;
    let client = reqwest_client();

    assert_eq!(
        client.get(base.join("abc/def/")?).send()?.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .get(base.join("abc/def/secret.txt")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client.get(base.join("abc/visible.txt")?).send()?.status(),
        StatusCode::OK
    );

    Ok(())
}

#[test]
fn ignore_file_allows_archive_and_rm_on_clean_dirs_and_auto_denies_self() -> Result<(), Error> {
    let tmp = TempDir::new()?;
    create_test_hierarchy(tmp.path())?;

    let ignore_in_root = tmp.path().join(".miniserveignore");
    {
        let mut f = File::create(&ignore_in_root)?;
        writeln!(f, "/abc/def/")?;
        writeln!(f, "*.log")?;
    }

    let (_guard, base) = spawn_server_with_args(
        tmp.path(),
        [
            OsStr::new("--hidden"),
            OsStr::new("-r"),
            OsStr::new("-R"),
            OsStr::new("--ignore-file"),
            ignore_in_root.as_os_str(),
        ],
    )?;
    let client = reqwest_client();

    // Auto-denied self
    assert_eq!(
        client.get(base.join(".miniserveignore")?).send()?.status(),
        StatusCode::NOT_FOUND
    );

    // rm on /abc (contains excluded /abc/def/) -> 403 Forbidden
    assert_eq!(
        client.post(base.join("rm?path=/abc")?).send()?.status(),
        StatusCode::FORBIDDEN
    );

    // rm on /clean_dir (contains no excluded items) -> succeeds
    let rm_clean = client.post(base.join("rm?path=/clean_dir")?).send()?;
    assert!(rm_clean.status().is_success());
    assert!(!tmp.path().join("clean_dir").exists());

    // Recreate clean_dir and test anchored-only ignore file for archive download
    create_dir_all(tmp.path().join("clean_dir"))?;
    File::create(tmp.path().join("clean_dir/item.txt"))?.write_all(b"clean item")?;

    let mut anchored_ignore = NamedTempFile::new()?;
    writeln!(anchored_ignore, "/abc/def/")?;
    anchored_ignore.flush()?;

    let (_guard2, base2) = spawn_server_with_args(
        tmp.path(),
        [
            OsStr::new("-r"),
            OsStr::new("--ignore-file"),
            anchored_ignore.path().as_os_str(),
        ],
    )?;
    assert_eq!(
        client
            .get(base2.join("clean_dir/?download=tar")?)
            .send()?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(base2.join("abc/?download=tar")?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );

    Ok(())
}

#[cfg(unix)]
#[rstest]
fn symlink_to_excluded_target_is_blocked(
    #[with(&["-u", "-R", "--exclude", "/abc/def", "--include", "/abc/def/ghi/jkl"])]
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    create_test_hierarchy(server.path())?;
    std::os::unix::fs::symlink(
        server.path().join("abc/def/secret.txt"),
        server.path().join("public_link"),
    )?;
    std::os::unix::fs::symlink(
        server.path().join("abc/def"),
        server.path().join("public_dir_link"),
    )?;

    assert_eq!(
        reqwest_client
            .get(server.url().join("public_link")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        reqwest_client
            .get(server.url().join("public_dir_link/secret.txt")?)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );

    let form = multipart::Form::new().part(
        "file_to_upload",
        multipart::Part::text("hack").file_name("evil.txt"),
    );
    assert_eq!(
        reqwest_client
            .post(server.url().join("upload?path=/public_dir_link")?)
            .multipart(form)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(!server.path().join("abc/def/evil.txt").exists());

    assert_eq!(
        reqwest_client
            .post(server.url().join("rm?path=/public_link")?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(server.path().join("abc/def/secret.txt").exists());

    Ok(())
}

#[test]
fn upload_rename_duplicate_checks_final_filename() -> Result<(), Error> {
    let tmp = TempDir::new()?;
    File::create(tmp.path().join("note.txt"))?.write_all(b"initial")?;

    let mut ignore_file = NamedTempFile::new()?;
    writeln!(ignore_file, "*-1.txt")?;
    ignore_file.flush()?;

    let (_guard, base) = spawn_server_with_args(
        tmp.path(),
        [
            OsStr::new("-u"),
            OsStr::new("-o"),
            OsStr::new("rename"),
            OsStr::new("--ignore-file"),
            ignore_file.path().as_os_str(),
        ],
    )?;
    let client = reqwest_client();

    let form = multipart::Form::new().part(
        "file_to_upload",
        multipart::Part::text("duplicate").file_name("note.txt"),
    );
    let resp = client
        .post(base.join("upload?path=/")?)
        .multipart(form)
        .send()?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(!tmp.path().join("note-1.txt").exists());

    Ok(())
}

#[test]
fn cli_validation_rejects_empty_prefixes_orphan_includes_and_single_file() -> Result<(), Error> {
    let tmp = TempDir::new()?;
    let single_file = NamedTempFile::new()?;

    Command::new(cargo::cargo_bin!("miniserve"))
        .arg(tmp.path())
        .arg("--exclude")
        .arg("")
        .assert()
        .failure();

    Command::new(cargo::cargo_bin!("miniserve"))
        .arg(tmp.path())
        .arg("--exclude")
        .arg("/abc")
        .arg("--include")
        .arg("/abc/def,")
        .assert()
        .failure();

    Command::new(cargo::cargo_bin!("miniserve"))
        .arg(tmp.path())
        .arg("--include")
        .arg("/abc")
        .assert()
        .failure();

    Command::new(cargo::cargo_bin!("miniserve"))
        .arg(single_file.path())
        .arg("--exclude")
        .arg("foo")
        .assert()
        .failure();

    Ok(())
}

#[cfg(unix)]
#[rstest]
fn unix_backslash_in_filename_and_dir_size_api(
    #[with(&["--directory-size", "--size-display", "exact", "--exclude", "/abc/def", "--include", "/abc/def/ghi/jkl"])]
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    create_test_hierarchy(server.path())?;
    File::create(server.path().join(r"abc\secret.txt"))?.write_all(b"backslash ok")?;

    // Backslash filename is not falsely treated as /abc/secret.txt
    assert_eq!(
        reqwest_client
            .get(server.url().join("abc%5Csecret.txt")?)
            .send()?
            .status(),
        StatusCode::OK
    );

    // DirSize on /abc counts visible.txt (7) + allowed.txt (7) + allowed.md (12) + README.md (17) = 43 B
    // while excluding secret.txt, secret.md, README.md under def, hidden.txt, and mid_secret.txt
    let mut command = HashMap::new();
    command.insert("DirSize", "/abc");
    let resp = reqwest_client
        .post(server.url().join("__miniserve_internal/api")?)
        .json(&command)
        .send()?
        .error_for_status()?;
    assert_eq!(resp.text()?, "43 B");

    Ok(())
}
