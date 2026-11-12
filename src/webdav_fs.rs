//! Helper types and functions to allow configuring hidden files visibility
//! for WebDAV handlers

use dav_server::{
    davpath::DavPath,
    fs::{
        DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError as DavFsError,
        FsFuture as DavFsFuture, FsStream as DavFsStream, OpenOptions as DavOpenOptions,
        ReadDirMeta as DavReadDirMeta,
    },
    localfs::LocalFs,
};
use futures::StreamExt;
use std::ffi::OsStr;
#[cfg(target_family = "unix")]
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use tokio::fs;

use crate::path_filter::{PathFilter, PathState};

/// A dav_server local filesystem backend that can be configured to deny access
/// to files and directories with names starting with a dot or matching PathFilter.
#[derive(Clone)]
pub struct RestrictedFs {
    local: Box<LocalFs>,
    base_path: PathBuf,
    canon_base: PathBuf,
    show_hidden: bool,
    no_symlinks: bool,
    path_filter: PathFilter,
}

impl RestrictedFs {
    /// Creates a new RestrictedFs serving the local path at "base".
    /// If "show_hidden" is false, access to hidden files is prevented.
    /// If "no_symlinks" is true, access to symlinks is prevented.
    pub fn new<P: AsRef<Path>>(
        base: P,
        show_hidden: bool,
        no_symlinks: bool,
        path_filter: PathFilter,
    ) -> Box<RestrictedFs> {
        let base_path = base.as_ref().to_path_buf();
        let canon_base = base_path
            .canonicalize()
            .unwrap_or_else(|_| base_path.clone());
        let local = LocalFs::new(base, false, false, false);
        Box::new(RestrictedFs {
            local,
            base_path,
            canon_base,
            show_hidden,
            no_symlinks,
            path_filter,
        })
    }

    /// true if the path is allowed to appear in responses (not hidden, not a symlink, and allowed by path_filter)
    async fn is_path_allowed(&self, path: &DavPath, for_open: bool) -> bool {
        if self.no_symlinks && path_has_symlink_components(path, &self.base_path).await {
            return false;
        }
        if !self.show_hidden && path_has_hidden_components(path) {
            return false;
        }
        if self.path_filter.is_none() {
            return true;
        }
        let rel = path.as_rel_ospath();
        let full = self.base_path.join(rel);
        if !self
            .path_filter
            .check_canonical_target(&self.canon_base, &full)
        {
            return false;
        }
        let is_dir = fs::metadata(&full)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if is_dir {
            let state = self
                .path_filter
                .effective_dir_state(&self.canon_base, &full, rel);
            if for_open {
                state == PathState::Allowed
            } else {
                state != PathState::Denied
            }
        } else {
            self.path_filter.is_file_allowed(rel)
        }
    }
}

/// true if any normal component of path either starts with dot or can't be turned into a str
fn path_has_hidden_components(path: &DavPath) -> bool {
    path.as_rel_ospath().components().any(|c| match c {
        Component::Normal(name) => name.to_str().is_none_or(|s| s.starts_with('.')),
        _ => panic!("dav path should not contain any non-normal components"),
    })
}

/// true if any component in `path` (relative to `base_path`) is a symlink
async fn path_has_symlink_components(path: &DavPath, base_path: &Path) -> bool {
    let mut current_path = base_path.to_path_buf();
    for comp in path.as_rel_ospath().components() {
        match comp {
            Component::Normal(name) => {
                current_path.push(name);
                if let Ok(md) = fs::symlink_metadata(&current_path).await
                    && md.file_type().is_symlink()
                {
                    return true;
                }
            }
            _ => {
                panic!("dav path should not contain any non-normal components")
            }
        }
    }
    false
}

impl DavFileSystem for RestrictedFs {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: DavOpenOptions,
    ) -> DavFsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            if !self.is_path_allowed(path, true).await {
                Err(DavFsError::NotFound)
            } else {
                self.local.open(path, options).await
            }
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        meta: DavReadDirMeta,
    ) -> DavFsFuture<'a, DavFsStream<Box<dyn DavDirEntry>>> {
        Box::pin(async move {
            if !self.is_path_allowed(path, false).await {
                return Err(DavFsError::NotFound);
            }

            if self.show_hidden && !self.no_symlinks && self.path_filter.is_none() {
                return self.local.read_dir(path, meta).await;
            }

            let dav_path = path.as_rel_ospath().to_path_buf();
            let base_path = self.base_path.join(&dav_path);
            let canon_base = self.canon_base.clone();
            let show_hidden = self.show_hidden;
            let no_symlinks = self.no_symlinks;
            let path_filter = self.path_filter.clone();

            let stream = self.local.read_dir(path, meta).await?;

            let filtered = stream.filter_map(move |entry_res| {
                let base_path = base_path.clone();
                let canon_base = canon_base.clone();
                let dav_path = dav_path.clone();
                let path_filter = path_filter.clone();
                async move {
                    match entry_res {
                        Ok(e) => {
                            if !show_hidden && e.name().starts_with(b".") {
                                return None;
                            }
                            let name = e.name();
                            #[cfg(not(target_os = "windows"))]
                            let os_string = OsStr::from_bytes(&name);
                            #[cfg(target_os = "windows")]
                            let os_string: &OsStr = std::str::from_utf8(&name).unwrap().as_ref();
                            let entry_path = base_path.join(os_string);

                            if no_symlinks
                                && let Ok(md) = fs::symlink_metadata(&entry_path).await
                                && md.file_type().is_symlink()
                            {
                                return None;
                            }

                            if !path_filter.is_none() {
                                if !path_filter.check_canonical_target(&canon_base, &entry_path) {
                                    return None;
                                }
                                let rel_entry = dav_path.join(os_string);
                                let is_dir = fs::metadata(&entry_path)
                                    .await
                                    .map(|m| m.is_dir())
                                    .unwrap_or(false);
                                if is_dir {
                                    if path_filter.dir_state(&rel_entry) == PathState::Denied {
                                        return None;
                                    }
                                } else if !path_filter.is_file_allowed(&rel_entry) {
                                    return None;
                                }
                            }
                            Some(Ok(e))
                        }
                        Err(e) => Some(Err(e)),
                    }
                }
            });

            Ok(Box::pin(filtered) as DavFsStream<Box<dyn DavDirEntry>>)
        })
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> DavFsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            if !self.is_path_allowed(path, false).await {
                Err(DavFsError::NotFound)
            } else {
                self.local.metadata(path).await
            }
        })
    }

    fn symlink_metadata<'a>(&'a self, path: &'a DavPath) -> DavFsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            if !self.is_path_allowed(path, false).await {
                Err(DavFsError::NotFound)
            } else {
                self.local.symlink_metadata(path).await
            }
        })
    }
}
