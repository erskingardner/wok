//! Publish complete database directories without replacing an existing path.
#![forbid(unsafe_code)]

use crate::DbError;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Atomically publish a staged directory. The destination must not exist,
/// including an empty directory or dangling symlink. Both paths must be on the
/// same filesystem. The caller must sync the destination's parent afterward.
pub fn promote_directory_noreplace(source: &Path, destination: &Path) -> Result<(), DbError> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            DbError::msg(format!(
                "publish {} without replacing {}: {error}",
                source.display(),
                destination.display()
            ))
        })
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    )))]
    {
        let _ = (source, destination);
        Err(DbError::msg(
            "atomic directory publication without replacement is unavailable on this platform",
        ))
    }
}

fn sync_tree(directory: &Path) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_file() {
            File::open(entry.path())?.sync_all()?;
        } else if kind.is_dir() {
            sync_tree(&entry.path())?;
        } else {
            return Err(std::io::Error::other(
                "unexpected special file in database backup",
            ));
        }
    }
    File::open(directory)?.sync_all()
}

pub(crate) fn create(
    source: &Path,
    output: &Path,
    write: impl FnOnce(&Path) -> Result<(), DbError>,
) -> Result<(), DbError> {
    let convert = |error: std::io::Error| DbError::msg(error.to_string());
    let source = fs::canonicalize(source).map_err(convert)?;
    let name = output
        .file_name()
        .ok_or_else(|| DbError::msg("backup needs a new directory name"))?;
    let parent = fs::canonicalize(
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .map_err(convert)?;
    if parent.starts_with(&source) {
        return Err(DbError::msg(
            "backup destination must be outside the source database",
        ));
    }
    let output = parent.join(name);
    match fs::symlink_metadata(&output) {
        Ok(_) => {
            return Err(DbError::msg(format!(
                "backup destination {} exists; refusing to replace it",
                output.display()
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(convert(error)),
    }
    // The native engine may create files with its own modes. Its entire output
    // remains beneath a private (0700) directory until publication.
    let staging = tempfile::Builder::new()
        .prefix(".wok-backup-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&parent)
        .map_err(convert)?;
    let database = staging.path().join("db");
    let mut published = false;
    let outcome: Result<(), DbError> = (|| {
        write(&database)?;
        fs::set_permissions(&database, fs::Permissions::from_mode(0o700)).map_err(convert)?;
        sync_tree(&database).map_err(convert)?;
        promote_directory_noreplace(&database, &output)?;
        published = true;
        File::open(&parent)
            .and_then(|file| file.sync_all())
            .map_err(convert)?;
        Ok(())
    })();
    match outcome {
        Ok(()) => Ok(()),
        Err(error) if published => Err(DbError::msg(format!(
            "backup published at {}, but parent sync failed: {error}",
            output.display()
        ))),
        Err(error) => {
            let retained = staging.keep();
            Err(DbError::msg(format!(
                "backup failed: {error}; incomplete backup retained at {}",
                retained.display()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_native_copy_retains_private_evidence_without_publishing() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let output = root.path().join("backup");
        let error = create(&source, &output, |directory| {
            fs::create_dir(directory).unwrap();
            fs::write(directory.join("partial"), b"incomplete native output").unwrap();
            Err(DbError::msg("injected native copy failure"))
        })
        .unwrap_err();
        assert!(!output.exists());
        let retained = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".wok-backup-")
            })
            .unwrap();
        assert_eq!(
            fs::metadata(&retained).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::read(retained.join("db/partial")).unwrap(),
            b"incomplete native output"
        );
        assert!(error.to_string().contains(retained.to_str().unwrap()));
    }
}
