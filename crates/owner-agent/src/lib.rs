//! Owner-local encrypted custody. No network or plaintext key API.
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};

use rustix::{
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags},
    process::{self, DumpableBehavior, Resource, Rlimit},
};
use zeroize::Zeroizing;

const MAX_ENVELOPE: usize = (65 << 20) + 40;
const PYTHON: &str = include_str!("owner_codec.py");
type Result<T> = std::result::Result<T, &'static str>;
type Secret = Zeroizing<[u8; 32]>;

pub fn validate_slot(slot: &str) -> Result<()> {
    if !(1..=80).contains(&slot.len())
        || !slot
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err("OWNER_SLOT");
    }
    Ok(())
}

pub fn protect() -> Result<()> {
    process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| "OWNER_PROCESS")?;
    process::set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|_| "OWNER_PROCESS")
}

pub struct Store(File);

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err("OWNER_PATH");
        }
        let fd = fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "OWNER_PATH")?;
        let stat = fs::fstat(&fd).map_err(|_| "OWNER_PATH")?;
        if stat.st_uid != process::geteuid().as_raw() || stat.st_mode & 0o7777 != 0o700 {
            return Err("OWNER_PATH");
        }
        fs::flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|_| "OWNER_BUSY")?;
        Ok(Self(fd.into()))
    }

    fn exists(&self, name: &str) -> Result<bool> {
        match fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(_) => Err("OWNER_FILE"),
        }
    }

    fn read(&self, name: &str) -> Result<Vec<u8>> {
        let fd = fs::openat(
            &self.0,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "OWNER_FILE")?;
        let stat = fs::fstat(&fd).map_err(|_| "OWNER_FILE")?;
        if stat.st_uid != process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || !(1..=MAX_ENVELOPE as i64).contains(&stat.st_size)
        {
            return Err("OWNER_FILE");
        }
        let mut data = Vec::new();
        File::from(fd)
            .take(MAX_ENVELOPE as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|_| "OWNER_FILE")?;
        if data.len() != stat.st_size as usize {
            return Err("OWNER_FILE");
        }
        Ok(data)
    }

    fn publish(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let pending = ".custody-pending";
        match fs::unlinkat(&self.0, pending, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err("OWNER_FILE"),
        }
        let fd = fs::openat(
            &self.0,
            pending,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| "OWNER_FILE")?;
        let mut file = File::from(fd);
        let result = (|| {
            fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|_| "OWNER_FILE")?;
            file.write_all(bytes).map_err(|_| "OWNER_FILE")?;
            file.sync_all().map_err(|_| "OWNER_FILE")?;
            fs::renameat_with(&self.0, pending, &self.0, name, fs::RenameFlags::NOREPLACE)
                .map_err(|error| {
                    if error == rustix::io::Errno::EXIST {
                        "OWNER_EXISTS"
                    } else {
                        "OWNER_FILE"
                    }
                })?;
            self.0.sync_all().map_err(|_| "OWNER_FILE")
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.0, pending, AtFlags::empty());
        }
        result
    }
}

#[derive(Clone, Copy)]
pub enum Action {
    Init,
    Check,
    Backup,
    Restore,
}

fn context(slot: &str, backup: bool) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(if backup {
        b"kryvola/owner-backup/v1\0"
    } else {
        b"kryvola/owner-custody/v1\0"
    });
    hash.update(slot.as_bytes());
    *hash.finalize().as_bytes()
}

fn limited_command(path: &Path, seconds: &str) -> Command {
    let mut command = Command::new("/usr/bin/timeout");
    command
        .args([
            OsStr::new("--kill-after=2s"),
            OsStr::new(seconds),
            path.as_os_str(),
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

fn capture(
    command: &mut Command,
    input: &[&[u8]],
    limit: usize,
    error: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    if !input.is_empty() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().map_err(|_| error)?;
    let result = (|| {
        if let Some(mut pipe) = child.stdin.take() {
            for bytes in input {
                pipe.write_all(bytes).map_err(|_| error)?;
            }
        }
        let mut output = Zeroizing::new(Vec::with_capacity(limit.min(128)));
        child
            .stdout
            .take()
            .ok_or(error)?
            .take(limit as u64 + 1)
            .read_to_end(&mut output)
            .map_err(|_| error)?;
        if output.len() > limit {
            return Err(error);
        }
        Ok(output)
    })();
    if result.is_err() {
        // Closing the pipes releases a well-behaved helper. timeout reaps a stuck one.
        drop(child.stdin.take());
        drop(child.stdout.take());
    }
    if !child.wait().map_err(|_| error)?.success() {
        return Err(error);
    }
    result
}

pub fn lookup(tool: &Path, slot: &str) -> Result<Secret> {
    validate_slot(slot)?;
    let bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").ok_or("OWNER_KEYSTORE")?;
    if !bus.as_encoded_bytes().starts_with(b"unix:") || bus.as_encoded_bytes().contains(&b';') {
        return Err("OWNER_KEYSTORE");
    }
    let mut command = limited_command(tool, "10s");
    command.env("DBUS_SESSION_BUS_ADDRESS", bus).args([
        "lookup",
        "application",
        "kryvola-owner-v1",
        "slot",
        slot,
    ]);
    let bytes = capture(&mut command, &[], 65, "OWNER_KEYSTORE")?;
    let hex = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let mut key = Zeroizing::new([0; 32]);
    hex::decode_to_slice(hex, &mut *key).map_err(|_| "OWNER_KEYSTORE")?;
    if *key == [0; 32] {
        return Err("OWNER_KEYSTORE");
    }
    Ok(key)
}

pub fn execute(
    store: &Store,
    python: &Path,
    action: Action,
    slot: &str,
    local: &[u8; 32],
    recovery: Option<&[u8; 32]>,
) -> Result<()> {
    validate_slot(slot)?;
    if !python.is_absolute() || *local == [0; 32] {
        return Err("OWNER_POLICY");
    }
    let key_file = format!("{slot}.key");
    let backup_file = format!("{slot}.backup");
    let local_context = context(slot, false);
    let backup_context = context(slot, true);
    let (operation, source, destination) = match action {
        Action::Init => ("init", None, Some(&key_file)),
        Action::Check => ("check", Some(&key_file), None),
        Action::Backup => ("backup", Some(&key_file), Some(&backup_file)),
        Action::Restore => ("restore", Some(&backup_file), Some(&key_file)),
    };
    let recovery = match action {
        Action::Backup | Action::Restore => recovery
            .filter(|secret| **secret != [0; 32] && *secret != local)
            .ok_or("OWNER_RECOVERY")?,
        _ => &[0; 32],
    };
    if let Some(name) = destination
        && store.exists(name)?
    {
        return Err("OWNER_EXISTS");
    }
    let sealed = source
        .map(|name| store.read(name))
        .transpose()?
        .unwrap_or_default();
    let mut command = limited_command(python, "60s");
    command.args(["-I", "-c", PYTHON, operation]);
    let output = capture(
        &mut command,
        &[local, &local_context, recovery, &backup_context, &sealed],
        MAX_ENVELOPE,
        "OWNER_CODEC",
    )?;
    if let Some(name) = destination {
        if output.is_empty() {
            return Err("OWNER_CODEC");
        }
        store.publish(name, &output)?;
    } else if !output.is_empty() {
        return Err("OWNER_CODEC");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn private_directory_and_atomic_non_overwriting_files() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::open(directory.path()).is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(Store::open(directory.path()).is_err());
        store.publish("slot.key", b"sealed fixture").unwrap();
        assert_eq!(store.publish("slot.key", b"overwrite"), Err("OWNER_EXISTS"));
        assert_eq!(store.read("slot.key").unwrap(), b"sealed fixture");
        let path = directory.path().join("slot.key");
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        symlink(&path, directory.path().join("other.key")).unwrap();
        assert!(store.read("other.key").is_err());
        std::fs::hard_link(&path, directory.path().join("linked.key")).unwrap();
        assert!(store.read("slot.key").is_err());
        assert!(!directory.path().join(".custody-pending").exists());
    }

    #[test]
    fn process_protection_is_applied_and_observable() {
        protect().unwrap();
        let core = process::getrlimit(Resource::Core);
        assert_eq!((core.current, core.maximum), (Some(0), Some(0)));
        assert_eq!(
            process::dumpable_behavior().unwrap(),
            DumpableBehavior::NotDumpable
        );
    }
}
