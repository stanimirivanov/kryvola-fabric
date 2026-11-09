use kryvola_owner_agent::{Action, Store, execute, lookup, protect, validate_slot};
use std::{
    io::{self, Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

fn run() -> Result<(), &'static str> {
    protect()?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if let [action, root, slot] = args.as_slice() {
        if !matches!(
            action.to_str(),
            Some("approve" | "verify-approval" | "revoke-approval")
        ) {
            return Err("OWNER_ARGUMENT");
        }
        let store = Store::open(Path::new(root))?;
        let slot = slot.to_str().ok_or("OWNER_SLOT")?;
        let policy = kryvola_owner_agent::approval::Policy::load(&store, slot)?;
        if action == "revoke-approval" {
            return policy.revoke(&store);
        }
        let mut input = Vec::new();
        io::stdin()
            .take(kryvola_owner_agent::approval::CONTROL as u64 + 1)
            .read_to_end(&mut input)
            .map_err(|_| "OWNER_APPROVAL_FORMAT")?;
        let now = kryvola_owner_agent::approval::now_unix_ms()?;
        return match action.to_str() {
            Some("approve") => {
                let signed =
                    kryvola_owner_agent::approval::local_sign(&policy, &store, slot, &input)?;
                io::stdout()
                    .lock()
                    .write_all(&signed)
                    .map_err(|_| "OWNER_APPROVAL_OUTPUT")
            }
            Some("verify-approval") => policy.verify(&store, &input, now),
            _ => Err("OWNER_ARGUMENT"),
        };
    }
    let [action, root, python, slot] = args.as_slice() else {
        return Err("OWNER_ARGUMENT");
    };
    let slot = slot.to_str().ok_or("OWNER_SLOT")?;
    validate_slot(slot)?;
    let action = match action.to_str() {
        Some("init") => Action::Init,
        Some("check") => Action::Check,
        Some("backup") => Action::Backup,
        Some("restore") => Action::Restore,
        _ => return Err("OWNER_ARGUMENT"),
    };
    let store = Store::open(Path::new(root))?;
    let local = lookup(Path::new("/usr/bin/secret-tool"), slot)?;
    let mut recovery = Zeroizing::new([0; 32]);
    let recovery = if matches!(action, Action::Backup | Action::Restore) {
        let mut input = io::stdin().lock();
        input
            .read_exact(&mut *recovery)
            .map_err(|_| "OWNER_RECOVERY")?;
        if input.read(&mut [0]).map_err(|_| "OWNER_RECOVERY")? != 0 {
            return Err("OWNER_RECOVERY");
        }
        Some(&*recovery)
    } else {
        None
    };
    execute(&store, Path::new(python), action, slot, &local, recovery)
}

fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}
