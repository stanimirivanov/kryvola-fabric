use std::{
    error::Error,
    fs::File,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
};

use kryvola_fabric_core::{
    limits::CONTROL_BYTES,
    registry::{Registry, RegistryError},
    registry_http::connect_pool,
};

fn bounded(reader: impl Read) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    reader
        .take(CONTROL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > CONTROL_BYTES {
        return Err("RELEASE_REJECTED".into());
    }
    Ok(bytes)
}

async fn registry(db: &str) -> Result<Registry, Box<dyn Error>> {
    let metadata = File::open(db)?.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("RELEASE_REJECTED".into());
    }
    Ok(Registry::new(connect_pool(db).await?))
}

pub(super) async fn commit(db: &str, config: &str) -> Result<(), Box<dyn Error>> {
    let file = File::open(config).map_err(|_| "RELEASE_REJECTED")?;
    let metadata = file.metadata().map_err(|_| "RELEASE_REJECTED")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("RELEASE_REJECTED".into());
    }
    let policy = serde_json::from_slice(&bounded(file)?).map_err(|_| "RELEASE_REJECTED")?;
    let request =
        serde_json::from_slice(&bounded(io::stdin().lock())?).map_err(|_| "RELEASE_REJECTED")?;
    let registry = registry(db).await.map_err(|_| "RELEASE_UNAVAILABLE")?;
    match registry.commit_release(&request, &policy).await {
        Ok(decision) => println!("{decision}"),
        Err(RegistryError::Unavailable) => std::process::exit(75),
        Err(_) => return Err("RELEASE_REJECTED".into()),
    }
    Ok(())
}

pub(super) async fn revoke(db: &str, digest: &str) -> Result<(), Box<dyn Error>> {
    registry(db)
        .await
        .map_err(|_| "RELEASE_UNAVAILABLE")?
        .revoke_release_approval(digest)
        .await
        .map_err(|_| "RELEASE_REJECTED".into())
}
