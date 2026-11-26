use std::path::Path;

use zeroize::Zeroizing;

use crate::{VaultError, backend::HostPlatform};

const KEY_BYTES: usize = 32;

pub(crate) async fn read_if_present(
    host: &dyn HostPlatform,
    path: &Path,
) -> Result<Option<Vec<u8>>, VaultError> {
    match host.read_file(path).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if matches!(&err, VaultError::Filesystem { code: Some(code), .. } if code != "ENOENT") => {
            Err(err)
        }
        Err(original) => match host.file_exists(path).await {
            Ok(false) => Ok(None),
            // A concurrent publisher can fill the path between the failed
            // read and the existence check.
            Ok(true) => host.read_file(path).await.map(Some).map_err(|_| original),
            Err(_) => Err(original),
        },
    }
}

pub(crate) async fn read_key(
    host: &dyn HostPlatform,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    read_key_if_present(host, path)
        .await?
        .ok_or_else(|| VaultError::Decryption {
            message: "Missing key material".to_string(),
            path: path.display().to_string(),
        })
}

async fn read_key_if_present(
    host: &dyn HostPlatform,
    path: &Path,
) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
    let Some(bytes) = read_if_present(host, path).await? else {
        return Ok(None);
    };
    let key = Zeroizing::new(bytes);
    if key.len() != KEY_BYTES {
        return Err(VaultError::Decryption {
            message: "Invalid key material: expected 32 bytes".to_string(),
            path: path.display().to_string(),
        });
    }
    Ok(Some(key))
}

pub(crate) async fn get_or_create_key(
    host: &dyn HostPlatform,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if let Some(key) = read_key_if_present(host, path).await? {
        return Ok(key);
    }

    let mut candidate = Zeroizing::new(vec![0; KEY_BYTES]);
    getrandom::fill(&mut candidate)
        .map_err(|err| VaultError::Other(format!("Failed to generate key: {err}")))?;
    if host.publish_file_if_absent(path, &candidate).await? {
        return Ok(candidate);
    }
    read_key(host, path).await
}
