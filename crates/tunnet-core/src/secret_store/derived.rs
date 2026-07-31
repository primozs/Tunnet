//! Machine-bound wrap key: HKDF-SHA256(machine-id, salt).
//!
//! Intentionally excludes Linux `boot_id`: that value changes every reboot, which
//! made sealed `state.enc` unreadable after restart (systemd agents crash-looped
//! with `unwrap DEK failed`). Machine-id alone still resists offline copy to
//! another host.

#[cfg(any(target_os = "macos", windows))]
use anyhow::Context;
use anyhow::bail;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const INFO: &[u8] = b"tunnet-state-enc-v1";

pub fn derive_wrap_key(salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let machine = read_machine_id()?;
    let ikm = machine.as_bytes();

    // HKDF-Extract: PRK = HMAC(salt, IKM)
    let mut extract = HmacSha256::new_from_slice(if salt.is_empty() { &[0u8; 32] } else { salt })
        .map_err(|_| anyhow::anyhow!("HMAC key"))?;
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    // HKDF-Expand: OKM = HMAC(PRK, info || 0x01)
    let mut expand = HmacSha256::new_from_slice(&prk).map_err(|_| anyhow::anyhow!("HMAC key"))?;
    expand.update(INFO);
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes();

    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    Ok(out)
}

fn read_machine_id() -> anyhow::Result<String> {
    #[cfg(target_os = "linux")]
    {
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(s) = std::fs::read_to_string(path) {
                let t = s.trim();
                if !t.is_empty() {
                    return Ok(t.to_string());
                }
            }
        }
        bail!("no machine-id found");
    }
    #[cfg(target_os = "macos")]
    {
        // IOPlatformUUID via ioreg
        let out = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .context("ioreg")?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(rest) = line.split("IOPlatformUUID").nth(1)
                && let Some(start) = rest.find('"')
            {
                let rest = &rest[start + 1..];
                if let Some(end) = rest.find('"') {
                    return Ok(rest[..end].to_string());
                }
            }
        }
        bail!("IOPlatformUUID not found");
    }
    #[cfg(windows)]
    {
        // MachineGuid from registry
        let out = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .context("reg query MachineGuid")?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.contains("MachineGuid") {
                let parts: Vec<_> = line.split_whitespace().collect();
                if let Some(guid) = parts.last() {
                    return Ok(guid.to_string());
                }
            }
        }
        bail!("MachineGuid not found");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Ok("unknown-machine".into())
    }
}

