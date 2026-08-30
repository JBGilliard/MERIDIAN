//! OS-session user claim. Not an attestation — PIV/CAC is the HSM profile.
//!
//! Collection is off unless `collect` is set (policy.allow_attribution after
//! argv tighten). Production builds never honor LEXICON_USER / LEXICON_HOST.
//! Debug builds do only when `--allow-env-identity` is set (test harnesses).

use lexicon_core::Attribution;

pub fn session_attribution(collect: bool, allow_env: bool) -> Result<Attribution, String> {
    if !collect {
        return Ok(Attribution::default());
    }
    let user = pick_field(allow_env, env_if(allow_env, "LEXICON_USER"), whoami())
        .ok_or_else(|| "cannot derive user from OS session".to_string())?;
    let host = pick_field(allow_env, env_if(allow_env, "LEXICON_HOST"), hostname())
        .ok_or_else(|| "cannot derive host from OS session".to_string())?;
    Ok(Attribution::session(user, host, detect_hwid()))
}

fn env_if(allow_env: bool, key: &str) -> Option<String> {
    if allow_env {
        std::env::var(key).ok()
    } else {
        None
    }
}

/// Env wins only when the test-only flag is on. Empty env falls through to OS.
fn pick_field(allow_env: bool, env: Option<String>, os: Option<String>) -> Option<String> {
    if allow_env {
        env.filter(|s| !s.is_empty()).or(os)
    } else {
        os
    }
}

fn whoami() -> Option<String> {
    // Absolute path first — a PATH `whoami` is a forgery.
    cmd_stdout(&["/usr/bin/whoami", "/bin/whoami"], &[])
}

fn hostname() -> Option<String> {
    cmd_stdout(&["/bin/hostname", "/usr/bin/hostname"], &[])
}

fn detect_hwid() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(darwin_platform_uuid)
}

fn darwin_platform_uuid() -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    parse_io_platform_uuid(&s)
}

fn parse_io_platform_uuid(blob: &str) -> Option<String> {
    let rest = blob.split_once("\"IOPlatformUUID\"")?.1;
    let rest = rest.split_once('=')?.1;
    let rest = rest.split_once('"')?.1;
    let val = rest.split_once('"')?.0.trim();
    (!val.is_empty()).then(|| val.to_string())
}

fn cmd_stdout(bins: &[&str], args: &[&str]) -> Option<String> {
    for bin in bins {
        if let Some(s) = std::process::Command::new(bin)
            .args(args)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return Some(s);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_only_when_allowed() {
        assert_eq!(
            pick_field(false, Some("jdoe".into()), Some("osuser".into())),
            Some("osuser".into())
        );
        assert_eq!(
            pick_field(true, Some("jdoe".into()), Some("osuser".into())),
            Some("jdoe".into())
        );
        assert_eq!(
            pick_field(true, None, Some("osuser".into())),
            Some("osuser".into())
        );
        assert_eq!(
            pick_field(true, Some(String::new()), Some("osuser".into())),
            Some("osuser".into())
        );
        assert_eq!(pick_field(false, Some("jdoe".into()), None), None);
    }

    #[test]
    fn parse_darwin_uuid() {
        let blob = r#"
+-o IOPlatformExpertDevice  <class IOPlatformExpertDevice>
{
  "IOPlatformUUID" = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
}
"#;
        assert_eq!(
            parse_io_platform_uuid(blob).as_deref(),
            Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        );
        assert_eq!(parse_io_platform_uuid("nope"), None);
    }

    #[test]
    fn os_session_has_user_and_host() {
        let a = session_attribution(true, false).expect("whoami/hostname");
        assert!(!a.user.is_empty());
        assert!(!a.host.is_empty());
        assert!(a.ip.is_none());
    }

    #[test]
    fn no_collect_is_empty_and_ignores_env() {
        let a = session_attribution(false, true).expect("default");
        assert!(a.user.is_empty());
        assert!(a.host.is_empty());
        assert!(a.ip.is_none());
        assert!(a.hwid.is_none());
    }
}
