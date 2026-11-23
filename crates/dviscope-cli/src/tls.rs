//! `dviscope tls init|renew`: a local CA whose key stays in the maintainer's
//! private state directory, and a leaf for `127.0.0.1` / `localhost`. `init` never replaces
//! an existing CA; `renew` reissues the leaf with the existing CA, staging the new pair and
//! keeping the old one until the new one is fully written.
//!
//! Private files: on Unix, directories are created 0700 and keys 0600 (set explicitly, not
//! left to the umask), existing keys with group/other access are refused, and secrets on
//! `/mnt/*` (Windows drives seen from WSL, where modes do not protect) are refused, checked
//! on the resolved path so symlinks cannot escape it. On Windows, key generation is refused
//! until owner-only DACLs can be set and verified at creation (`platform::windows`, Stage
//! 2c); generate the keys in WSL instead (the pilot's server runs there).

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
};
use time::{Duration, OffsetDateTime};

/// Leaf lifetime.
pub const LEAF_DAYS: i64 = 365;
/// CA lifetime.
pub const CA_DAYS: i64 = 3650;

/// Output paths.
#[derive(Debug, Clone)]
pub struct TlsPaths {
    /// CA certificate (public).
    pub ca_cert: PathBuf,
    /// CA key (private, maintainer only).
    pub ca_key: PathBuf,
    /// Leaf certificate chain for the server.
    pub server_cert: PathBuf,
    /// Leaf key for the server.
    pub server_key: PathBuf,
}

impl TlsPaths {
    /// Standard layout: CA files in `ca_dir`, server files in `server_dir`.
    #[must_use]
    pub fn new(ca_dir: &Path, server_dir: &Path) -> Self {
        Self {
            ca_cert: ca_dir.join("dviscope-ca.pem"),
            ca_key: ca_dir.join("dviscope-ca.key"),
            server_cert: server_dir.join("server.pem"),
            server_key: server_dir.join("server.key"),
        }
    }
}

/// Where private files may live.
#[derive(Debug, Clone, Default)]
pub struct PrivatePolicy {
    /// Test-only escape hatch: accept any location (never set by the CLI).
    pub allow_any_location: bool,
}

/// TLS errors.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Refused to replace an existing CA.
    #[error(
        "a CA already exists at {0}; use `dviscope tls renew` to reissue the server certificate"
    )]
    CaExists(PathBuf),
    /// No CA to renew with.
    #[error("no CA at {0}; run `dviscope tls init` first")]
    NoCa(PathBuf),
    /// The CA predates name constraints: renewing would keep an unconstrained trust anchor.
    #[error(
        "the CA at {0} is not limited to local names; create a new one with `dviscope tls init` \
         in a new CA directory, then replace the trusted copy (browser or OS store) with it"
    )]
    LegacyCa(PathBuf),
    /// A private file is accessible to others or in an unprotectable place.
    #[error("refusing {path}: {reason}")]
    NotPrivate {
        /// File or directory.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// Certificate generation failed.
    #[error("certificate generation failed: {0}")]
    Generate(String),
    /// File I/O failed.
    #[error("{path}: {source}")]
    Io {
        /// File.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> TlsError + '_ {
    move |source| TlsError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn gen_err(e: rcgen::Error) -> TlsError {
    TlsError::Generate(e.to_string())
}

/// The nearest existing ancestor of `path`, resolved (symlinks followed), with the
/// remaining components appended.
fn resolved(path: &Path) -> Result<PathBuf, TlsError> {
    let abs = std::path::absolute(path).map_err(io(path))?;
    let mut existing = abs.as_path();
    let mut rest = Vec::new();
    while !existing.exists() {
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                existing = parent;
            }
            _ => break,
        }
    }
    let mut out = std::fs::canonicalize(existing).map_err(io(existing))?;
    for name in rest.into_iter().rev() {
        out.push(name);
    }
    Ok(out)
}

/// Checks that `path` is a place where private files can be protected.
fn check_location(path: &Path, policy: &PrivatePolicy) -> Result<(), TlsError> {
    if policy.allow_any_location {
        return Ok(());
    }
    if cfg!(windows) {
        return Err(TlsError::NotPrivate {
            path: path.to_path_buf(),
            reason: "on Windows, owner-only ACLs for keys are not implemented yet; run `dviscope tls init` in WSL (where the server runs) and copy only the public CA certificate to Windows".into(),
        });
    }
    let real = resolved(path)?;
    if real.starts_with("/mnt") {
        return Err(TlsError::NotPrivate {
            path: real,
            reason: "secrets on /mnt/* (a Windows drive seen from WSL) cannot be protected by file modes; use a path on the Linux file system".into(),
        });
    }
    Ok(())
}

/// Creates a private directory (0700 on Unix) or checks an existing one.
fn private_dir(dir: &Path, policy: &PrivatePolicy) -> Result<(), TlsError> {
    check_location(dir, policy)?;
    if !dir.exists() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            b.mode(0o700);
        }
        b.create(dir).map_err(io(dir))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir)
            .map_err(io(dir))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(TlsError::NotPrivate {
                path: dir.to_path_buf(),
                reason: format!(
                    "directory mode {:o} gives access to others (chmod 700)",
                    mode & 0o777
                ),
            });
        }
    }
    Ok(())
}

/// Refuses an existing private file that others can read.
fn check_private_file(path: &Path, policy: &PrivatePolicy) -> Result<(), TlsError> {
    check_location(path, policy)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .map_err(io(path))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(TlsError::NotPrivate {
                path: path.to_path_buf(),
                reason: format!("mode {:o} gives access to others (chmod 600)", mode & 0o777),
            });
        }
    }
    Ok(())
}

/// Writes `data` to a new private file (0600 on Unix, set explicitly) at `path`, which
/// must not exist.
fn write_new_private(path: &Path, data: &[u8]) -> Result<(), TlsError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(io(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(io(path))?;
    }
    f.write_all(data).map_err(io(path))?;
    f.sync_all().map_err(io(path))
}

fn write_new_public(path: &Path, data: &[u8]) -> Result<(), TlsError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io(path))?;
    f.write_all(data).map_err(io(path))?;
    f.sync_all().map_err(io(path))
}

/// The only names the local CA may vouch for: the leaf's `localhost`, `127.0.0.1` and `::1`.
/// A user who trusts the CA in a browser or OS store then trusts nothing else with it, even if
/// its key leaks. A DNS subtree also covers subdomains (RFC 5280 4.2.1.10): names under
/// `localhost` are loopback names too (RFC 6761 6.3), so that is intended.
fn local_only() -> NameConstraints {
    let mut v6 = [0_u8; 16];
    v6[15] = 1;
    NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName("localhost".to_string()),
            GeneralSubtree::IpAddress(CidrSubnet::V4([127, 0, 0, 1], [255; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6(v6, [255; 16])),
        ],
        excluded_subtrees: Vec::new(),
    }
}

/// Whether a CA certificate carries a critical name-constraints extension (a CA made before
/// the constraints were introduced has none).
fn has_local_constraints(cert_pem: &str) -> bool {
    let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()) else {
        return false;
    };
    let Ok(cert) = pem.parse_x509() else {
        return false;
    };
    cert.extensions().iter().any(|e| {
        e.critical
            && matches!(
                e.parsed_extension(),
                x509_parser::extensions::ParsedExtension::NameConstraints(_)
            )
    })
}

fn ca_params(now: OffsetDateTime) -> Result<CertificateParams, TlsError> {
    let mut p = CertificateParams::new(Vec::<String>::new()).map_err(gen_err)?;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.name_constraints = Some(local_only());
    p.distinguished_name
        .push(DnType::CommonName, "DVIScope local CA");
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    p.not_before = now - Duration::minutes(5);
    p.not_after = now + Duration::days(CA_DAYS);
    Ok(p)
}

/// A freshly generated leaf: chain PEM (leaf + CA) and key PEM.
fn generate_leaf(
    now: OffsetDateTime,
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> Result<(String, String), TlsError> {
    let mut leaf = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
        .map_err(gen_err)?;
    leaf.distinguished_name
        .push(DnType::CommonName, "DVIScope server");
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf.not_before = now - Duration::minutes(5);
    leaf.not_after = now + Duration::days(LEAF_DAYS);
    // Strict X.509 verifiers (e.g. Python 3.13+ `VERIFY_X509_STRICT`) require the
    // authority key identifier on a CA-issued certificate.
    leaf.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate().map_err(gen_err)?;
    let leaf_cert = leaf
        .signed_by(&leaf_key, ca_cert, ca_key)
        .map_err(gen_err)?;
    Ok((
        format!("{}{}", leaf_cert.pem(), ca_cert.pem()),
        leaf_key.serialize_pem(),
    ))
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

/// Checks that the first certificate of `chain_pem` is a valid X.509 certificate whose
/// public key is the public key of `key` (the pair belongs together).
fn verify_pair(chain_pem: &[u8], key: &KeyPair) -> Result<(), TlsError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem)
        .map_err(|e| TlsError::Generate(format!("staged certificate is not PEM: {e}")))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| TlsError::Generate(format!("staged certificate is not X.509: {e}")))?;
    if cert.public_key().raw != key.public_key_der().as_slice() {
        return Err(TlsError::Generate(
            "staged certificate and key do not match".into(),
        ));
    }
    Ok(())
}

/// One step of the activation, recorded so it can be undone.
enum Moved {
    /// `from` was renamed to `to`.
    Renamed { from: PathBuf, to: PathBuf },
}

fn undo(done: Vec<Moved>) {
    for Moved::Renamed { from, to } in done.into_iter().rev() {
        let _ = std::fs::rename(&to, &from);
    }
}

/// Installs a new leaf pair. Both files are first written as `.new`; the current pair is then
/// moved to `.old` and the new pair into place. A failure at any step undoes the steps done
/// so far, so the previous pair stays active. Backups from an earlier renewal are removed
/// only after the switch succeeded. A lock file serializes concurrent renewals.
fn install_leaf(paths: &TlsPaths, chain: &str, key: &str) -> Result<(), TlsError> {
    let lock = sibling(&paths.server_key, ".lock");
    let _guard = LockFile::acquire(&lock)?;
    let (cert_new, key_new) = (
        sibling(&paths.server_cert, ".new"),
        sibling(&paths.server_key, ".new"),
    );
    let stamp = std::process::id();
    let (cert_old, key_old) = (
        sibling(&paths.server_cert, &format!(".old-{stamp}")),
        sibling(&paths.server_key, &format!(".old-{stamp}")),
    );
    for p in [&cert_new, &key_new] {
        if p.exists() {
            std::fs::remove_file(p).map_err(io(p))?;
        }
    }
    write_new_public(&cert_new, chain.as_bytes())?;
    write_new_private(&key_new, key.as_bytes())?;
    // Validate the staged pair before touching the active one.
    let staged_key = std::fs::read_to_string(&key_new).map_err(io(&key_new))?;
    let staged_key = KeyPair::from_pem(&staged_key).map_err(gen_err)?;
    let staged_chain = std::fs::read(&cert_new).map_err(io(&cert_new))?;
    verify_pair(&staged_chain, &staged_key)?;

    let mut done = Vec::new();
    let steps: Vec<(PathBuf, PathBuf)> = [
        (paths.server_cert.clone(), cert_old.clone()),
        (paths.server_key.clone(), key_old.clone()),
    ]
    .into_iter()
    .filter(|(from, _)| from.exists())
    .chain([
        (key_new, paths.server_key.clone()),
        (cert_new, paths.server_cert.clone()),
    ])
    .collect();
    for (from, to) in steps {
        if let Err(e) = std::fs::rename(&from, &to) {
            undo(done);
            return Err(TlsError::Io {
                path: from,
                source: e,
            });
        }
        done.push(Moved::Renamed { from, to });
    }
    // Success: keep this renewal's backups as `.old`, drop older ones.
    for (backup, keep) in [
        (cert_old, sibling(&paths.server_cert, ".old")),
        (key_old, sibling(&paths.server_key, ".old")),
    ] {
        if backup.exists() {
            let _ = std::fs::remove_file(&keep);
            let _ = std::fs::rename(&backup, &keep);
        }
    }
    Ok(())
}

/// An exclusive lock file, removed on drop.
struct LockFile(PathBuf);

impl LockFile {
    fn acquire(path: &Path) -> Result<Self, TlsError> {
        OpenOptions::new().write(true).create_new(true).open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                TlsError::NotPrivate {
                    path: path.to_path_buf(),
                    reason: "another renewal is running (or a stale lock file remains; remove it if no renewal is running)".into(),
                }
            } else {
                TlsError::Io { path: path.to_path_buf(), source: e }
            }
        })?;
        Ok(Self(path.to_path_buf()))
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Creates a CA and a server certificate. Never replaces an existing CA.
///
/// # Errors
/// Existing CA, unprotectable location, generation or file errors.
pub fn init(paths: &TlsPaths, now: OffsetDateTime, policy: &PrivatePolicy) -> Result<(), TlsError> {
    if paths.ca_key.exists() || paths.ca_cert.exists() {
        return Err(TlsError::CaExists(paths.ca_key.clone()));
    }
    for dir in [paths.ca_key.parent(), paths.server_key.parent()]
        .into_iter()
        .flatten()
    {
        private_dir(dir, policy)?;
    }
    let ca_key = KeyPair::generate().map_err(gen_err)?;
    let ca_cert = ca_params(now)?.self_signed(&ca_key).map_err(gen_err)?;
    write_new_private(&paths.ca_key, ca_key.serialize_pem().as_bytes())?;
    write_new_public(&paths.ca_cert, ca_cert.pem().as_bytes())?;
    let (chain, key) = generate_leaf(now, &ca_cert, &ca_key)?;
    install_leaf(paths, &chain, &key)
}

/// Reissues the server certificate with the existing CA.
///
/// # Errors
/// Missing or unprotected CA, generation or file errors.
pub fn renew(
    paths: &TlsPaths,
    now: OffsetDateTime,
    policy: &PrivatePolicy,
) -> Result<(), TlsError> {
    if !paths.ca_key.exists() || !paths.ca_cert.exists() {
        return Err(TlsError::NoCa(paths.ca_key.clone()));
    }
    check_private_file(&paths.ca_key, policy)?;
    if let Some(dir) = paths.server_key.parent() {
        private_dir(dir, policy)?;
    }
    let key_pem = std::fs::read_to_string(&paths.ca_key).map_err(io(&paths.ca_key))?;
    let cert_pem = std::fs::read_to_string(&paths.ca_cert).map_err(io(&paths.ca_cert))?;
    if !has_local_constraints(&cert_pem) {
        return Err(TlsError::LegacyCa(paths.ca_cert.clone()));
    }
    let ca_key = KeyPair::from_pem(&key_pem).map_err(gen_err)?;
    // Same subject and key as the stored CA, so the existing trust anchor validates the leaf.
    let mut params = CertificateParams::from_ca_cert_pem(&cert_pem).map_err(gen_err)?;
    params.name_constraints = Some(local_only());
    let ca_cert = params.self_signed(&ca_key).map_err(gen_err)?;
    let (chain, key) = generate_leaf(now, &ca_cert, &ca_key)?;
    install_leaf(paths, &chain, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any() -> PrivatePolicy {
        PrivatePolicy {
            allow_any_location: true,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dviscope-tls-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn init_refuses_existing_ca_and_renew_keeps_old_pair() {
        let dir = tmp("unit");
        let paths = TlsPaths::new(&dir.join("ca"), &dir.join("server"));
        assert!(matches!(
            renew(&paths, OffsetDateTime::now_utc(), &any()),
            Err(TlsError::NoCa(_))
        ));
        init(&paths, OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            init(&paths, OffsetDateTime::now_utc(), &any()),
            Err(TlsError::CaExists(_))
        ));
        let before = std::fs::read(&paths.server_cert).unwrap_or_default();
        renew(&paths, OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(
            before,
            std::fs::read(&paths.server_cert).unwrap_or_default()
        );
        assert_eq!(
            before,
            std::fs::read(sibling(&paths.server_cert, ".old")).unwrap_or_default()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| {
                std::fs::metadata(p)
                    .map(|m| m.permissions().mode() & 0o777)
                    .unwrap_or(0)
            };
            assert_eq!(mode(&paths.ca_key), 0o600);
            assert_eq!(mode(&paths.server_key), 0o600);
            assert_eq!(mode(&dir.join("ca")), 0o700);
            // A CA key readable by others is refused on renew.
            std::fs::set_permissions(&paths.ca_key, std::fs::Permissions::from_mode(0o644))
                .unwrap_or(());
            assert!(matches!(
                renew(&paths, OffsetDateTime::now_utc(), &any()),
                Err(TlsError::NotPrivate { .. })
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The leaf names its issuer's key (AKI = the CA's SKI), after init and after renew:
    /// strict verifiers refuse a CA-issued certificate without it.
    #[test]
    fn leaf_carries_the_authority_key_identifier() {
        use x509_parser::extensions::ParsedExtension;
        let dir = tmp("aki");
        let paths = TlsPaths::new(&dir.join("ca"), &dir.join("server"));
        init(&paths, OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
        let ski = |der: &[u8]| -> Option<Vec<u8>> {
            let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
            c.extensions()
                .iter()
                .find_map(|e| match e.parsed_extension() {
                    ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
                    _ => None,
                })
        };
        let aki = |der: &[u8]| -> Option<Vec<u8>> {
            let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
            c.extensions()
                .iter()
                .find_map(|e| match e.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(k) => {
                        k.key_identifier.as_ref().map(|k| k.0.to_vec())
                    }
                    _ => None,
                })
        };
        let pem_der = |path: &Path| -> Vec<u8> {
            let text = std::fs::read(path).unwrap_or_default();
            x509_parser::pem::parse_x509_pem(&text)
                .map(|(_, p)| p.contents)
                .unwrap_or_default()
        };
        let ca = ski(&pem_der(&paths.ca_cert));
        assert!(ca.is_some(), "the CA has a subject key identifier");
        assert_eq!(aki(&pem_der(&paths.server_cert)), ca);
        renew(&paths, OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(aki(&pem_der(&paths.server_cert)), ca);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ca_is_limited_to_local_names() {
        use x509_parser::extensions::{GeneralName, ParsedExtension};
        let ca_key = KeyPair::generate().unwrap_or_else(|e| panic!("{e}"));
        let ca = ca_params(OffsetDateTime::now_utc())
            .and_then(|p| p.self_signed(&ca_key).map_err(gen_err))
            .unwrap_or_else(|e| panic!("{e}"));
        let (_, cert) =
            x509_parser::parse_x509_certificate(ca.der()).unwrap_or_else(|e| panic!("{e}"));
        let mut names = Vec::new();
        for ext in cert.extensions() {
            if let ParsedExtension::NameConstraints(nc) = ext.parsed_extension() {
                assert!(ext.critical);
                for sub in nc.permitted_subtrees.iter().flatten() {
                    names.push(match &sub.base {
                        GeneralName::DNSName(d) => (*d).to_string(),
                        GeneralName::IPAddress(ip) => format!("{ip:?}"),
                        other => panic!("unexpected subtree {other:?}"),
                    });
                }
            }
        }
        assert_eq!(names.len(), 3, "{names:?}");
        assert_eq!(names[0], "localhost");
        // Address and mask, each a single host.
        assert!(
            names[1].contains("127, 0, 0, 1, 255, 255, 255, 255"),
            "{names:?}"
        );
        assert!(
            names[2].contains(&format!("{}1, {}", "0, ".repeat(15), "255, ".repeat(15))),
            "{names:?}"
        );
    }

    /// A real verifier (rustls/webpki) accepts the local leaf and rejects any other name the
    /// CA's key might sign.
    #[test]
    fn verifier_enforces_the_constraints() {
        use rustls::client::WebPkiServerVerifier;
        use rustls::client::danger::ServerCertVerifier as _;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use std::sync::Arc;

        let now = OffsetDateTime::now_utc();
        let ca_key = KeyPair::generate().unwrap_or_else(|e| panic!("{e}"));
        let ca = ca_params(now)
            .and_then(|p| p.self_signed(&ca_key).map_err(gen_err))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.der().to_vec()))
            .unwrap_or_else(|e| panic!("{e}"));
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
        let leaf_for = |names: Vec<String>| {
            let mut p = CertificateParams::new(names).unwrap_or_else(|e| panic!("{e}"));
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let key = KeyPair::generate().unwrap_or_else(|e| panic!("{e}"));
            let cert = p
                .signed_by(&key, &ca, &ca_key)
                .unwrap_or_else(|e| panic!("{e}"));
            CertificateDer::from(cert.der().to_vec())
        };
        let check = |leaf: &CertificateDer<'static>, name: &str| {
            let name = ServerName::try_from(name.to_string()).unwrap_or_else(|e| panic!("{e}"));
            verifier
                .verify_server_cert(leaf, &[], &name, &[], UnixTime::now())
                .is_ok()
        };
        let local = leaf_for(vec!["127.0.0.1".to_string(), "localhost".to_string()]);
        assert!(check(&local, "localhost"));
        assert!(check(&local, "127.0.0.1"));
        let foreign = leaf_for(vec!["bank.example".to_string()]);
        assert!(!check(&foreign, "bank.example"));
        let foreign_ip = leaf_for(vec!["192.0.2.7".to_string()]);
        assert!(!check(&foreign_ip, "192.0.2.7"));
    }

    #[test]
    fn renew_refuses_a_legacy_unconstrained_ca() {
        let dir = tmp("legacy");
        let paths = TlsPaths::new(&dir.join("ca"), &dir.join("server"));
        for d in [dir.join("ca"), dir.join("server")] {
            private_dir(&d, &any()).unwrap_or_else(|e| panic!("{e}"));
        }
        let ca_key = KeyPair::generate().unwrap_or_else(|e| panic!("{e}"));
        let mut legacy = ca_params(OffsetDateTime::now_utc()).unwrap_or_else(|e| panic!("{e}"));
        legacy.name_constraints = None;
        let ca = legacy
            .self_signed(&ca_key)
            .unwrap_or_else(|e| panic!("{e}"));
        write_new_private(&paths.ca_key, ca_key.serialize_pem().as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
        write_new_public(&paths.ca_cert, ca.pem().as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            renew(&paths, OffsetDateTime::now_utc(), &any()),
            Err(TlsError::LegacyCa(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mismatched_pair_is_detected() {
        let ca_key = KeyPair::generate().unwrap_or_else(|e| panic!("{e}"));
        let ca = ca_params(OffsetDateTime::now_utc())
            .and_then(|p| p.self_signed(&ca_key).map_err(gen_err))
            .unwrap_or_else(|e| panic!("{e}"));
        let (chain, key_pem) = generate_leaf(OffsetDateTime::now_utc(), &ca, &ca_key)
            .unwrap_or_else(|e| panic!("{e}"));
        let key = KeyPair::from_pem(&key_pem).unwrap_or_else(|e| panic!("{e}"));
        assert!(verify_pair(chain.as_bytes(), &key).is_ok());
        let other = KeyPair::generate().unwrap_or_else(|e| panic!("{e}"));
        assert!(verify_pair(chain.as_bytes(), &other).is_err());
        assert!(verify_pair(b"not pem", &key).is_err());
    }

    #[test]
    fn failed_activation_keeps_the_active_pair() {
        let dir = tmp("rollback");
        let paths = TlsPaths::new(&dir.join("ca"), &dir.join("server"));
        init(&paths, OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
        let cert_before = std::fs::read(&paths.server_cert).unwrap_or_default();
        let key_before = std::fs::read(&paths.server_key).unwrap_or_default();
        // A directory where the certificate's final step must land makes the last rename fail:
        // occupy `server.pem` after the first two steps by making the cert path a non-empty dir
        // is not possible before staging, so instead block the `.old` name of the key.
        std::fs::create_dir_all(
            sibling(&paths.server_key, &format!(".old-{}", std::process::id())).join("x"),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(renew(&paths, OffsetDateTime::now_utc(), &any()).is_err());
        assert_eq!(
            std::fs::read(&paths.server_cert).unwrap_or_default(),
            cert_before
        );
        assert_eq!(
            std::fs::read(&paths.server_key).unwrap_or_default(),
            key_before
        );
        assert!(!sibling(&paths.server_key, ".lock").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn secrets_on_mnt_are_refused() {
        let paths = TlsPaths::new(Path::new("/mnt/d/ca"), Path::new("/mnt/d/server"));
        // Also through a symlink whose target is under /mnt.
        let dir = tmp("mntlink");
        std::fs::create_dir_all(&dir).unwrap_or(());
        let link = dir.join("link");
        if std::os::unix::fs::symlink("/mnt", &link).is_ok() {
            let via = TlsPaths::new(&link.join("ca"), &link.join("server"));
            assert!(matches!(
                init(&via, OffsetDateTime::now_utc(), &PrivatePolicy::default()),
                Err(TlsError::NotPrivate { .. })
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(
            init(&paths, OffsetDateTime::now_utc(), &PrivatePolicy::default()),
            Err(TlsError::NotPrivate { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_key_generation_is_refused_until_acls_exist() {
        let policy = PrivatePolicy::default();
        let dir = tmp("win");
        let paths = TlsPaths::new(&dir.join("ca"), &dir.join("server"));
        assert!(matches!(
            init(&paths, OffsetDateTime::now_utc(), &policy),
            Err(TlsError::NotPrivate { .. })
        ));
    }
}
