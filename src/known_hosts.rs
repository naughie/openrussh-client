use russh::client::{ChannelOpenHandle, Handler, Msg, Session};
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelOpenFailure};

use russh::Preferred;
use russh::keys::ssh_key;

pub use ssh_key::known_hosts as openssh_known_hosts;
use ssh_key::known_hosts::{Entry, HostPatterns, Marker};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg};
use ssh_key::{Certificate, Fingerprint, PublicKey};

use std::io::Error as IoError;
use std::path::Path;

pub struct KnownHostsHandler {
    /// Guaranteed not to contain `PubkeySigAlg::Other`.
    pubkeys: Option<Vec<(SigAlg, Fingerprint)>>,
    /// Guaranteed not to contain `CertSigAlg::Other`.
    cas: Option<(Vec<(SigAlg, Fingerprint)>, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SigAlg {
    Ed25519,
    EcdsaSha2NistP521,
    EcdsaSha2NistP384,
    EcdsaSha2NistP256,
    RsaSha512,
    RsaSha256,
    Other,
}

impl SigAlg {
    fn from(alg: &Algorithm) -> Self {
        use ssh_key::EcdsaCurve;

        match alg {
            Algorithm::Ed25519 => Self::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            } => Self::EcdsaSha2NistP521,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            } => Self::EcdsaSha2NistP384,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => Self::EcdsaSha2NistP256,
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            } => Self::RsaSha512,
            Algorithm::Rsa { hash: _ } => Self::RsaSha256,
            _ => Self::Other,
        }
    }

    const fn to_alg(self) -> Algorithm {
        use ssh_key::EcdsaCurve;

        match self {
            Self::Ed25519 => Algorithm::Ed25519,
            Self::EcdsaSha2NistP521 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            Self::EcdsaSha2NistP384 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Self::EcdsaSha2NistP256 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Self::RsaSha512 => Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            Self::RsaSha256 => Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Self::Other => unreachable!(),
        }
    }
}

impl KnownHostsHandler {
    pub fn new(known_hosts: &KnownHosts, host: &str, port: u16) -> Self {
        fn collect<T>(it: impl Iterator<Item = T>) -> Option<Vec<T>> {
            let mut ret: Option<Vec<T>> = None;

            for item in it {
                ret.get_or_insert_default().push(item);
            }

            ret
        }

        use core::fmt::NumBuffer;

        let host = host.trim_start_matches('[');
        let host = host
            .find("]:")
            .map(|idx| &host[..idx])
            .unwrap_or(host)
            .trim_end_matches(']')
            .to_ascii_lowercase();

        let mut buf = (port != 22).then(NumBuffer::new);
        let port_str = buf.as_mut().map(|buf| port.format_into(buf));

        let mut pubkeys = collect(known_hosts.public_keys.iter().filter_map(|entry| {
            if host_matched_known_hosts(&host, port_str, entry.host_patterns()) {
                let pubkey = entry.public_key();
                let alg = SigAlg::from(&pubkey.algorithm());

                (alg != SigAlg::Other)
                    .then(|| (alg, Fingerprint::new(HashAlg::Sha256, pubkey.key_data())))
            } else {
                None
            }
        }));
        if let Some(pubkeys) = &mut pubkeys {
            pubkeys.sort_unstable();
        }

        let cas = collect(known_hosts.cas.iter().filter_map(|(entry, _)| {
            if host_matched_known_hosts(&host, port_str, entry.host_patterns()) {
                let pubkey = entry.public_key();
                let alg = SigAlg::from(&pubkey.algorithm());

                (alg != SigAlg::Other)
                    .then(|| (alg, Fingerprint::new(HashAlg::Sha256, pubkey.key_data())))
            } else {
                None
            }
        }));
        let mut cas = cas.map(|cas| (cas, host));
        if let Some((cas, _)) = &mut cas {
            cas.sort_unstable();
        }

        Self { pubkeys, cas }
    }

    pub fn check_public_key(&self, pubkey: &PublicKey) -> MatchResult {
        self.check_public_key_impl(pubkey.key_data(), SigAlg::from(&pubkey.algorithm()))
    }

    fn check_public_key_impl(&self, pubkey: &KeyData, alg: SigAlg) -> MatchResult {
        if let Some(pubkeys) = &self.pubkeys {
            let fp = Fingerprint::new(HashAlg::Sha256, pubkey);
            if pubkeys.binary_search(&(alg, fp)).is_ok() {
                MatchResult::Found
            } else {
                MatchResult::KeyMismatch
            }
        } else {
            MatchResult::NotFound
        }
    }

    pub fn check_cert(&self, cert: &Certificate) -> MatchResult {
        if let Some((cas, host)) = &self.cas {
            if !cert.critical_options().is_empty() {
                return MatchResult::UnknownCriticalOptions;
            }

            if !host_matched_principals(host, cert.valid_principals()) {
                return MatchResult::PrincipalMismatch;
            }

            let cas = cas.iter().map(|(_, fp)| fp);
            if cert.validate(cas).is_ok() {
                MatchResult::Found
            } else {
                self.check_public_key_impl(cert.public_key(), SigAlg::from(&cert.algorithm()))
            }
        } else {
            MatchResult::CertNotVerified
        }
    }

    pub fn check_server_key(&self, server_key: &PublicKeyOrCertificate) -> MatchResult {
        match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => self.check_public_key(key),
            PublicKeyOrCertificate::Certificate(cert) => self.check_cert(cert),
        }
    }

    pub fn update_preferred_config(&self, config: &mut Preferred) {
        use std::borrow::Cow;

        // `it` is a sorted iterator
        fn dedup<T: Eq + Clone>(it: impl Iterator<Item = T>) -> Vec<T> {
            let mut v = Vec::new();

            for item in it {
                if let Some(prev) = v.last()
                    && &item == prev
                {
                    continue;
                }
                v.push(item.clone());
            }

            v
        }

        if let Some(pubkeys) = &self.pubkeys {
            let mut new_algs = dedup(pubkeys.iter().map(|(alg, _)| alg.to_alg()));

            for alg in config.key.iter() {
                let alg_key = SigAlg::from(alg);
                if pubkeys
                    .binary_search_by_key(&alg_key, |(alg, _)| *alg)
                    .is_err()
                {
                    new_algs.push(alg.clone());
                }
            }

            config.key = Cow::Owned(new_algs);
        }

        const PREFERRED: &[Algorithm] = &[
            SigAlg::Ed25519.to_alg(),
            SigAlg::EcdsaSha2NistP521.to_alg(),
            SigAlg::EcdsaSha2NistP256.to_alg(),
            SigAlg::EcdsaSha2NistP256.to_alg(),
            SigAlg::RsaSha512.to_alg(),
            SigAlg::RsaSha256.to_alg(),
        ];

        config.host_key_certificates = Cow::Borrowed(PREFERRED);
    }
}

impl Handler for KnownHostsHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let res: MatchResult = Self::check_server_key(self, server_public_key);
        Ok(res.is_found())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct KnownHosts {
    public_keys: Vec<Entry>,
    cas: Vec<(Entry, Fingerprint)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatchResult {
    /// The public key or certificate already exists in `~/.known_hosts`.
    Found,
    /// The public key does not exist in `~/.known_hosts`.
    NotFound,
    /// The requested host is found in `~/.known_hosts`, but given the wrong public key.
    KeyMismatch,
    /// The certificate does not match the requested host.
    PrincipalMismatch,
    /// Failed to recognize the critical options in the certificate.
    ///
    /// For now, there are no known critical options for host certificates.
    UnknownCriticalOptions,
    /// The certificate is invalid.
    ///
    /// There are sereval possible reasons:
    ///
    /// - The timestamp is invalid (expired or not yet valid).
    /// - Either the payload or the signature is corrupted.
    /// - We encounter an error when we get the current Unix timestamp.
    /// - No CAs matched the requested host.
    /// - One or more CAs are found, but no one can verity the certificate.
    CertNotVerified,
}

impl MatchResult {
    pub fn is_found(self) -> bool {
        self == Self::Found
    }
}

impl KnownHosts {
    pub fn new(known_hosts: ssh_key::KnownHosts) -> Self {
        let mut public_keys = Vec::new();
        let mut cas = Vec::new();

        for entry in known_hosts.into_iter().filter_map(|entry| entry.ok()) {
            match entry.marker() {
                Some(&Marker::Revoked) => continue,
                Some(&Marker::CertAuthority) => {
                    let fp = Fingerprint::new(HashAlg::Sha256, entry.public_key().key_data());
                    cas.push((entry, fp))
                }
                None => public_keys.push(entry),
            }
        }

        Self { public_keys, cas }
    }

    pub fn parse(known_hosts: &str) -> Self {
        Self::new(ssh_key::KnownHosts::new(known_hosts))
    }

    pub fn parse_path(known_hosts: impl AsRef<Path>) -> Result<Self, IoError> {
        let known_hosts = std::fs::read_to_string(known_hosts)?;
        Ok(Self::parse(&known_hosts))
    }

    pub fn parse_default_path() -> Result<Self, IoError> {
        let known_hosts = if let Some(mut home) = std::env::home_dir() {
            home.push(".ssh/known_hosts");
            home
        } else {
            "/etc/ssh/ssh_known_hosts".into()
        };

        Self::parse_path(known_hosts)
    }

    pub fn handler(&self, host: &str, port: u16) -> KnownHostsHandler {
        KnownHostsHandler::new(self, host, port)
    }
}

fn host_matched_principals(target_host: &str, principals: &[String]) -> bool {
    if principals.is_empty() {
        return true;
    }

    principals
        .iter()
        .any(|principal| matched_glob(target_host, principal))
}

fn host_matched_known_hosts(
    target_host: &str,
    target_port: Option<&str>,
    test: &HostPatterns,
) -> bool {
    fn verify_plain(target_host: &str, target_port: Option<&str>, pats: &[String]) -> bool {
        if pats.is_empty() {
            return false;
        }

        let mut some_matched = false;

        for pat in pats {
            let (pat, is_neg) = pat
                .strip_prefix('!')
                .map(|s| (s, true))
                .unwrap_or((pat, false));

            let host_pat = if let Some((host_pat, port_pat)) = pat.rsplit_once("]:") {
                if !matched_glob(target_port.unwrap_or("22"), port_pat) {
                    continue;
                }

                host_pat.strip_prefix('[').unwrap_or(host_pat)
            } else {
                if target_port.is_some() {
                    continue;
                }

                pat
            };

            if !matched_glob(target_host, host_pat) {
                continue;
            }

            if is_neg {
                return false;
            } else {
                some_matched = true;
            }
        }

        some_matched
    }

    fn verify_hashed(
        target_host: &str,
        target_port: Option<&str>,
        salt: &[u8],
        hash: &[u8; 20],
    ) -> bool {
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use sha1::Sha1;

        let mut mac = Hmac::<Sha1>::new_from_slice(salt).expect("HMAC can take key of any size");

        if let Some(target_port) = target_port {
            mac.update(b"[");
            mac.update(target_host.as_bytes());
            mac.update(b"]:");
            mac.update(target_port.as_bytes());
        } else {
            mac.update(target_host.as_bytes());
        }

        mac.verify_slice(hash).is_ok()
    }

    match test {
        HostPatterns::Patterns(pats) => verify_plain(target_host, target_port, pats),
        HostPatterns::HashedName { salt, hash } => {
            verify_hashed(target_host, target_port, salt, hash)
        }
    }
}

fn matched_glob(needle: &str, pattern: &str) -> bool {
    use glob::{MatchOptions, Pattern};
    use std::borrow::Cow;

    if !pattern.contains(['*', '?']) {
        return needle == pattern;
    }

    let pat = {
        let mut ret: Option<String> = None;

        let mut start = 0usize;
        for (idx, matched) in pattern.match_indices(['[', ']']) {
            let escaped = if matched == "[" { "[[]" } else { "[]]" };

            let append = &pattern[start..idx];
            let ret_inner = if let Some(ret) = ret.as_mut() {
                ret
            } else {
                ret.get_or_insert_with(|| String::with_capacity(append.len() + escaped.len()))
            };
            ret_inner.push_str(append);
            ret_inner.push_str(escaped);
            start = idx + 1;
        }

        if let Some(mut ret) = ret {
            ret.push_str(&pattern[start..]);
            Cow::Owned(ret)
        } else {
            Cow::Borrowed(pattern)
        }
    };
    let Ok(pat) = Pattern::new(&pat) else {
        return false;
    };

    let opts = MatchOptions {
        // already lowercased
        case_sensitive: true,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };

    pat.matches_with(needle, opts)
}
