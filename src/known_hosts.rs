//! Utilities to read and parse OpenSSH `known_hosts` files and
//! [`check_server_key()`](KnownHostsHandler::check_server_key()) against them.
//!
//! [`KnownHosts`] represents the trusted and revoked keys, and [`KnownHostsHandler`] checks the
//! server host key for a given host and port. They support public keys and host certificates,
//! including the
//! [`@cert-authority`](openssh_known_hosts::Marker::CertAuthority) and
//! [`@revoked`](openssh_known_hosts::Marker::Revoked) entries.
//! `KnownHosts` also implements [`MakeHandler`] to create a handler and client config for each
//! server in a connection chain.
//!
//! If no matched key is found, then the connection fails. We do not add it automatically, nor
//! do we prompt you. If you need more flexibility, you can
//! [`check_server_key()`](KnownHostsHandler::check_server_key()) directly in your own
//! [`Handler`] implementation.
//!
//! # Usage
//!
//! ```
//! # async fn dummy() {
//! use openrussh_client::known_hosts::KnownHosts;
//!
//! use russh::client::{Config, connect};
//!
//! use std::sync::Arc;
//!
//! let known_hosts = KnownHosts::parse_default_path().unwrap();
//! let handler = known_hosts.handler("my-host", 22);
//!
//! let mut conf = Config::default();
//! handler.update_preferred_config(&mut conf.preferred);
//!
//! let handle = connect(Arc::new(conf), ("my-host", 22), handler).await.unwrap();
//! # }
//! ```

use crate::connect::{Context, MakeHandler};

use russh::client::{ChannelOpenHandle, Handler, Msg, Session};
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelOpenFailure};

use russh::Preferred;
use russh::keys::ssh_key;

pub use ssh_key::known_hosts as openssh_known_hosts;
use ssh_key::known_hosts::HostPatterns;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg};
use ssh_key::{Certificate, Fingerprint, PublicKey};

use std::io::Error as IoError;
use std::iter::FusedIterator;
use std::path::Path;
use std::sync::Arc;

type Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LookupKey {
    Pubkey(SigAlg, Digest),
    Ca(Digest),
}

#[derive(Debug)]
struct PreparedEntry {
    lookup: LookupKey,
    hosts: HostPatterns,
}

fn digest(key: &KeyData) -> Digest {
    if let Fingerprint::Sha256(data) = Fingerprint::new(HashAlg::Sha256, key) {
        data
    } else {
        unreachable!()
    }
}

/// Checks the server host key against the [`KnownHosts`] for a given host and port.
///
/// Its [`Handler`] implementation accepts only [`MatchResult::Found`] and
/// rejects all server-initiated channels, including agent and X11 forwarding.
///
/// It matches the host patterns as follows:
///
/// - Plain patterns support `*` and `?`; brackets are literal. A comma-separated list must have
///   at least one matched positive pattern and no matched `!` pattern.
/// - A pattern without a port matches only port `22`. A `[host]:port` pattern matches the host
///   and the decimal port separately, allowing `*` and `?` in both. It can also match port `22`.
/// - A `|1|` hashed host name is checked with HMAC-SHA1 against `host` for port `22`, or
///   `[host]:port` for any other port. A hash of `[host]:22` does not match port `22`.
///
/// Only the requested host is converted to [ASCII lowercase](str::to_ascii_lowercase()); the
/// patterns are unchanged, and comparisons are case-sensitive. Wildcard matching uses a
/// [glob pattern](glob::Pattern) with `case_sensitive = true`, `require_literal_separator = false`,
/// and `require_literal_leading_dot = false`. Patterns that cannot be parsed do not match.
/// See also [`KnownHostsHandler::new()`].
///
/// # Usage
///
/// ```
/// # async fn dummy() {
/// use openrussh_client::known_hosts::KnownHosts;
///
/// let known_hosts = KnownHosts::parse_default_path().unwrap();
/// let handler = known_hosts.handler("test.com", 22);
/// let handle = russh::client::connect(Default::default(), ("test.com", 22), handler).await.unwrap();
/// # }
/// ```
pub struct KnownHostsHandler {
    trusted: Option<Arc<[PreparedEntry]>>,
    revoked: Option<Arc<[PreparedEntry]>>,
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SigAlg {
    Ed25519,
    EcdsaSha2NistP521,
    EcdsaSha2NistP384,
    EcdsaSha2NistP256,
    #[cfg(feature = "rsa")]
    RsaSha512,
    #[cfg(feature = "rsa")]
    RsaSha256,
    Other,
}

impl SigAlg {
    const fn mask(self) -> u8 {
        let shift = self as u8;
        debug_assert!(shift < 8, "SigAlg has too many variants");
        1 << shift
    }

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
            #[cfg(feature = "rsa")]
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            } => Self::RsaSha512,
            #[cfg(feature = "rsa")]
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
            #[cfg(feature = "rsa")]
            Self::RsaSha512 => Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            #[cfg(feature = "rsa")]
            Self::RsaSha256 => Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Self::Other => unreachable!(),
        }
    }
}

impl KnownHostsHandler {
    /// Creates a [`KnownHostsHandler`] for the requested host and port.
    ///
    /// It removes leading `[` characters, any suffix starting at the first `]:`, and trailing
    /// `]` characters from `host`, then converts it to [ASCII lowercase](str::to_ascii_lowercase()).
    /// The port number is always given by `port`, even if `host` contains a port suffix.
    /// It is allocation-free except for `host.to_ascii_lowercase()`; the parsed entries are shared
    /// via [`Arc`].
    ///
    /// ```
    /// # async fn dummy() {
    /// use openrussh_client::known_hosts::KnownHosts;
    ///
    /// let known_hosts = KnownHosts::parse_default_path().unwrap();
    /// let handler = known_hosts.handler("test.com", 22);
    /// let handle = russh::client::connect(Default::default(), ("test.com", 22), handler).await.unwrap();
    /// # }
    /// ```
    pub fn new(known_hosts: &KnownHosts, host: &str, port: u16) -> Self {
        let host = host.trim_start_matches('[');
        let host = host
            .find("]:")
            .map(|idx| &host[..idx])
            .unwrap_or(host)
            .trim_end_matches(']')
            .to_ascii_lowercase();

        Self {
            trusted: known_hosts.trusted.clone(),
            revoked: known_hosts.revoked.clone(),
            host,
            port,
        }
    }

    fn host_matched(&self, hosts: &HostPatterns) -> bool {
        use core::fmt::NumBuffer;

        let mut buf = (self.port != 22).then(NumBuffer::new);
        let port_str = buf.as_mut().map(|buf| self.port.format_into(buf));

        host_matched_known_hosts(&self.host, port_str, hosts)
    }

    fn contains_entry(&self, entries: &[PreparedEntry], lookup: LookupKey) -> bool {
        let start = entries.partition_point(|entry| entry.lookup < lookup);

        entries[start..]
            .iter()
            .take_while(|entry| entry.lookup == lookup)
            .any(|entry| self.host_matched(&entry.hosts))
    }

    fn is_trusted(&self, lookup: LookupKey) -> bool {
        self.trusted
            .as_ref()
            .is_some_and(|entries| self.contains_entry(entries, lookup))
    }

    fn is_revoked(&self, lookup: LookupKey) -> bool {
        self.revoked
            .as_ref()
            .is_some_and(|entries| self.contains_entry(entries, lookup))
    }

    fn has_pubkeys(&self) -> bool {
        self.trusted.as_ref().is_some_and(|trusted| {
            trusted.iter().any(|entry| {
                matches!(entry.lookup, LookupKey::Pubkey(..)) && self.host_matched(&entry.hosts)
            })
        })
    }

    /// Checks the public key against the entries for the requested host and port.
    ///
    /// Keys are compared by [algorithm](PublicKey::algorithm()) and
    /// [SHA-256 fingerprint](PublicKey::fingerprint()), ignoring their comments.
    /// A matched `@revoked` entry returns [`MatchResult::Revoked`], even if the key is also
    /// trusted. The order of the entries does not affect this result.
    ///
    /// Only the supported, unmarked public keys are trusted. See also [`KnownHosts::new()`].
    /// If no matched public key is found, then it returns [`MatchResult::KeyMismatch`] if another
    /// such key is known for this host, or [`MatchResult::NotFound`] otherwise.
    /// `@cert-authority` entries do not count as public keys for either result.
    ///
    /// ```no_run
    /// use openrussh_client::known_hosts::{KnownHosts, MatchResult};
    /// use russh::keys::PublicKey;
    ///
    /// let known_hosts = "test.com ssh-rsa XXXXXXXXXX";
    /// let known_hosts = KnownHosts::parse(known_hosts);
    ///
    /// let handler = known_hosts.handler("test.com", 22);
    ///
    /// let public_key = PublicKey::from_openssh("XXXXXXXXXX").unwrap();
    /// let matched = handler.check_public_key(&public_key);
    /// assert_eq!(matched, MatchResult::Found);
    /// ```
    pub fn check_public_key(&self, pubkey: &PublicKey) -> MatchResult {
        self.check_public_key_impl(digest(pubkey.key_data()), SigAlg::from(&pubkey.algorithm()))
    }

    fn check_public_key_impl(&self, pubkey: Digest, alg: SigAlg) -> MatchResult {
        let lookup = LookupKey::Pubkey(alg, pubkey);
        if self.is_revoked(lookup) {
            MatchResult::Revoked
        } else if alg != SigAlg::Other && self.is_trusted(lookup) {
            MatchResult::Found
        } else if self.has_pubkeys() {
            MatchResult::KeyMismatch
        } else {
            MatchResult::NotFound
        }
    }

    /// Checks the host certificate against the entries for the requested host and port.
    ///
    /// It checks the certificate type, critical options, and principals in this order:
    ///
    /// - If the certificate type is not `host`, it returns [`MatchResult::CertNotVerified`].
    /// - If any critical options are present, it returns [`MatchResult::UnknownCriticalOptions`].
    /// - If none of the principals match, it returns [`MatchResult::PrincipalMismatch`].
    ///
    /// An empty principals list accepts any host name. Otherwise each principal is matched with
    /// `*` and `?` against the normalized host name, without a port, using the same glob options
    /// as [`KnownHostsHandler`]. Principals are case-sensitive, with literal brackets and no
    /// special meaning for a leading `!`.
    ///
    /// After those checks, it checks the [signing key](Certificate::signature_key()) and certified
    /// public key for revocation. Both checks use the requested host and port. A matched
    /// `@revoked` entry returns [`MatchResult::Revoked`].
    ///
    /// It looks up the signing key's SHA-256 fingerprint in the `@cert-authority` entries for
    /// this host and port, then [`validate()`](Certificate::validate())s the certificate, checking
    /// its signature and validity period against the system clock. Any validation error, including
    /// an expired or not-yet-valid certificate or a clock error, falls back to checking the
    /// certified public key as a regular public key. If no CA is found, then it returns
    /// [`MatchResult::CertNotVerified`] without this fallback. Certificate extensions are ignored.
    ///
    /// ```no_run
    /// use openrussh_client::known_hosts::{KnownHosts, MatchResult};
    /// use russh::keys::Certificate;
    ///
    /// let known_hosts = "test.com ssh-rsa XXXXXXXXXX";
    /// let known_hosts = KnownHosts::parse(known_hosts);
    ///
    /// let handler = known_hosts.handler("test.com", 22);
    ///
    /// let certificate = Certificate::from_openssh("XXXXXXXXXX").unwrap();
    /// let matched = handler.check_cert(&certificate);
    /// assert_eq!(matched, MatchResult::Found);
    /// ```
    pub fn check_cert(&self, cert: &Certificate) -> MatchResult {
        if !cert.cert_type().is_host() {
            return MatchResult::CertNotVerified;
        }

        if !cert.critical_options().is_empty() {
            return MatchResult::UnknownCriticalOptions;
        }

        if !host_matched_principals(&self.host, cert.valid_principals()) {
            return MatchResult::PrincipalMismatch;
        }

        let signature_key = cert.signature_key();
        let public_key = cert.public_key();

        let sig_digest = digest(signature_key);
        let pub_alg = SigAlg::from(&public_key.algorithm());
        let pub_digest = digest(public_key);

        if self.is_revoked(LookupKey::Pubkey(
            SigAlg::from(&signature_key.algorithm()),
            sig_digest,
        )) || self.is_revoked(LookupKey::Pubkey(pub_alg, pub_digest))
        {
            return MatchResult::Revoked;
        }

        let trusted = self.is_trusted(LookupKey::Ca(sig_digest));

        if trusted {
            let ca = Fingerprint::Sha256(sig_digest);
            if trusted && cert.validate([&ca]).is_ok() {
                MatchResult::Found
            } else {
                self.check_public_key_impl(pub_digest, SigAlg::from(&cert.algorithm()))
            }
        } else {
            MatchResult::CertNotVerified
        }
    }

    /// Checks the server host key, calling either [`Self::check_public_key()`]
    /// or [`Self::check_cert()`]
    ///
    /// The `hash_alg` field of [`PublicKeyOrCertificate::PublicKey`] does not affect the lookup.
    ///
    /// ```no_run
    /// use openrussh_client::known_hosts::{KnownHosts, MatchResult};
    /// use russh::keys::{PublicKey, PublicKeyOrCertificate};
    ///
    /// let known_hosts = "test.com ssh-rsa XXXXXXXXXX";
    /// let known_hosts = KnownHosts::parse(known_hosts);
    ///
    /// let handler = known_hosts.handler("test.com", 22);
    ///
    /// let public_key = PublicKey::from_openssh("XXXXXXXXXX").unwrap();
    /// let server_key = PublicKeyOrCertificate::PublicKey {
    ///     key: public_key,
    ///     hash_alg: None,
    /// };
    /// let matched = handler.check_server_key(&server_key);
    /// assert_eq!(matched, MatchResult::Found);
    /// ```
    pub fn check_server_key(&self, server_key: &PublicKeyOrCertificate) -> MatchResult {
        match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => self.check_public_key(key),
            PublicKeyOrCertificate::Certificate(cert) => self.check_cert(cert),
        }
    }

    /// Puts the known public key algorithms first and sets the preferred certificate algorithms.
    ///
    /// It replaces `config.key` with
    /// [`Self::preferred_public_key_alg()`] if any public key is known
    /// for this host. Otherwise `key` is unchanged. It always replaces the
    /// `config.host_key_certificates` with
    /// [`Self::preferred_cert_alg()`].
    pub fn update_preferred_config(&self, config: &mut Preferred) {
        use std::borrow::Cow;

        let pubkeys = self.preferred_public_key_alg(config);
        if pubkeys.is_some() {
            config.key = Cow::Owned(pubkeys.collect());
        }

        config.host_key_certificates = Cow::Borrowed(Self::preferred_cert_alg());
    }

    /// Iterates over the known public key algorithms, followed by the remaining algorithms in
    /// `config.key`.
    ///
    /// The known algorithms come first even if they are absent from `config.key`, in this order:
    /// `ssh-ed25519`, `ecdsa-sha2-nistp521`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp256`, and
    /// `rsa-sha2-256` (when the `rsa` feature is enabled). Each known algorithm occurs only once;
    /// the remaining algorithms keep their order and duplicates from `config.key`.
    ///
    /// An RSA key read from `known_hosts` has no hash algorithm, so it is treated as
    /// `rsa-sha2-256`. An explicit `rsa-sha2-512` in `config.key` remains in the trailing part.
    /// When filtering `config.key`, the other RSA algorithms belong to the same group as
    /// `rsa-sha2-256`.
    /// Only unmarked entries determine the known algorithms; `@cert-authority` and `@revoked`
    /// entries do not change this preference.
    ///
    /// If no public key is known for the requested host and port, then the iterator is empty.
    ///
    /// ```no_run
    /// use openrussh_client::known_hosts::KnownHosts;
    /// use russh::keys::ssh_key::{Algorithm, EcdsaCurve};
    /// use russh::Preferred;
    ///
    /// use std::borrow::Cow;
    ///
    /// let known_hosts = "test.com ssh-ed25519 XXXXXXXXXX\ntest.com ecdsa-sha2-nistp521 YYYYYYYYYY";
    /// let known_hosts = KnownHosts::parse(known_hosts);
    ///
    /// let handler = known_hosts.handler("test.com", 22);
    ///
    /// let config = Preferred {
    ///     key: Cow::Owned(vec![Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }]),
    ///     ..Default::default()
    /// };
    /// let algorithms = handler.preferred_public_key_alg(&config)
    ///     .map(|algorithm| algorithm.to_string())
    ///     .collect::<Vec<String>>();
    /// assert_eq!(algorithms, vec!["ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp256"]);
    /// ```
    pub fn preferred_public_key_alg<'k, 'c>(
        &'k self,
        config: &'c Preferred,
    ) -> PreferredPublicKeyAlgIter<'k, 'c> {
        let known = self.known_public_key_algs();

        PreferredPublicKeyAlgIter {
            known_mask: known,
            known_it: TrustedIter::from(&self.trusted),
            prev: SigAlg::Other,
            preferred: config.key.iter(),
        }
    }

    fn known_public_key_algs(&self) -> u8 {
        let mut known = 0;

        // Match only until each algorithm is found for this host.
        for entry in TrustedIter::from(&self.trusted) {
            let LookupKey::Pubkey(alg, _) = entry.lookup else {
                break;
            };

            if known & alg.mask() == 0 && self.host_matched(&entry.hosts) {
                known |= alg.mask();
            }
        }

        known
    }

    /// Alias to [`KnownHosts::preferred_cert_alg()`].
    pub const fn preferred_cert_alg() -> &'static [Algorithm] {
        KnownHosts::preferred_cert_alg()
    }
}

struct TrustedIter<'k> {
    inner: Option<std::slice::Iter<'k, PreparedEntry>>,
}

impl<'k> TrustedIter<'k> {
    fn from(trusted: &'k Option<Arc<[PreparedEntry]>>) -> Self {
        Self {
            inner: trusted.as_ref().map(|entries| entries.iter()),
        }
    }
}

impl<'k> Iterator for TrustedIter<'k> {
    type Item = &'k PreparedEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let inner = self.inner.as_mut()?;
        inner.next()
    }
}
impl FusedIterator for TrustedIter<'_> {}

/// The [`Iterator`] of public key algorithms, returned by
/// [`KnownHostsHandler::preferred_public_key_alg()`].
pub struct PreferredPublicKeyAlgIter<'k, 'c> {
    known_mask: u8,
    known_it: TrustedIter<'k>,
    prev: SigAlg,
    preferred: std::slice::Iter<'c, Algorithm>,
}

impl PreferredPublicKeyAlgIter<'_, '_> {
    /// Returns `true` if any public key algorithm is known for the requested host and port.
    /// It stays `true` even after the iterator is exhausted.
    pub fn is_some(&self) -> bool {
        self.known_mask != 0
    }

    /// Returns `true` if no public key algorithm is known for the requested host and port.
    pub fn is_none(&self) -> bool {
        self.known_mask == 0
    }
}

impl Iterator for PreferredPublicKeyAlgIter<'_, '_> {
    type Item = Algorithm;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_none() {
            return None;
        }

        for entry in &mut self.known_it {
            let LookupKey::Pubkey(alg, _) = entry.lookup else {
                break;
            };

            if self.known_mask & alg.mask() == 0 || alg == self.prev {
                continue;
            }
            self.prev = alg;
            return Some(alg.to_alg());
        }

        for alg in &mut self.preferred {
            let alg_key = SigAlg::from(alg);
            if self.known_mask & alg_key.mask() == 0 {
                return Some(alg.clone());
            }
        }

        None
    }
}
impl FusedIterator for PreferredPublicKeyAlgIter<'_, '_> {}

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

/// Represents the trusted and revoked keys in an OpenSSH `known_hosts`.
///
/// It implements [`MakeHandler`] to create a [`KnownHostsHandler`] for each server.
/// Each context starts with the default client [`Config`](russh::client::Config), then
/// [`KnownHostsHandler::update_preferred_config()`] sets the preferred
/// algorithms. The parsed entries are shared between the handlers via [`Arc`].
///
/// # Usage
///
/// ```
/// # async fn dummy() {
/// use openrussh_client::known_hosts::KnownHosts;
///
/// let known_hosts = KnownHosts::parse_default_path().unwrap();
/// let handler = known_hosts.handler("test.com", 22);
/// let handle = russh::client::connect(Default::default(), ("test.com", 22), handler).await.unwrap();
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct KnownHosts {
    trusted: Option<Arc<[PreparedEntry]>>,
    revoked: Option<Arc<[PreparedEntry]>>,
}

/// Result of checking a public key or certificate against the [`KnownHosts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatchResult {
    /// The public key is trusted, or the certificate is verified by a trusted CA.
    Found,
    /// No trusted public key is found for the requested host and port.
    NotFound,
    /// Another public key is known for the requested host and port, but not the given key.
    KeyMismatch,
    /// The public key, certified public key, or certificate signing key is revoked
    /// for the requested host.
    Revoked,
    /// The certificate does not match the requested host.
    PrincipalMismatch,
    /// Failed to recognize the critical options in the certificate.
    ///
    /// For now, there are no known critical options for host certificates.
    UnknownCriticalOptions,
    /// The certificate could not be verified.
    ///
    /// There are two possible reasons:
    ///
    /// - The certificate type is not [host](russh::keys::ssh_key::certificate::CertType::Host).
    /// - No CAs matched the requested host.
    ///
    /// If a CA is found but the validation fails, then [`KnownHostsHandler::check_cert()`]
    /// returns the result of checking the certified public key instead.
    CertNotVerified,
}

impl MatchResult {
    pub fn is_found(self) -> bool {
        self == Self::Found
    }
}

impl KnownHosts {
    /// Parses the OpenSSH `known_hosts` entries from [`ssh_key::KnownHosts`].
    ///
    /// Invalid entries are ignored. Unmarked entries support `ssh-ed25519`,
    /// `ecdsa-sha2-nistp521`, `ecdsa-sha2-nistp384`, and `ecdsa-sha2-nistp256`, plus RSA with the
    /// crate's `rsa` feature. Other unmarked public keys are ignored. `@cert-authority` and
    /// `@revoked` entries are retained regardless of the public key algorithm.
    /// Enabling `russh/rsa` alone does not enable this crate's RSA support.
    ///
    /// It retains the host patterns and hashed host names as parsed, without converting them to
    /// [ASCII lowercase](str::to_ascii_lowercase()). See [`KnownHostsHandler`] for their matching
    /// behavior.
    ///
    /// ```no_run
    /// use openrussh_client::known_hosts::{KnownHosts, MatchResult};
    /// use russh::keys::{PublicKey, ssh_key};
    ///
    /// let key = "ssh-ed25519 XXXXXXXXXX";
    /// let known_hosts = format!("my-host {key}");
    /// let known_hosts = KnownHosts::new(ssh_key::KnownHosts::new(&known_hosts));
    /// let public_key = PublicKey::from_openssh(key).unwrap();
    ///
    /// let handler = known_hosts.handler("my-host", 22);
    /// assert_eq!(handler.check_public_key(&public_key), MatchResult::Found);
    ///
    /// let handler = known_hosts.handler("my-host", 2222);
    /// assert_eq!(handler.check_public_key(&public_key), MatchResult::NotFound);
    ///
    /// let handler = known_hosts.handler("other-host", 22);
    /// assert_eq!(handler.check_public_key(&public_key), MatchResult::NotFound);
    /// ```
    pub fn new(known_hosts: ssh_key::KnownHosts) -> Self {
        use ssh_key::known_hosts::Entry;

        fn revoked_lookup(entry: &Entry) -> LookupKey {
            let pubkey = entry.public_key();
            LookupKey::Pubkey(SigAlg::from(&pubkey.algorithm()), digest(pubkey.key_data()))
        }
        fn cert_authority_lookup(entry: &Entry) -> LookupKey {
            LookupKey::Ca(digest(entry.public_key().key_data()))
        }
        fn pubkey_lookup(entry: &Entry) -> Option<LookupKey> {
            let pubkey = entry.public_key();
            let alg = SigAlg::from(&pubkey.algorithm());

            (alg != SigAlg::Other).then(|| LookupKey::Pubkey(alg, digest(pubkey.key_data())))
        }

        use ssh_key::known_hosts::Marker;

        let known_hosts = known_hosts.into_iter().filter_map(|entry| entry.ok());

        let mut revoked: Option<Vec<PreparedEntry>> = None;
        let mut trusted: Option<Vec<PreparedEntry>> = None;

        for entry in known_hosts {
            match entry.marker() {
                Some(&Marker::Revoked) => {
                    revoked.get_or_insert_default().push(PreparedEntry {
                        lookup: revoked_lookup(&entry),
                        hosts: entry.into(),
                    });
                }
                Some(&Marker::CertAuthority) => {
                    trusted.get_or_insert_default().push(PreparedEntry {
                        lookup: cert_authority_lookup(&entry),
                        hosts: entry.into(),
                    });
                }
                None => {
                    if let Some(lookup) = pubkey_lookup(&entry) {
                        trusted.get_or_insert_default().push(PreparedEntry {
                            lookup,
                            hosts: entry.into(),
                        });
                    }
                }
            }
        }

        if let Some(entries) = &mut trusted {
            entries.sort_unstable_by_key(|entry| entry.lookup);
        }
        if let Some(entries) = &mut revoked {
            entries.sort_unstable_by_key(|entry| entry.lookup);
        }

        Self {
            trusted: trusted.map(Into::into),
            revoked: revoked.map(Into::into),
        }
    }

    /// Parses the OpenSSH `known_hosts` entries. Equivalent to
    /// [`Self::new(ssh_key::KnownHosts::new(known_hosts))`](Self::new()).
    pub fn parse(known_hosts: &str) -> Self {
        Self::new(ssh_key::KnownHosts::new(known_hosts))
    }

    /// Parses the OpenSSH `known_hosts` entries. Equivalent to
    /// [`Self::parse(std::fs::read_to_string(known_hosts))`](Self::parse()).
    pub fn parse_path(known_hosts: impl AsRef<Path>) -> Result<Self, IoError> {
        let known_hosts = std::fs::read_to_string(known_hosts)?;
        Ok(Self::parse(&known_hosts))
    }

    /// Parses the OpenSSH `known_hosts` entries. Equivalent to
    /// [`Self::parse_path(DEFAULT_PATH)`](Self::parse_path()).
    /// `DEFAULT_PATH` points to `~/.ssh/known_hosts` (if `std::env::home_dir()` returns `Some`)
    /// or `/etc/ssh/ssh_known_hosts` otherwise.
    pub fn parse_default_path() -> Result<Self, IoError> {
        let known_hosts = if let Some(mut home) = std::env::home_dir() {
            home.push(".ssh/known_hosts");
            home
        } else {
            "/etc/ssh/ssh_known_hosts".into()
        };

        Self::parse_path(known_hosts)
    }

    /// Alias to [`KnownHostsHandler::new()`].
    pub fn handler(&self, host: &str, port: u16) -> KnownHostsHandler {
        KnownHostsHandler::new(self, host, port)
    }

    /// Returns the preferred algorithms for host certificates.
    ///
    /// It returns `ssh-ed25519`, `ecdsa-sha2-nistp521`, `ecdsa-sha2-nistp384`, and
    /// `ecdsa-sha2-nistp256`, in this order, followed by `rsa-sha2-512` and `rsa-sha2-256` when
    /// the `rsa` feature is enbaled. This preference is independent of the parsed entries and
    /// requested host.
    pub const fn preferred_cert_alg() -> &'static [Algorithm] {
        const PREFERRED: &[Algorithm] = &[
            SigAlg::Ed25519.to_alg(),
            SigAlg::EcdsaSha2NistP521.to_alg(),
            SigAlg::EcdsaSha2NistP384.to_alg(),
            SigAlg::EcdsaSha2NistP256.to_alg(),
            #[cfg(feature = "rsa")]
            SigAlg::RsaSha512.to_alg(),
            #[cfg(feature = "rsa")]
            SigAlg::RsaSha256.to_alg(),
        ];
        PREFERRED
    }
}

impl MakeHandler for KnownHosts {
    type Handler = KnownHostsHandler;
    type Error = std::convert::Infallible;

    fn make_handler(
        &self,
        host: &crate::config::Host,
    ) -> Result<Context<Self::Handler>, Self::Error> {
        use russh::client::Config;

        let handler = self.handler(&host.dest.name, host.dest.port);
        let mut conf = Config::default();
        handler.update_preferred_config(&mut conf.preferred);
        Ok(Context::new(handler, Arc::new(conf)))
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

#[cfg(test)]
mod tests {
    use super::*;

    use russh::keys::PublicKey;

    fn rand_public_key() -> PublicKey {
        use russh::keys::PrivateKey;

        let mut rng = rand::rng();
        let private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        private_key.public_key().clone()
    }

    fn make_known_hosts<'a>(target: impl IntoIterator<Item = &'a str>) -> KnownHosts {
        const HOST_PLAIN_DUMMY1: &str = "dummy.net";
        const HOST_HASHED_DUMMY1: &str =
            "|1|uPR1jzXUEW7aHtrrnbQh7FXMOjM=|uXYQEMFUGMJmvEMOBpNp1P5EA0g=";

        const HOST_PLAIN_DUMMY2: &str = "[dummy.net]:2222";
        const HOST_HASHED_DUMMY2: &str =
            "|1|cO/9F5qqT8/PcGa65MNc78PzbQw=|08inzOilVfBMnqEhzhVt0YPvioM=";

        let mut s = String::new();

        fn push_dummy(s: &mut String, dummy: &str) {
            let public_key = rand_public_key();
            let public_key = public_key.to_openssh().unwrap();

            s.push_str(dummy.trim());
            s.push(' ');
            s.push_str(public_key.trim());
            s.push('\n');
        }

        for _ in 0..5 {
            push_dummy(&mut s, HOST_PLAIN_DUMMY1);
            push_dummy(&mut s, HOST_HASHED_DUMMY1);
            push_dummy(&mut s, HOST_PLAIN_DUMMY2);
            push_dummy(&mut s, HOST_HASHED_DUMMY2);
        }

        for entry in target {
            s.push_str(entry.trim());
            s.push('\n');
        }

        for _ in 0..5 {
            push_dummy(&mut s, HOST_PLAIN_DUMMY1);
            push_dummy(&mut s, HOST_HASHED_DUMMY1);
            push_dummy(&mut s, HOST_PLAIN_DUMMY2);
            push_dummy(&mut s, HOST_HASHED_DUMMY2);
        }

        KnownHosts::parse(&s)
    }

    #[test]
    fn revoked_public_key() {
        let public_key = rand_public_key();
        let key = public_key.to_openssh().unwrap();
        let other_key = rand_public_key().to_openssh().unwrap();
        let trusted = format!("test.com {key}");

        for (host, revoked_key, expected) in [
            ("test.com", &key, MatchResult::Revoked),
            ("other.test.com", &key, MatchResult::Found),
            ("[test.com]:2222", &key, MatchResult::Found),
            ("test.com", &other_key, MatchResult::Found),
        ] {
            let revoked = format!("@revoked {host} {revoked_key}");

            let entries = [trusted.as_str(), revoked.as_str()];
            let known_hosts = make_known_hosts(entries);
            let handler = known_hosts.clone().handler("test.com", 22);
            assert_eq!(
                handler.check_public_key(&public_key),
                expected,
                "unexpected result for entries {entries:?}",
            );
            assert_eq!(
                handler.check_public_key(&public_key).is_found(),
                expected == MatchResult::Found,
            );

            let entries = [revoked.as_str(), trusted.as_str()];
            let known_hosts = make_known_hosts(entries);
            let handler = known_hosts.clone().handler("test.com", 22);
            assert_eq!(
                handler.check_public_key(&public_key),
                expected,
                "unexpected result for entries {entries:?}",
            );
            assert_eq!(
                handler
                    .check_server_key(&PublicKeyOrCertificate::PublicKey {
                        key: public_key.clone(),
                        hash_alg: None,
                    })
                    .is_found(),
                expected == MatchResult::Found,
            );
        }

        let known_hosts = KnownHosts::parse(&format!("@revoked test.com {key}"));
        assert_eq!(
            known_hosts
                .handler("test.com", 22)
                .check_public_key(&public_key),
            MatchResult::Revoked,
        );
        assert!(
            known_hosts
                .handler("test.com", 22)
                .preferred_public_key_alg(&Preferred::default())
                .is_none()
        );
        assert!(KnownHosts::parse(&trusted).revoked.is_none());
    }

    #[test]
    fn public_key() {
        const HOST_PLAIN_GLOB_22: &str = "*.test.com";
        const HOST_PLAIN_GLOB_2222: &str = "[*.test.com]:2222";

        const HOST_PLAIN_22: &str = "test.com";
        const HOST_HASHED_22: &str = "|1|IkYYsmkv/vlfNnRRVq0PKKfzOZ4=|Y4L+Ts7EGb5KWLd28MOl7bBUkoA=";

        const HOST_PLAIN_2222: &str = "[test.com]:2222";
        const HOST_HASHED_2222: &str =
            "|1|SwCSMfyuiggtBQws61eVrGHyk7Q=|haRngUZFFxGaXgudTJXhQFF26l0=";

        fn assert_impl<'a>(
            targets: impl IntoIterator<Item = (&'a str, &'a PublicKey)>,
            host: &str,
            port: u16,
            public_key: &PublicKey,
            expect_found: bool,
        ) {
            let targets = targets
                .into_iter()
                .map(|(pat, key)| {
                    let key = key.to_openssh().unwrap();
                    format!("{pat} {key}")
                })
                .collect::<Vec<_>>();
            let known_hosts = make_known_hosts(targets.as_slice().iter().map(|s| s.as_str()));
            let handler = known_hosts.handler(host, port);

            if expect_found {
                assert!(
                    handler.check_public_key(public_key).is_found(),
                    "expected to find the entry for {host}:{port}, but not found",
                );
            } else {
                let res = handler.check_public_key(public_key);
                assert!(
                    res == MatchResult::NotFound || res == MatchResult::KeyMismatch,
                    "expected not to find the entry for {host}:{port}, but found",
                );
            }
        }

        let public_key = rand_public_key();
        let public_key_old = rand_public_key();

        assert_impl(
            [(HOST_PLAIN_22, &public_key)],
            "test.com",
            22,
            &public_key,
            true,
        );
        assert_impl(
            [(HOST_PLAIN_2222, &public_key)],
            "test.com",
            22,
            &public_key,
            false,
        );
        assert_impl(
            [(HOST_PLAIN_22, &public_key)],
            "test.com",
            2222,
            &public_key,
            false,
        );
        assert_impl(
            [(HOST_PLAIN_2222, &public_key)],
            "test.com",
            2022,
            &public_key,
            false,
        );
        assert_impl(
            [(HOST_PLAIN_22, &public_key), (HOST_PLAIN_2222, &public_key)],
            "test.com",
            22,
            &public_key,
            true,
        );
        assert_impl(
            [(HOST_PLAIN_22, &public_key), (HOST_PLAIN_2222, &public_key)],
            "test.com",
            2222,
            &public_key,
            true,
        );

        assert_impl(
            [(HOST_HASHED_22, &public_key)],
            "test.com",
            22,
            &public_key,
            true,
        );
        assert_impl(
            [(HOST_HASHED_2222, &public_key)],
            "test.com",
            22,
            &public_key,
            false,
        );
        assert_impl(
            [(HOST_HASHED_22, &public_key)],
            "test.com",
            2222,
            &public_key,
            false,
        );
        assert_impl(
            [(HOST_HASHED_2222, &public_key)],
            "test.com",
            2022,
            &public_key,
            false,
        );
        assert_impl(
            [
                (HOST_HASHED_22, &public_key),
                (HOST_HASHED_2222, &public_key),
            ],
            "test.com",
            22,
            &public_key,
            true,
        );
        assert_impl(
            [
                (HOST_HASHED_22, &public_key),
                (HOST_HASHED_2222, &public_key),
            ],
            "test.com",
            2222,
            &public_key,
            true,
        );

        assert_impl(
            [(HOST_PLAIN_GLOB_22, &public_key)],
            "test.com",
            22,
            &public_key,
            false,
        );
        assert_impl(
            [(HOST_PLAIN_GLOB_22, &public_key)],
            "test.test.com",
            22,
            &public_key,
            true,
        );
        assert_impl(
            [(HOST_PLAIN_GLOB_2222, &public_key)],
            "test.test.com",
            22,
            &public_key,
            false,
        );
        assert_impl(
            [(HOST_PLAIN_GLOB_22, &public_key)],
            "test.test.com",
            2222,
            &public_key,
            false,
        );
        assert_impl(
            [(HOST_PLAIN_GLOB_2222, &public_key)],
            "test.test.com",
            2022,
            &public_key,
            false,
        );

        assert_impl(
            [(HOST_PLAIN_22, &public_key_old)],
            "test.com",
            22,
            &public_key,
            false,
        );
        assert_impl(
            [(HOST_HASHED_22, &public_key_old)],
            "test.com",
            22,
            &public_key,
            false,
        );
        assert_impl(
            [
                (HOST_PLAIN_22, &public_key_old),
                (HOST_PLAIN_22, &public_key),
            ],
            "test.com",
            22,
            &public_key,
            true,
        );
        assert_impl(
            [
                (HOST_PLAIN_22, &public_key),
                (HOST_PLAIN_22, &public_key_old),
            ],
            "test.com",
            22,
            &public_key,
            true,
        );
    }
}
