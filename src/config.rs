//! Represents an OpenSSH config.
//!
//! It leverages the [`ssh2-config`](ssh2_config) crate for parsing and querying the config file,
//! but we need some [`ignored_fields`](ssh2_config::HostParams::ignored_fields) for controling the
//! behavior of authentication methods and PTY.
//! One of the most important implication is that the `ssh2_config` crate itself may add the new
//! fields for those directives, removing them from the `ignored_fields` mapping, hence breaking our
//! code at runtime with the minor version updates.
//!
//! Supported directives:
//!
//! - `CertificateFile`
//! - `Host`
//! - `IdentityAgent` (or `${SSH_AUTH_SOCK}`)
//! - `IdentityFile`
//! - `IdentitiesOnly`
//! - `RequestTTY`
//! - `Port`
//! - `ProxyJump`
//! - `User`
//!
//! # Usage
//!
//! ```
//! # fn dummy() {
//! use openrussh_client::config::Target;
//! use openrussh_client::ssh2_config::{ParseRule, SshConfig};
//!
//! let conf = SshConfig::parse_default_file(ParseRule::ALLOW_UNSUPPORTED_FIELDS).unwrap();
//!
//! let target = Target::parse("my-host");
//! let hosts = target.query(&conf).unwrap();
//! # }
//! ```

use std::iter::Rev;
use std::path::PathBuf;
use std::slice::Windows;

#[cfg(feature = "config-parser")]
use ssh2_config::{HostParams as OpenSshHost, SshConfig as OpenSshConfig};

/// Errors when reading or parsing an OpenSSH config.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Could not get the user name by [`whoami::username()`].
    #[cfg(feature = "config-parser")]
    UserNotFound(whoami::Error),
}

/// Target host of the user input.
///
/// ```no_run
/// use openrussh_client::config::Target;
/// use openrussh_client::ssh2_config::{ParseRule, SshConfig};
///
/// let conf = SshConfig::parse_default_file(ParseRule::ALLOW_UNSUPPORTED_FIELDS).unwrap();
///
/// let target = Target::parse("my-host");
/// let hosts = target.query(&conf).unwrap();
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Target<'a> {
    pub host: &'a str,
    pub port: Option<u16>,
    pub user: Option<&'a str>,
}

impl<'a> Target<'a> {
    /// Parses the user input `[user@]host[:port]`.
    ///
    /// If the port cannot be parsed as a `u16`, then it will be `None`.
    ///
    /// ```
    /// # use openrussh_client::config::Target;
    /// let target = Target::parse("my-host");
    /// assert_eq!(target.host, "my-host");
    /// assert_eq!(target.port, None);
    /// assert_eq!(target.user, None);
    ///
    /// let target = Target::parse("user@my-host:22");
    /// assert_eq!(target.host, "my-host");
    /// assert_eq!(target.port, Some(22));
    /// assert_eq!(target.user, Some("user"));
    ///
    /// let target = Target::parse("my-host:nan");
    /// assert_eq!(target.host, "my-host");
    /// assert_eq!(target.port, None);
    /// assert_eq!(target.user, None);
    /// ```
    pub fn parse(query: &'a str) -> Self {
        let (user, rest) = if let Some((user, rest)) = query.split_once('@') {
            (Some(user), rest)
        } else {
            (None, query)
        };

        let (port, host) = if let Some((host, port)) = rest.rsplit_once(':') {
            (Some(port), host)
        } else {
            (None, rest)
        };

        Self {
            host,
            port: port.and_then(|port| port.parse().ok()),
            user,
        }
    }

    /// Queries and resolves the OpenSSH config.
    ///
    /// It includes:
    ///
    /// - Substituting the default port number `22` if it is `None`.
    /// - Substituting the default user name, [`whoami::username()`], if it is `None`. If
    ///   `username()` returns an error, then you get [`Error::UserNotFound`].
    /// - Reading the authentication preferences: `IdentityFile`, `CertificateFile`,
    ///   `IdentityAgent` (also `${SSH_AUTH_SOCK}`), and `IdentitiesOnly`.
    /// - If the paths of `IdentityFile`, `CertificateFile`, and `IdentityAgent` start with tildes `~/`, then they are resolved into the home directory [`std::env::home_dir()`]. If `home_dir()` returns `None`, then the paths are ignored.
    /// - If the paths start with `~user/` then it first checks your user name,
    ///   [`whoami::username()`], and resolves to the home directory *only if* the user name matches
    ///   with the path component `~user/`. Otherwise they are ignored.
    /// - Resolving the `ProxyJump` chain by recursively querying the OpenSSH config.
    ///   It does not check `ProxyCommand`.
    ///
    /// This method returns an `Err` if any of [`Host::parse_openssh()`] calls return an `Err`.
    ///
    /// ```
    /// use openrussh_client::ssh2_config::{ParseRule, SshConfig};
    /// use openrussh_client::config::Target;
    /// use std::io::BufReader;
    ///
    /// let ssh_config = r#"
    /// Host host1
    /// Host host2
    ///   ProxyJump host1
    /// Host host3
    ///   ProxyJump host2
    /// "#;
    /// let ssh_config = SshConfig::default().parse(&mut BufReader::new(ssh_config.as_bytes()),
    /// ParseRule::ALLOW_UNSUPPORTED_FIELDS).unwrap();
    ///
    /// let target = Target::parse("host1");
    /// let chain = target.query(&ssh_config).unwrap();
    /// assert_eq!(chain.target.dest.name, "host1");
    /// assert!(chain.bastions.is_none());
    ///
    /// let target = Target::parse("host2");
    /// let chain = target.query(&ssh_config).unwrap();
    /// assert_eq!(chain.target.dest.name, "host2");
    /// assert!(chain.bastions.is_some_and(|v| {
    ///     v.len() == 1
    ///         && v[0].dest.name == "host1"
    /// }));
    ///
    /// let target = Target::parse("host3");
    /// let chain = target.query(&ssh_config).unwrap();
    /// assert_eq!(chain.target.dest.name, "host3");
    /// assert!(chain.bastions.is_some_and(|v| {
    ///     v.len() == 2
    ///         && v[0].dest.name == "host2"
    ///         && v[1].dest.name == "host1"
    /// }));
    /// ```
    #[cfg(feature = "config-parser")]
    pub fn query(self, conf: &OpenSshConfig) -> Result<Chain, Error> {
        parsers::parse_config(self, conf)
    }
}

/// Represents a server profile (where to connect), both the final target and bastions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dest {
    /// Corresponds to the `HostName` directive.
    pub name: String,
    /// Corresponds to the `Port` directive.
    pub port: u16,
    /// Corresponds to the `User` directive.
    pub user: String,
}

#[cfg(feature = "config-parser")]
impl Dest {
    /// Parses the OpenSSH parameters. See also [`Target::query()`].
    ///
    /// It returns [`Error::UserNotFound`] if [`whoami::username()`] fails.
    ///
    /// Side effects that mutate `conf`:
    ///
    /// - [Take](Option::take()) the ownership of [`host_name`](OpenSshHost::host_name).
    /// - [Take](Option::take()) the ownership of [`user`](OpenSshHost::user).
    ///
    /// ```
    /// use openrussh_client::config::{Dest, Target};
    /// use ssh2_config::{DefaultAlgorithms, HostParams};
    ///
    /// let target = Target::parse("my-host");
    ///
    /// let mut conf = HostParams::new(&DefaultAlgorithms::empty());
    /// conf.user = Some("me".to_owned());
    /// let dest = Dest::parse_openssh(&mut conf, target).unwrap();
    ///
    /// assert_eq!(dest.name, "my-host");
    /// assert_eq!(dest.port, 22);
    /// assert_eq!(dest.user, "me");
    /// ```
    pub fn parse_openssh(conf: &mut OpenSshHost, target: Target<'_>) -> Result<Self, Error> {
        parsers::parse_dest(conf, target)
    }
}

/// Represents the authentication methods that the client will try.
#[derive(Debug, Clone, PartialEq)]
pub struct Auth {
    /// Corresponds to the `IdentityFile` directive, trying in this order.
    pub identities: Option<Vec<PathBuf>>,
    /// Corresponds to the `CertificateFile` directive.
    pub cert: Option<PathBuf>,
    /// Corresponds to the `IdentityAgent` directive or the environment variable
    /// `${SSH_AUTH_SOCK}`.
    pub agent: Option<PathBuf>,
    /// Corresponds to the `IdentitiesOnly` directive.
    pub identities_only: bool,
    /// Indicates whether we perform the authentication method "none" first or not.
    /// Since OpenSSH config has no directive to control this behavior, it always defaults to `true`.
    /// However, you can substitute it with `false` later.
    pub includes_none: bool,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            identities: None,
            cert: None,
            agent: None,
            identities_only: false,
            includes_none: true,
        }
    }
}

#[cfg(feature = "config-parser")]
impl Auth {
    /// Parses the OpenSSH parameters. See also [`Target::query()`].
    ///
    /// Side effects that mutate `conf`:
    ///
    /// - [Take](Option::take()) the ownership of [`identity_file`](OpenSshHost::identity_file).
    /// - [Take](Option::take()) the ownership of [`certificate_file`](OpenSshHost::certificate_file).
    /// - [Remove](std::collections::HashMap::remove()) the `IdentityAgent` from
    ///   [`unsupported_fields`](OpenSshHost::unsupported_fields).
    ///
    /// ```
    /// use openrussh_client::config::{Auth, Target};
    /// use ssh2_config::{DefaultAlgorithms, HostParams};
    /// use std::path::Path;
    ///
    /// let test_id = Path::new("your/own/id_ed25519");
    ///
    /// let mut conf = HostParams::new(&DefaultAlgorithms::empty());
    /// conf.identity_file = Some(vec![test_id.to_path_buf()]);
    /// let auth = Auth::parse_openssh(&mut conf);
    ///
    /// assert_eq!(auth.identities, Some(vec![test_id.to_path_buf()]));
    /// assert!(auth.cert.is_none());
    /// assert!(!auth.identities_only);
    /// ```
    pub fn parse_openssh(conf: &mut OpenSshHost) -> Self {
        parsers::parse_auth(conf)
    }
}

/// Whether or not you [request PTY](russh::Channel::request_pty()) when you
/// [execute a command](russh::Channel::exec()) or
/// [request a shell](russh::Channel::request_shell()).
///
/// When trying to request PTY, we use [`IsTerminal`](std::io::IsTerminal) for checking
/// if [`stdin`](std::io::stdin()) is a terminal.
///
/// If it is not a terminal, then we fallback to the default dimension and default modes.
/// If it is a terminal, then we use [`terminal_size_of(stdin)`](terminal_size::terminal_size_of())
/// to get the dimension and [`tcgetattr(stdin)`](libc::tcgetattr()) to get the terminal modes.
///
/// The terminal name is obtained via [`std::env::var("TERM")`](std::env::var()).
///
/// # Platform-specific behavior
///
/// We do not call [`tcgetattr(stdin)`](libc::tcgetattr()) on non-Unix targets.
/// Instead, we set nothing (`&[]`) for the terminal modes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RequestTty {
    /// Never requests PTY (`RequestTTY no`).
    Never,
    /// Always requests PTY (`RequestTTY force`).
    Always,
    /// Requests PTY if `stdin` is TTY/PTY (`RequestTTY yes`).
    IfTty,
    /// Requests PTY if you request a shell (`RequestTTY auto`).
    #[default]
    ForShell,
}

#[cfg(feature = "config-parser")]
impl RequestTty {
    fn from_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("no") {
            Self::Never
        } else if s.eq_ignore_ascii_case("yes") {
            Self::IfTty
        } else if s.eq_ignore_ascii_case("force") {
            Self::Always
        } else {
            Self::ForShell
        }
    }

    /// Parses the OpenSSH parameters. See also [`Target::query()`].
    ///
    /// No side effects that mutate `conf`.
    ///
    /// ```
    /// use openrussh_client::config::{RequestTty, Target};
    /// use ssh2_config::{DefaultAlgorithms, HostParams};
    ///
    /// let directive = "RequestTTY";
    ///
    /// let mut conf = HostParams::new(&DefaultAlgorithms::empty());
    /// conf.unsupported_fields.insert(
    ///     directive.to_ascii_lowercase(),
    ///     vec!["yes".to_owned()]
    /// );
    /// let tty = RequestTty::parse_openssh(&conf);
    ///
    /// assert_eq!(tty, RequestTty::IfTty);
    /// ```
    pub fn parse_openssh(conf: &OpenSshHost) -> Self {
        parsers::parse_tty(conf)
    }
}

/// Represents a configuration for a server, both the final target and bastions.
#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    pub dest: Dest,
    pub auth: Auth,
    pub tty: RequestTty,
}

#[cfg(feature = "config-parser")]
impl Host {
    /// Parses the OpenSSH parameters. See also [`Target::query()`].
    ///
    /// See [`Dest::parse_openssh()`], [`Auth::parse_openssh()`], and
    /// [`RequestTty::parse_openssh()`] for the side effects on `conf`.
    ///
    /// ```
    /// use openrussh_client::config::{Host, Target};
    /// use ssh2_config::{DefaultAlgorithms, HostParams};
    /// use std::path::Path;
    ///
    /// let target = Target::parse("my-host");
    ///
    /// let test_id = Path::new("your/own/id_ed25519");
    ///
    /// let mut conf = HostParams::new(&DefaultAlgorithms::empty());
    /// conf.user = Some("me".to_owned());
    /// conf.identity_file = Some(vec![test_id.to_path_buf()]);
    /// let host = Host::parse_openssh(&mut conf, target).unwrap();
    ///
    /// assert_eq!(host.dest.name, "my-host");
    /// assert_eq!(host.dest.port, 22);
    /// assert_eq!(host.dest.user, "me");
    ///
    /// assert_eq!(host.auth.identities, Some(vec![test_id.to_path_buf()]));
    /// ```
    pub fn parse_openssh(conf: &mut OpenSshHost, target: Target<'_>) -> Result<Self, Error> {
        parsers::parse_host(conf, target)
    }
}

/// Bastion chain, from the local server to the target server.
///
/// There are two cases depending on your `ProxyJump` settings:
///
/// 1. Only one `target` and no `bastions`. In this case you just call
///    [`connect()`](russh::client::connect()) for `Chain::target`.
/// 2. One `target` and one or more `bastions`. The `bastions` field are sorted in the *reversed* order, meaning that you have the bastion chain like
///
/// ```text
/// local -> bastions[N-1] -> bastions[N-2] -> ... -> bastions[0] -> target
/// ```
///
/// In the second case, you should call [`connect()`](russh::client::connect()) for `bastions[N-1]`
/// first, and then continuing to calling [`connect_stream()`](russh::client::connect_stream()) for
/// each `bastions[i] -> bastions[i-1]` pair (`i` running from `N-1` to `1`, inclusive), and finally
/// calling `connect_stream()` for the `bastions[0] -> target` pair.
///
/// This is exactly what [`Chain::iter()`] does.
///
/// ```
/// # use tokio::net::ToSocketAddrs;
/// # use russh::client::Config;
/// # use std::sync::Arc;
/// # #[derive(Clone, Copy)]
/// # struct MyHandler;
/// # impl MyHandler {
/// #     fn new() -> Self { Self }
/// # }
/// # struct Channel;
/// # impl Channel {
/// #     fn into_stream(self) {}
/// # }
/// # struct Handle;
/// # impl Handle {
/// #     async fn channel_open_direct_tcpip(&self, dh: &str, dp: u32, sh: &str, sp: u32) ->
/// #     Result<Channel, ()> { Ok(Channel) }
/// # }
/// # async fn connect(config: Arc<Config>, addrs: impl ToSocketAddrs, handler: MyHandler) -> Result<Handle, ()> {
/// #     Ok(Handle)
/// # }
/// # async fn connect_stream(config: Arc<Config>, stream: (), handler: MyHandler) -> Result<Handle, ()> {
/// #     Ok(Handle)
/// # }
/// # async fn dummy() {
/// use openrussh_client::ssh2_config::{ParseRule, SshConfig};
/// use openrussh_client::config::Target;
///
/// use russh::client::Config;
/// use std::io::BufReader;
/// use std::sync::Arc;
///
/// let handler = MyHandler::new();
/// let config = Arc::new(Config::default());
///
/// let ssh_config = r#"
/// Host host1
///   IdentityFile priv1
/// Host host2
///   IdentityFile priv2
///   ProxyJump host1
/// Host host3
///   IdentityFile priv3
///   ProxyJump host2
/// "#;
/// let ssh_config = SshConfig::default().parse(&mut BufReader::new(ssh_config.as_bytes()),
/// ParseRule::ALLOW_UNSUPPORTED_FIELDS).unwrap();
///
/// // Case 1: one `target` only
/// let target = Target::parse("host1");
/// let chain = target.query(&ssh_config).unwrap();
/// assert!(chain.bastions.is_none());
///
/// let (target, bastions) = chain.iter();
/// assert_eq!(target.dest.name, "host1");
/// assert!(bastions.is_none());
///
/// let _handle = connect(config.clone(), (target.dest.name.as_str(), target.dest.port), handler).await.unwrap();
///
/// // Case 2: one `target` and one or more `bastions`
/// let target = Target::parse("host3");
/// let chain = target.query(&ssh_config).unwrap();
/// assert!(chain.bastions.as_ref().is_some_and(|v| !v.is_empty()));
///
/// let (first, bastions) = chain.iter();
/// assert_eq!(first.dest.name, "host1");
/// assert!(bastions.is_some());
///
/// let mut bastions = bastions.unwrap();
///
/// let mut handle = connect(
///     config.clone(),
///     (first.dest.name.as_str(), first.dest.port),
///     handler,
/// ).await.unwrap();
///
/// let bastion0 = bastions.next().unwrap();
/// assert_eq!(bastion0.from.dest.name, "host1");
/// assert_eq!(bastion0.to.dest.name, "host2");
///
/// let channel = handle
///     .channel_open_direct_tcpip(
///         &bastion0.to.dest.name,
///         bastion0.to.dest.port as u32,
///         "127.0.0.1",
///         0,
///     )
///     .await
///     .unwrap();
/// handle = connect_stream(
///     config.clone(),
///     channel.into_stream(),
///     handler
/// )
///     .await
///     .unwrap();
///
/// let bastion1 = bastions.next().unwrap();
/// assert_eq!(bastion1.from.dest.name, "host2");
/// assert_eq!(bastion1.to.dest.name, "host3");
///
/// let channel = handle
///     .channel_open_direct_tcpip(
///         &bastion1.to.dest.name,
///         bastion1.to.dest.port as u32,
///         "127.0.0.1",
///         0,
///     )
///     .await
///     .unwrap();
/// handle = connect_stream(
///     config.clone(),
///     channel.into_stream(),
///     handler
/// )
///     .await
///     .unwrap();
///
/// assert!(bastions.next().is_none());
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Chain {
    /// The final target server.
    pub target: Host,
    /// Intermediate servers, specified by `ProxyJump`s.
    pub bastions: Option<Box<[Host]>>,
}

impl Chain {
    /// Queries and resolves the OpenSSH config. Alias to [`Target::query()`].
    #[cfg(feature = "config-parser")]
    pub fn new(target: Target<'_>, conf: &OpenSshConfig) -> Result<Self, Error> {
        target.query(conf)
    }

    /// Iterates over the bastions.
    ///
    /// The first half of the returned value *is not* the `target` server.
    /// This indicates the first server to which you should call
    /// [`connect()`](russh::client::connect()) from the local SSH client.
    ///
    /// The second returned value is the bastion chain.
    ///
    /// Let us call it `bastion_chain`:
    ///
    /// ```
    /// # use openrussh_client::config::Chain;
    /// # fn dummy(chain: &Chain) {
    /// let (first, bastion_chain) = chain.iter();
    /// # }
    /// ```
    ///
    /// If `bastion_chain` is `Some`, then it is guaranteed that the length of the contained
    /// iterator is longer than zero, and actually equal to `self.bastions.len()`.
    ///
    /// ```
    /// use openrussh_client::ssh2_config::{ParseRule, SshConfig};
    /// use openrussh_client::config::Target;
    /// use std::io::BufReader;
    ///
    /// let ssh_config = r#"
    /// Host host1
    /// Host host2
    ///   ProxyJump host1
    /// Host host3
    ///   ProxyJump host2
    /// "#;
    /// let ssh_config = SshConfig::default().parse(&mut BufReader::new(ssh_config.as_bytes()),
    /// ParseRule::ALLOW_UNSUPPORTED_FIELDS).unwrap();
    ///
    /// let target = Target::parse("host1");
    /// let chain = target.query(&ssh_config).unwrap();
    /// let (_, bastion_chain) = chain.iter();
    /// assert!(bastion_chain.is_none());
    /// assert!(chain.bastions.is_none());
    ///
    /// let target = Target::parse("host2");
    /// let chain = target.query(&ssh_config).unwrap();
    /// let (_, bastion_chain) = chain.iter();
    /// let count = bastion_chain.map(|c| c.count()).unwrap_or_default();
    /// assert_eq!(count, 1);
    /// assert!(chain.bastions.is_some_and(|v| v.len() == count));
    ///
    /// let target = Target::parse("host3");
    /// let chain = target.query(&ssh_config).unwrap();
    /// let (_, bastion_chain) = chain.iter();
    /// let count = bastion_chain.map(|c| c.count()).unwrap_or_default();
    /// assert_eq!(count, 2);
    /// assert!(chain.bastions.is_some_and(|v| v.len() == count));
    /// ```
    ///
    /// Also it is guaranteed that:
    ///
    /// ```
    /// # use openrussh_client::config::Chain;
    /// # use openrussh_client::config::{Host, BastionIter};
    /// # fn dummy(chain: &Chain, first: &Host, bastion_chain: &mut BastionIter<'_>) {
    /// use std::ptr;
    ///
    /// let item_0 = bastion_chain.next().unwrap();
    /// assert!(ptr::eq(item_0.from, first));
    ///
    /// let item_1 = bastion_chain.next().unwrap();
    /// assert!(ptr::eq(item_1.from, item_0.to));
    ///
    /// let item_2 = bastion_chain.next().unwrap();
    /// assert!(ptr::eq(item_2.from, item_1.to));
    ///
    /// // ...
    ///
    ///
    /// # let item_N_prev = bastion_chain.next().unwrap();
    /// let item_N = bastion_chain.next().unwrap();
    /// assert!(ptr::eq(item_N.from, item_N_prev.to));
    /// assert!(ptr::eq(item_N.to, &chain.target));
    ///
    /// assert!(bastion_chain.next().is_none());
    /// # }
    /// # use openrussh_client::ssh2_config::{ParseRule, SshConfig};
    /// # use openrussh_client::config::Target;
    /// # use std::io::BufReader;
    /// # use std::ptr;
    /// # let ssh_config = r#"
    /// # Host host1
    /// # Host host2
    /// #   ProxyJump host1
    /// # Host host3
    /// #   ProxyJump host2
    /// # Host host4
    /// #   ProxyJump host3
    /// # "#;
    /// # let ssh_config = SshConfig::default().parse(&mut BufReader::new(ssh_config.as_bytes()),
    /// # ParseRule::ALLOW_UNSUPPORTED_FIELDS).unwrap();
    /// # let target = Target::parse("host4");
    /// # let chain = target.query(&ssh_config).unwrap();
    /// # let (first, bastion_chain) = chain.iter();
    /// # let mut bastion_chain = bastion_chain.unwrap();
    /// # let item_0 = bastion_chain.next().unwrap();
    /// # assert!(ptr::eq(item_0.from, first));
    /// # let item_1 = bastion_chain.next().unwrap();
    /// # assert!(ptr::eq(item_1.from, item_0.to));
    /// # let item_2 = bastion_chain.next().unwrap();
    /// # assert!(ptr::eq(item_2.from, item_1.to));
    /// # assert!(ptr::eq(item_2.to, &chain.target));
    /// # assert!(bastion_chain.next().is_none());
    /// ```
    pub fn iter(&self) -> (&Host, Option<BastionIter<'_>>) {
        if let Some(bastions) = &self.bastions
            && let Some(first) = bastions.last()
        {
            let it = BastionIter {
                final_target: Some(BastionItem {
                    from: &bastions[0],
                    to: &self.target,
                }),
                bastions: bastions.windows(2).rev(),
            };
            (first, Some(it))
        } else {
            (&self.target, None)
        }
    }
}

/// Iterator of a `ProxyJump` chain.
///
/// Read [`Chain::iter()`] for more information.
#[derive(Debug, Clone)]
pub struct BastionIter<'a> {
    final_target: Option<BastionItem<'a>>,
    bastions: Rev<Windows<'a, Host>>,
}

/// Returned item of [`BastionIter`].
#[derive(Debug, Clone, Copy)]
pub struct BastionItem<'a> {
    pub from: &'a Host,
    pub to: &'a Host,
}

impl<'a> Iterator for BastionIter<'a> {
    type Item = BastionItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(next) = self.bastions.next() {
            Some(BastionItem {
                from: &next[1],
                to: &next[0],
            })
        } else {
            self.final_target.take()
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}
impl std::iter::FusedIterator for BastionIter<'_> {}

impl ExactSizeIterator for BastionIter<'_> {
    fn len(&self) -> usize {
        if self.final_target.is_none() {
            0
        } else {
            self.bastions.len() + 1
        }
    }
}

#[cfg(feature = "config-parser")]
mod parsers {
    use super::{Auth, Chain, Dest, Host, RequestTty, Target};
    use super::{Error, OpenSshConfig, OpenSshHost};

    use std::path::PathBuf;

    pub(super) const AGENT_ENV: &str = "SSH_AUTH_SOCK";

    pub(super) fn parse_config(target: Target<'_>, conf: &OpenSshConfig) -> Result<Chain, Error> {
        let mut target_params = conf.query(target.host);
        let target_host = parse_host(&mut target_params, target)?;

        let mut proxy_jump = target_params.proxy_jump.take();

        let mut bastions: Option<Vec<Host>> = None;

        loop {
            if let Some(inner) = proxy_jump
                && let Some((first_bastion, rest)) = inner.split_first()
            {
                let bastions = if let Some(bastions) = bastions.as_mut() {
                    bastions.reserve(rest.len() + 1);
                    bastions
                } else {
                    bastions.insert(Vec::with_capacity(rest.len() + 1))
                };

                for bastion in rest.iter().rev() {
                    let target = Target::parse(bastion);
                    let mut params = conf.query(target.host);
                    let host = parse_host(&mut params, target)?;
                    bastions.push(host);
                }

                let target = Target::parse(first_bastion);
                let mut params = conf.query(target.host);
                let host = parse_host(&mut params, target)?;
                bastions.push(host);

                proxy_jump = params.proxy_jump.take();
            } else {
                return Ok(Chain {
                    target: target_host,
                    bastions: bastions.map(|bastions| bastions.into_boxed_slice()),
                });
            }
        }
    }

    pub(super) fn parse_host(params: &mut OpenSshHost, target: Target<'_>) -> Result<Host, Error> {
        let dest = parse_dest(params, target)?;
        let auth = parse_auth(params);

        let tty = parse_tty(params);

        Ok(Host { dest, auth, tty })
    }

    pub(super) fn parse_dest(conf: &mut OpenSshHost, target: Target<'_>) -> Result<Dest, Error> {
        let name = conf
            .host_name
            .take()
            .unwrap_or_else(|| target.host.to_owned());
        let port = conf.port.unwrap_or_else(|| target.port.unwrap_or(22));
        let user = if let Some(user) = conf.user.take() {
            user
        } else if let Some(user) = target.user {
            user.to_owned()
        } else {
            whoami::username().map_err(Error::UserNotFound)?
        };

        Ok(Dest { name, port, user })
    }

    pub(super) fn parse_auth(conf: &mut OpenSshHost) -> Auth {
        fn expand_tilde(path: PathBuf) -> Option<PathBuf> {
            use std::path::Component;

            let mut it = path.components();
            match it.next() {
                Some(Component::Normal(first)) => {
                    if first != "~" {
                        let bytes = first.as_encoded_bytes();
                        let user = match bytes.first().copied() {
                            Some(b'~') => first.to_str().and_then(|s| s.strip_prefix('~')),
                            Some(_) => return Some(path),
                            None => return None,
                        };
                        if user.is_none_or(|user| {
                            if let Ok(me) = whoami::username() {
                                user != me
                            } else {
                                true
                            }
                        }) {
                            return None;
                        }
                    }

                    let mut expanded = std::env::home_dir()?;
                    expanded.push(it.as_path());

                    Some(expanded)
                }
                Some(_) => Some(path),
                None => None,
            }
        }

        fn agent_from_env(env: &str) -> Option<PathBuf> {
            std::env::var_os(env).and_then(|value| expand_tilde(value.into()))
        }

        fn parse_agent(value: String) -> Option<PathBuf> {
            if value == "none" {
                None
            } else if value == AGENT_ENV {
                agent_from_env(AGENT_ENV)
            } else if let Some(env_key) = value.strip_prefix('$') {
                agent_from_env(env_key)
            } else {
                expand_tilde(value.into())
            }
        }

        let identities = conf
            .identity_file
            .take()
            .map(|v| v.into_iter().filter_map(expand_tilde).collect::<Vec<_>>());

        let cert = conf.certificate_file.take().and_then(expand_tilde);

        let agent = conf
            .unsupported_fields
            .remove("identityagent")
            .and_then(|mut v| (!v.is_empty()).then(|| v.swap_remove(0)))
            .and_then(parse_agent)
            .or_else(|| agent_from_env(AGENT_ENV));

        let identities_only = conf
            .unsupported_fields
            .get("identitiesonly")
            .is_some_and(|v| v.first().is_some_and(|v| v == "yes"));

        Auth {
            identities,
            cert,
            agent,
            identities_only,
            includes_none: true,
        }
    }

    pub(super) fn parse_tty(conf: &OpenSshHost) -> RequestTty {
        conf.unsupported_fields
            .get("requesttty")
            .and_then(|v| v.first())
            .map(|s| RequestTty::from_str(s))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parsers::AGENT_ENV;

    #[test]
    fn parse_target() {
        assert_eq!(
            Target::parse("my-host"),
            Target {
                host: "my-host",
                port: None,
                user: None,
            }
        );

        assert_eq!(
            Target::parse("user@my-host"),
            Target {
                host: "my-host",
                port: None,
                user: Some("user"),
            }
        );

        assert_eq!(
            Target::parse("my-host:2222"),
            Target {
                host: "my-host",
                port: Some(2222),
                user: None,
            }
        );

        assert_eq!(
            Target::parse("user@my-host:22"),
            Target {
                host: "my-host",
                port: Some(22),
                user: Some("user"),
            }
        );

        assert_eq!(
            Target::parse("my-host:nan"),
            Target {
                host: "my-host",
                port: None,
                user: None,
            }
        );
    }

    fn openssh_config(conf: &str) -> OpenSshConfig {
        use ssh2_config::ParseRule;
        use std::io::BufReader;
        use std::io::Cursor;

        let mut rdr = BufReader::new(Cursor::new(conf.trim().as_bytes()));
        let conf = OpenSshConfig::default().parse(&mut rdr, ParseRule::ALLOW_UNSUPPORTED_FIELDS);
        assert!(conf.is_ok(), "could not parse OpenSSH config: {conf:?}");
        conf.unwrap()
    }

    fn query_config(conf: &str, host: &str) -> Host {
        let target = Target::parse(host);
        let conf = openssh_config(conf);
        let mut params = conf.query(target.host);
        let res = parsers::parse_host(&mut params, target);
        assert!(
            res.is_ok(),
            "could not resolve OpenSSH host for {host:?}: {res:?}"
        );
        res.unwrap()
    }

    fn clear_ssh_agent() {
        // SAFETY: We read/write environment variables only through std::env
        unsafe {
            std::env::remove_var(AGENT_ENV);
        }
    }
    fn set_ssh_agent(env: &str, value: &str) {
        // SAFETY: We read/write environment variables only through std::env
        unsafe {
            std::env::set_var(env, value);
        }
    }

    fn username() -> String {
        whoami::username().unwrap()
    }

    #[test]
    fn parse_dest() {
        let conf = "
Host test
    HostName test.com
    User me
    Port 2222
    IdentityFile path
        ";
        let host = query_config(conf, "test");
        assert_eq!(
            host.dest,
            Dest {
                name: "test.com".to_owned(),
                user: "me".to_owned(),
                port: 2222,
            }
        );
        let host = query_config(conf, "no");
        assert_eq!(
            host.dest,
            Dest {
                name: "no".to_owned(),
                user: username(),
                port: 22,
            }
        );
        let host = query_config(conf, "user@no:2022");
        assert_eq!(
            host.dest,
            Dest {
                name: "no".to_owned(),
                user: "user".to_owned(),
                port: 2022,
            }
        );

        let conf = "
Host *
    Port 2222

Host test
    HostName test.com
    User me
    Port 22
    IdentityFile path

Host *
    Port 2022
    User you
        ";
        let host = query_config(conf, "test");
        assert_eq!(
            host.dest,
            Dest {
                name: "test.com".to_owned(),
                user: "me".to_owned(),
                port: 2222,
            }
        );
        let host = query_config(conf, "no");
        assert_eq!(
            host.dest,
            Dest {
                name: "no".to_owned(),
                user: "you".to_owned(),
                port: 2222,
            }
        );
    }

    #[test]
    fn parse_auth() {
        clear_ssh_agent();

        let conf = "
Host test1
    IdentityFile path
Host test2
    IdentityFile path1
    IdentityFile path2
        ";
        let host = query_config(conf, "test1");
        assert_eq!(
            host.auth,
            Auth {
                identities: Some(vec![PathBuf::from("path")]),
                ..Default::default()
            }
        );
        let host = query_config(conf, "test2");
        assert_eq!(
            host.auth,
            Auth {
                identities: Some(vec![PathBuf::from("path1"), PathBuf::from("path2")]),
                ..Default::default()
            }
        );
        let host = query_config(conf, "no");
        assert_eq!(host.auth, Auth::default());

        let conf = "
Host *
    IdentityFile path1
Host test
    IdentityFile path2
Host *
    IdentityFile path3
        ";
        let host = query_config(conf, "test");
        assert_eq!(
            host.auth,
            Auth {
                identities: Some(vec![
                    PathBuf::from("path1"),
                    PathBuf::from("path2"),
                    PathBuf::from("path3")
                ]),
                ..Default::default()
            }
        );

        let conf = "
Host test1
    IdentityFile id
    CertificateFile cert 
    IdentitiesOnly yes
Host test2
    IdentitiesOnly no
        ";
        let host = query_config(conf, "test1");
        assert_eq!(
            host.auth,
            Auth {
                identities: Some(vec![PathBuf::from("id")]),
                cert: Some(PathBuf::from("cert")),
                identities_only: true,
                ..Default::default()
            }
        );
        let host = query_config(conf, "test2");
        assert_eq!(host.auth, Auth::default());

        let conf = "
Host test1
    IdentityAgent none
Host test2
    IdentityAgent sock
Host test3
    IdentityAgent SSH_AUTH_SOCK
Host test4
    IdentityAgent $SSH_AUTH_SOCK
Host test5
    IdentityAgent $_OPENRUSSH_TEST_SSH_AUTH_SOCK
        ";
        let host = query_config(conf, "test1");
        assert_eq!(host.auth, Auth::default());
        let host = query_config(conf, "test2");
        assert_eq!(
            host.auth,
            Auth {
                agent: Some(PathBuf::from("sock")),
                ..Default::default()
            }
        );
        let host = query_config(conf, "test3");
        assert_eq!(host.auth, Auth::default());
        let host = query_config(conf, "test4");
        assert_eq!(host.auth, Auth::default());

        set_ssh_agent("_OPENRUSSH_TEST_SSH_AUTH_SOCK", "sock");
        let host = query_config(conf, "test5");
        assert_eq!(
            host.auth,
            Auth {
                agent: Some(PathBuf::from("sock")),
                ..Default::default()
            }
        );
    }

    #[test]
    fn parse_tty() {
        let conf = "
Host test1
    IdentityFile path
Host test2
    RequestTTY no
Host test3
    RequestTTY yes
Host test4
    RequestTTY force
Host test5
    RequestTTY auto
Host test6
    RequestTTY unknown
        ";
        let host = query_config(conf, "test1");
        assert_eq!(host.tty, RequestTty::ForShell);
        let host = query_config(conf, "test2");
        assert_eq!(host.tty, RequestTty::Never);
        let host = query_config(conf, "test3");
        assert_eq!(host.tty, RequestTty::IfTty);
        let host = query_config(conf, "test4");
        assert_eq!(host.tty, RequestTty::Always);
        let host = query_config(conf, "test5");
        assert_eq!(host.tty, RequestTty::ForShell);
        let host = query_config(conf, "test6");
        assert_eq!(host.tty, RequestTty::ForShell);
    }

    #[test]
    fn include_conf() {
        use std::io::Write as _;

        let isolated_tmp = {
            let mut isolated_tmp = tempfile::NamedTempFile::new().unwrap();

            let saved_conf = "
Host test2
    Port 3333
        ";
            isolated_tmp.write_all(saved_conf.as_bytes()).unwrap();
            isolated_tmp.flush().unwrap();
            isolated_tmp
        };

        let grouped_tmp = {
            use std::fs::File;

            let dir = tempfile::tempdir().unwrap();
            let confd = dir.path().join("conf.d/my-group");

            std::fs::create_dir_all(&confd).unwrap();

            let mut f = File::create(confd.join("alfa.conf")).unwrap();
            let conf = "
Host test1
    User me
        ";
            f.write_all(conf.as_bytes()).unwrap();
            f.flush().unwrap();

            let mut f = File::create(confd.join("bravo.conf")).unwrap();
            let conf = "
Host test1
    HostName test.com
        ";
            f.write_all(conf.as_bytes()).unwrap();
            f.flush().unwrap();

            let mut f = File::create(confd.join("charlie.conf")).unwrap();
            let conf = "
Host test2
    User you
    IdentityFile path
        ";
            f.write_all(conf.as_bytes()).unwrap();
            f.flush().unwrap();

            dir
        };

        let conf = format!(
            "
Include {}/conf.d/my-group/*.conf
Include {}

Host test1
    Port 2222
    IdentityFile path
        ",
            grouped_tmp.path().display(),
            isolated_tmp.path().display(),
        );

        let host = query_config(&conf, "test1");
        assert_eq!(
            host.dest,
            Dest {
                name: "test.com".to_owned(),
                user: "me".to_owned(),
                port: 2222,
            }
        );

        let host = query_config(&conf, "test2");
        assert_eq!(
            host.dest,
            Dest {
                name: "test2".to_owned(),
                user: "you".to_owned(),
                port: 3333,
            }
        );
    }

    #[test]
    fn expand_tilde() {
        let home = std::env::home_dir().unwrap();

        let conf = "
Host test1
    IdentityFile path
Host test2
    IdentityFile ~/path
Host test3
    IdentityFile ~/long/long/path
        ";
        let host = query_config(conf, "test1");
        assert_eq!(
            host.auth,
            Auth {
                identities: Some(vec![PathBuf::from("path")]),
                ..Default::default()
            }
        );
        let host = query_config(conf, "test2");
        assert_eq!(
            host.auth,
            Auth {
                identities: Some(vec![home.join("path")]),
                ..Default::default()
            }
        );
        let host = query_config(conf, "test3");
        assert_eq!(
            host.auth,
            Auth {
                identities: Some(vec![home.join("long/long/path")]),
                ..Default::default()
            }
        );
    }

    #[test]
    fn proxy_jump() {
        #[derive(Debug)]
        struct Bastion {
            from: Option<String>,
            to: String,
        }
        #[derive(Debug)]
        struct BastionRef<'a> {
            from: Option<&'a str>,
            to: &'a str,
        }
        impl PartialEq<BastionRef<'_>> for Bastion {
            fn eq(&self, other: &BastionRef<'_>) -> bool {
                self.from.as_deref() == other.from && self.to == other.to
            }
        }
        fn query_chain(conf: &str, host: &str) -> Vec<Bastion> {
            let target = Target::parse(host);
            let conf = openssh_config(conf);
            let chain = target.query(&conf);

            assert!(
                chain.is_ok(),
                "could not resolve OpenSSH host for {host:?}: {chain:?}"
            );
            let chain = chain.unwrap();
            let (first, rest) = chain.iter();

            let mut v = vec![Bastion {
                from: None,
                to: first.dest.name.to_owned(),
            }];

            if let Some(rest) = rest {
                for bastion in rest {
                    v.push(Bastion {
                        from: Some(bastion.from.dest.name.to_owned()),
                        to: bastion.to.dest.name.to_owned(),
                    });
                }
            }

            v
        }

        let conf = "
Host test1
    IdentityFile path
Host test2
    IdentityFile path
    ProxyJump test1
Host test3
    IdentityFile path
    ProxyJump test2
Host test4
    IdentityFile path
Host test5
    IdentityFile path
    ProxyJump test1,test4
Host test6
    IdentityFile path
    ProxyJump test2,test4
Host test7
    IdentityFile path
    ProxyJump test1,test2,test3,test4
        ";
        assert_eq!(
            query_chain(conf, "test1"),
            vec![BastionRef {
                from: None,
                to: "test1",
            }],
        );
        assert_eq!(
            query_chain(conf, "test2"),
            vec![
                BastionRef {
                    from: None,
                    to: "test1",
                },
                BastionRef {
                    from: Some("test1"),
                    to: "test2",
                },
            ],
        );
        assert_eq!(
            query_chain(conf, "test3"),
            vec![
                BastionRef {
                    from: None,
                    to: "test1",
                },
                BastionRef {
                    from: Some("test1"),
                    to: "test2",
                },
                BastionRef {
                    from: Some("test2"),
                    to: "test3",
                },
            ],
        );
        assert_eq!(
            query_chain(conf, "test5"),
            vec![
                BastionRef {
                    from: None,
                    to: "test1",
                },
                BastionRef {
                    from: Some("test1"),
                    to: "test4",
                },
                BastionRef {
                    from: Some("test4"),
                    to: "test5",
                },
            ],
        );
        assert_eq!(
            query_chain(conf, "test6"),
            vec![
                BastionRef {
                    from: None,
                    to: "test1",
                },
                BastionRef {
                    from: Some("test1"),
                    to: "test2",
                },
                BastionRef {
                    from: Some("test2"),
                    to: "test4",
                },
                BastionRef {
                    from: Some("test4"),
                    to: "test6",
                },
            ],
        );
        assert_eq!(
            query_chain(conf, "test7"),
            vec![
                BastionRef {
                    from: None,
                    to: "test1",
                },
                BastionRef {
                    from: Some("test1"),
                    to: "test2",
                },
                BastionRef {
                    from: Some("test2"),
                    to: "test3",
                },
                BastionRef {
                    from: Some("test3"),
                    to: "test4",
                },
                BastionRef {
                    from: Some("test4"),
                    to: "test7",
                },
            ],
        );
    }
}
