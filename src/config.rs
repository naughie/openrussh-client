use std::iter::Rev;
use std::path::PathBuf;
use std::slice::Windows;

use ssh2_config::HostParams as OpenSshHost;
use ssh2_config::SshConfig as OpenSshConfig;

const AGENT_ENV: &str = "SSH_AUTH_SOCK";

#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    UserNotFound(whoami::Error),
}

#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub host: &'a str,
    pub port: Option<u16>,
    pub user: Option<&'a str>,
}

impl<'a> Target<'a> {
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

    pub fn query(self, conf: &OpenSshConfig) -> Result<Chain, Error> {
        Chain::new(self, conf)
    }
}

#[derive(Debug, Clone)]
pub struct Dest {
    pub name: String,
    pub port: u16,
    pub user: String,
}

#[derive(Debug, Clone)]
pub struct Auth {
    pub identities: Option<Vec<PathBuf>>,
    pub cert: Option<PathBuf>,
    pub agent: Option<PathBuf>,
    pub identities_only: bool,
}

#[derive(Debug, Clone)]
pub struct Host {
    pub dest: Dest,
    pub auth: Auth,
}

#[derive(Debug, Clone)]
pub struct Chain {
    pub target: Host,
    pub bastions: Option<Box<[Host]>>,
}

impl Chain {
    pub fn new(target: Target<'_>, conf: &OpenSshConfig) -> Result<Self, Error> {
        resolve_config(target, conf)
    }

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

#[derive(Debug, Clone)]
pub struct BastionIter<'a> {
    final_target: Option<BastionItem<'a>>,
    bastions: Rev<Windows<'a, Host>>,
}

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

fn resolve_config(target: Target<'_>, conf: &OpenSshConfig) -> Result<Chain, Error> {
    fn query(params: &mut OpenSshHost, target: Target<'_>) -> Result<Host, Error> {
        let name = params
            .host_name
            .take()
            .unwrap_or_else(|| target.host.to_owned());
        let port = params.port.unwrap_or_else(|| target.port.unwrap_or(22));
        let user = if let Some(user) = params.user.take() {
            user
        } else if let Some(user) = target.user {
            user.to_owned()
        } else {
            whoami::username().map_err(Error::UserNotFound)?
        };

        let auth = parse_auth_methods(params);

        Ok(Host {
            dest: Dest { name, port, user },
            auth,
        })
    }

    let mut target_params = conf.query(target.host);
    let target_host = query(&mut target_params, target)?;

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
                let host = query(&mut params, target)?;
                bastions.push(host);
            }

            let target = Target::parse(first_bastion);
            let mut params = conf.query(target.host);
            let host = query(&mut params, target)?;
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

#[derive(Debug, Clone)]
pub enum AuthMethod {
    LocalKey(PathBuf),
    Agent(PathBuf),
}

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

fn parse_auth_methods(conf: &mut OpenSshHost) -> Auth {
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
    }
}
