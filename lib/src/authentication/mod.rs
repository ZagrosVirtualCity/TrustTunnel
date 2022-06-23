pub mod file_based;
pub mod radius;


use std::borrow::Cow;
use async_trait::async_trait;
use crate::log_utils;


/// Authentication request source
#[derive(Debug, Clone, PartialEq)]
pub enum Source<'this> {
    /// A client tries to authenticate using SNI
    Sni(Cow<'this, str>),
    /// A client tries to authenticate using
    /// [the basic authentication scheme](https://datatracker.ietf.org/doc/html/rfc7617)
    ProxyBasic(Cow<'this, str>),
}

/// Authentication procedure status
#[derive(Clone, PartialEq)]
pub enum Status {
    /// Success
    Pass,
    /// Failure
    Reject,
    /// The authentication procedure should be done through forwarder
    TryThroughForwarder(Source<'static>),
}

/// The authenticator abstract interface
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Authenticate client
    async fn authenticate(&self, source: Source<'_>, log_id: &log_utils::IdChain<u64>) -> Status;
}

/// The [`Authenticator`] implementation which always returns the same status.
/// By default it authenticates any request.
#[derive(Default)]
pub struct DummyAuthenticator {
    redirect_to_forwarder: bool,
}

impl DummyAuthenticator {
    /// Make the authenticator delegate any authentication request to a forwarder
    pub fn redirect_to_forwarder() -> Self {
        Self {
            redirect_to_forwarder: true,
        }
    }
}

#[async_trait]
impl Authenticator for DummyAuthenticator {
    async fn authenticate(&self, source: Source<'_>, _log_id: &log_utils::IdChain<u64>) -> Status {
        if self.redirect_to_forwarder {
            Status::TryThroughForwarder(source.into_owned())
        } else {
            Status::Pass
        }
    }
}

impl<'a> Source<'a> {
    pub fn into_owned(self) -> Source<'static> {
        match self {
            Source::Sni(x) => Source::Sni(Cow::Owned(x.into_owned())),
            Source::ProxyBasic(x) => Source::ProxyBasic(Cow::Owned(x.into_owned())),
        }
    }
}
