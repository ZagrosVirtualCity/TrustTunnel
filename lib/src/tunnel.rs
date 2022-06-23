use std::io;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use tokio::time;
use crate::authentication::Status;
use crate::downstream::{AuthorizedRequest, Downstream, PendingDatagramMultiplexerRequest, PendingTcpConnectRequest};
use crate::forwarder::Forwarder;
use crate::{authentication, core, datagram_pipe, downstream, forwarder, log_id, log_utils, pipe, udp_pipe};
use crate::pipe::DuplexPipe;


#[derive(Clone)]
pub(crate) enum AuthenticationPolicy<'this> {
    /// Perform the regular authentication procedure through the configured authenticator
    Default,
    /// The whole connection is authenticated, perform authentication only if requested
    Authenticated,
    /// Pass the provided authentication info to the forwarder with each request
    ThroughForwarder(authentication::Source<'this>),
}

pub(crate) struct Tunnel {
    context: Arc<core::Context>,
    downstream: Box<dyn Downstream>,
    forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
    authentication_policy: AuthenticationPolicy<'static>,
    id: log_utils::IdChain<u64>,
}


impl Tunnel {
    pub fn new(
        context: Arc<core::Context>,
        downstream: Box<dyn Downstream>,
        forwarder: Box<dyn Forwarder>,
        authentication_policy: AuthenticationPolicy<'static>,
        id: log_utils::IdChain<u64>,
    ) -> Self {
        Self {
            context,
            downstream,
            forwarder: Arc::new(Mutex::new(forwarder)),
            authentication_policy,
            id,
        }
    }

    pub async fn listen(&mut self) -> io::Result<()> {
        let (mut shutdown_notification, _shutdown_completion) = {
            let shutdown = self.context.shutdown.lock().unwrap();
            (shutdown.notification_handler(), shutdown.completion_guard())
        };
        tokio::select! {
            x = shutdown_notification.wait() => {
                match x {
                    Ok(_) => self.downstream.graceful_shutdown().await,
                    Err(e) => Err(io::Error::new(ErrorKind::Other, format!("{}", e))),
                }
            }
            x = self.listen_inner() => x,
        }
    }

    async fn listen_inner(&mut self) -> io::Result<()> {
        loop {
            let request = match tokio::time::timeout(
                self.context.settings.client_listener_timeout, self.downstream.listen()
            ).await {
                Ok(Ok(None)) => {
                    log_id!(debug, self.id, "Tunnel closed gracefully");
                    return Ok(());
                }
                Ok(Ok(Some(r))) => r,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::from(ErrorKind::TimedOut)),
            };

            let context = self.context.clone();
            let forwarder = self.forwarder.clone();
            let request_id = request.id();
            let authentication_policy = self.authentication_policy.clone();
            let log_id = self.id.clone();
            let update_metrics = {
                let metrics = context.metrics.clone();
                let protocol = self.downstream.protocol();
                move |direction, n| {
                    match direction {
                        pipe::SimplexDirection::Incoming => metrics.add_inbound_bytes(protocol, n),
                        pipe::SimplexDirection::Outgoing => metrics.add_outbound_bytes(protocol, n),
                    }
                }
            };

            tokio::spawn(async move {
                let forwarder_auth = match authentication_policy {
                    AuthenticationPolicy::Default => {
                        let auth_info = request.auth_info();
                        match auth_info {
                            Ok(Some(source)) =>
                                match context.settings.authenticator.authenticate(source, &log_id).await {
                                    Status::Pass => None,
                                    Status::Reject => {
                                        log_id!(debug, request_id, "Authentication failed");
                                        request.fail_request();
                                        return;
                                    }
                                    Status::TryThroughForwarder(x) => Some(x),
                                },
                            Ok(None) => {
                                log_id!(debug, request_id, "Got request without authentication info on non-authenticated connection");
                                request.fail_request();
                                return;
                            }
                            Err(e) => {
                                log_id!(debug, request_id, "Failed to get auth info: {}", e);
                                request.fail_request();
                                return;
                            }
                        }
                    }
                    AuthenticationPolicy::Authenticated => None,
                    AuthenticationPolicy::ThroughForwarder(x) => Some(x),
                };

                match request.succeed_request() {
                    Ok(None) => (),
                    Ok(Some(AuthorizedRequest::TcpConnect(request))) => {
                        if let Err((request, message, e)) = Tunnel::on_tcp_connect_request(
                            context, forwarder, request, forwarder_auth, update_metrics,
                        ).await {
                            log_id!(debug, request_id, "{}: {}", message, e);
                            if let Some(request) = request {
                                let _ = request.fail_request(e);
                            }
                        }
                    }
                    Ok(Some(AuthorizedRequest::DatagramMultiplexer(request))) => {
                        if let Err((message, e)) = Tunnel::on_datagram_mux_request(
                            context, forwarder, request, forwarder_auth, update_metrics,
                        ).await {
                            log_id!(debug, request_id, "{}: {}", message, e);
                        }
                    }
                    Err(e) => {
                        log_id!(debug, request_id, "Failed to complete request: {}", e);
                    }
                }
            });
        }
    }

    async fn on_tcp_connect_request<F: Fn(pipe::SimplexDirection, usize) + Send + Clone>(
        context: Arc<core::Context>,
        forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
        request: Box<dyn PendingTcpConnectRequest>,
        forwarder_auth: Option<authentication::Source<'static>>,
        update_metrics: F,
    ) -> Result<(), (Option<Box<dyn PendingTcpConnectRequest>>, &'static str, io::Error)> {
        let request_id = request.id();
        let destination = match request.destination() {
            Ok(d) => d,
            Err(e) => return Err((Some(request), "Failed to get destination", e)),
        };

        let meta = forwarder::TcpConnectionMeta {
            client_address: match request.client_address() {
                Ok(x) => x,
                Err(e) => return Err((Some(request), "Failed to get client address", e)),
            },
            destination,
            auth: forwarder_auth,
            client_platform: request.client_platform(),
            app_name: request.app_name(),
        };
        log_id!(trace, request_id, "Connecting to peer: {:?}", meta);

        let connector =
            match forwarder.lock().unwrap().tcp_connector(request_id.clone(), meta) {
                Ok(c) => c,
                Err(e) => return Err((Some(request), "Failed to start connection", e)),
            };

        let (fwd_rx, fwd_tx) =
            match time::timeout(context.settings.tcp_connections_timeout, connector.connect()).await
                .unwrap_or_else(|_| Err(io::Error::from(ErrorKind::TimedOut)))
            {
                Ok(x) => x,
                Err(e) => return Err((Some(request), "Connection to peer failed", e)),
            };

        log_id!(trace, request_id, "Successfully connected to peer");
        let (dstr_rx, dstr_tx) =
            match request.succeed_request() {
                Ok(x) => x,
                Err(e) => return Err((None, "Failed to complete request", e)),
            };

        let mut pipe = DuplexPipe::new(
            (pipe::SimplexDirection::Outgoing, dstr_rx, fwd_tx),
            (pipe::SimplexDirection::Incoming, fwd_rx, dstr_tx),
            update_metrics,
        );

        match pipe.exchange(context.settings.tcp_connections_timeout).await {
            Ok(_) => {
                log_id!(trace, request_id, "Both ends closed gracefully");
                Ok(())
            }
            Err(e) => Err((None, "Error on pipe", e)),
        }
    }

    async fn on_datagram_mux_request<F: Fn(pipe::SimplexDirection, usize) + Send + Clone + Sync>(
        context: Arc<core::Context>,
        forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
        request: Box<dyn PendingDatagramMultiplexerRequest>,
        forwarder_auth: Option<authentication::Source<'static>>,
        update_metrics: F,
    ) -> Result<(), (&'static str, io::Error)> {
        let request_id = request.id();
        let client_address = match request.client_address() {
            Ok(x) => x,
            Err(e) => return Err(("Failed to get client address", e)),
        };
        let client_platform = request.client_platform();
        let mut pipe: Box<dyn datagram_pipe::DuplexPipe> = match request.succeed_request() {
            Ok(downstream::DatagramPipeHalves::Udp(dstr_source, dstr_sink)) => {
                let meta = forwarder::UdpMultiplexerMeta {
                    client_address,
                    auth: forwarder_auth,
                    client_platform,
                };
                let (fwd_shared, fwd_source, fwd_sink) =
                    match forwarder.lock().unwrap()
                        .make_udp_datagram_multiplexer(request_id.clone(), meta)
                    {
                        Ok(x) => x,
                        Err(e) => return Err(("Failed to create datagram multiplexer", e)),
                    };

                Box::new(udp_pipe::DuplexPipe::new(
                    (dstr_source, dstr_sink),
                    (fwd_shared, fwd_source, fwd_sink),
                    update_metrics,
                    context.settings.udp_connections_timeout,
                ))
            }
            Ok(downstream::DatagramPipeHalves::Icmp(dstr_source, dstr_sink)) => {
                let (fwd_source, fwd_sink) =
                    match forwarder.lock().unwrap().make_icmp_datagram_multiplexer(request_id.clone()) {
                        Ok(x) => x,
                        Err(e) => return Err(("Failed to create datagram multiplexer", e)),
                    };

                Box::new(datagram_pipe::GenericDuplexPipe::new(
                    (
                        pipe::SimplexDirection::Outgoing,
                        dstr_source,
                        fwd_sink,
                    ),
                    (
                        pipe::SimplexDirection::Incoming,
                        fwd_source,
                        dstr_sink,
                    ),
                    update_metrics,
                ))
            }
            Err(e) => return Err(("Failed to respond for datagram multiplexer request", e)),
        };

        match pipe.exchange().await {
            Ok(_) => {
                log_id!(trace, request_id, "Datagram multiplexer gracefully closed");
                Ok(())
            },
            Err(e) => Err(("Datagram multiplexer closed with error", e)),
        }
    }
}
