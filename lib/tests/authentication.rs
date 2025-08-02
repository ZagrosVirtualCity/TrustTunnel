use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use futures::future;
use http::Request;
use log::info;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use vpn_libs_endpoint::authentication;
use vpn_libs_endpoint::authentication::registry_based::RegistryBasedAuthenticator;
use vpn_libs_endpoint::settings::{ForwardProtocolSettings, Http1Settings, ListenProtocolSettings, Settings, Socks5ForwarderSettings, TlsHostInfo, TlsHostsSettings};

mod common;

#[tokio::test]
async fn registry_proxy_auth_success() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let status = do_connect_request(&endpoint_address, Some("a:b".into())).await;
        assert_ne!(status, http::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address, true, None) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn registry_proxy_auth_failure() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let status = do_connect_request(&endpoint_address, None).await;
        assert_eq!(status, http::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address, true, None) => unreachable!(),
        _ = client_task => (),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn no_authenticator_socks_standard_auth() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let (socks_addr, socks_task) = make_socks_server_harness();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = do_connect_request(&endpoint_address, Some("a:b".into())).await;
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address, true, Some(socks_addr)) => unreachable!(),
        _ = client_task => unreachable!(),
        x = socks_task => assert!(x.contains(&0x02), "{:?}", x),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn no_authenticator_no_socks_auth() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let (socks_addr, socks_task) = make_socks_server_harness();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = do_connect_request(&endpoint_address, None).await;
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address, false, Some(socks_addr)) => unreachable!(),
        _ = client_task => unreachable!(),
        x = socks_task => assert!(!x.iter().any(|x| *x != 0x00), "Must not contain non-NoAuth methods: {:?}", x),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

#[tokio::test]
async fn authenticator_present_socks_standard_auth() {
    common::set_up_logger();
    let endpoint_address = common::make_endpoint_address();

    let (socks_addr, socks_task) = make_socks_server_harness();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = do_connect_request(&endpoint_address, Some("a:b".into())).await;
    };

    tokio::select! {
        _ = run_endpoint(&endpoint_address, true, Some(socks_addr)) => unreachable!(),
        _ = client_task => unreachable!(),
        x = socks_task => assert!(x.contains(&0x02), "{:?}", x),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("Timed out"),
    }
}

async fn run_endpoint(listen_address: &SocketAddr, with_auth: bool, socks_proxy: Option<SocketAddr>) {
    let mut builder = Settings::builder()
        .listen_address(listen_address).unwrap()
        .listen_protocols(ListenProtocolSettings {
            http1: Some(Http1Settings::builder().build()),
            ..Default::default()
        })
        .allow_private_network_connections(true);

    if with_auth {
        builder = builder.clients(Vec::from_iter(std::iter::once(
            authentication::registry_based::Client {
                username: "a".into(),
                password: "b".into(),
            }
        )));
    }

    if let Some(address) = socks_proxy {
        builder = builder.forwarder_settings(ForwardProtocolSettings::Socks5(
            Socks5ForwarderSettings::builder()
                .server_address(address).unwrap()
                .build().unwrap()
        ));
    }

    let settings = builder.build().unwrap();

    let cert_key_file = common::make_cert_key_file();
    let cert_key_path = cert_key_file.path.to_str().unwrap();
    let hosts_settings = TlsHostsSettings::builder()
        .main_hosts(vec![TlsHostInfo {
            hostname: common::MAIN_DOMAIN_NAME.to_string(),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
        }])
        .build().unwrap();

    common::run_endpoint_with_settings(settings, hosts_settings).await;
}

async fn do_connect_request(
    endpoint_address: &SocketAddr,
    proxy_auth: Option<String>,
) -> http::StatusCode {
    let stream = common::establish_tls_connection(
        common::MAIN_DOMAIN_NAME,
        endpoint_address,
        None,
    ).await;

    let (mut request, conn_driver) = hyper::client::conn::Builder::new()
        .handshake(stream)
        .await.unwrap();

    let exchange = async move {
        let mut rr = Request::builder()
            .version(http::Version::HTTP_11)
            .method(http::Method::CONNECT)
            .uri("https://httpbin.agrd.dev:443/");

        if let Some(x) = proxy_auth {
            rr = rr.header(
                http::header::PROXY_AUTHORIZATION,
                format!("Basic {}", BASE64_ENGINE.encode(x)),
            );
        }

        let rr = rr.body(hyper::Body::empty())
            .unwrap();
        let response = request.send_request(rr).await.unwrap();
        info!("CONNECT response: {:?}", response);
        response.status()
    };

    futures::pin_mut!(conn_driver);
    futures::pin_mut!(exchange);
    match future::select(conn_driver, exchange).await {
        future::Either::Left((_, exchange)) => exchange.await,
        future::Either::Right((x, _)) => x,
    }
}

fn make_socks_server_harness() -> (SocketAddr, impl Future<Output=Vec<u8>>) {
    let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let task = async move {
        let server = TcpListener::from_std(server).unwrap();
        let (mut socket, peer) = server.accept().await.unwrap();
        info!("New connection from {}", peer);

        let mut buf = vec![0; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0, "n = {}", n);
        assert_eq!(buf[0], 0x05, "Unexpected version number");
        assert_eq!(buf[1] as usize, n - 2, "Unexpected number of methods");
        Vec::from(&buf[2..n])
    };

    (server_addr, task)
}
