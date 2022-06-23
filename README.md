# AdGuard VPN endpoint

## Building

Execute the following commands in Terminal:
```shell
cargo build
```
to build the debug version, or
```shell
cargo build --release
```
to build the release version.

## Issuing self-signed cert and keys (RSA)

Execute the following commands in Terminal:
```shell
openssl req -config <openssl.conf> -new -x509 -sha256 -newkey rsa:2048 -nodes -days 1000 -keyout key.pem -out cert.pem
```
where
* `<openssl.conf>` is an optional OpenSSL request template file

## Endpoint configuration

### Library configuration

An endpoint can be configured using a JSON file. The file struct reflects the library settings
(see `struct Settings` in [settings.rs](./lib/src/settings.rs)).
For a detailed description of the features see [here](./lib/README.md#features-description).
The very basic configuration file can be found in [the example](#example-endpoint).

The full set of settings is shown bellow in the pseudo-json format:
* the lines which start with `///` are comments
* an item marked with `Default(x)` is set to `x` in case it is omitted
* an item marked with `Optional` may be omitted, it will turn off the corresponding feature
* an item marked with `Enum` may take one of the listed values; for example, authenticator may be
  `"authenticator": { "file": { "path": "/creds.txt" } }` as well as
  `"authenticator": { "radius": { "address": "127.0.0.1:1813" } }`

```
{
  /// The number of worker threads
  "threads_number": Default(number of CPUs),
  /// The address to listen on
  "listen_address": Default("0.0.0.0:433"),
  /// The TLS host info for traffic tunneling
  "tunnel_tls_host_info": {
    "hostname": "localhost",
    /// Path to a file containing the certificate chain
    "cert_chain_path": "cert.pem",
    /// Path to a file containing the private key.
    /// May be equal to `cert_chain_path` if it contains both of them.
    "private_key_path": "key.pem"
  },
  /// The TLS host info for HTTPS pinging.
  /// With this one set up the endpoint will respond with `200 OK` to HTTPS `GET` requests
  /// to the specified domain.
  /// The host name MUST differ from the tunneling host and reverse proxy ones.
  "ping_tls_host_info": {
    "hostname": "ping.localhost",
    "cert_chain_path": "cert.pem",
    "private_key_path": "key.pem"
  },
  /// The reverse proxy settings.
  /// With this one set up the endpoint does TLS termination on such connections and
  /// translates HTTP/x traffic into HTTP/1.1 protocol towards the server and back
  /// into original HTTP/x towards the client. Like this:
  ///
  /// ```(client) TLS(HTTP/x) <--(endpoint)--> (server) HTTP/1.1```
  ///
  /// The translated HTTP/1.1 requests have the custom header `X-Original-Protocol`
  /// appended. For now, its value can be either `HTTP1`, or `HTTP3`.
  "reverse_proxy": Optional {
    /// The origin server address
    "server_address": "127.0.0.1:1111",
    "tls_info": {
      "hostname": "hello.localhost",
      "cert_chain_path": "cert.pem",
      "private_key_path": "key.pem"
    },
    /// The connection timeout
    "connection_timeout_secs": Default(30),
    /// With this one set to `true` the endpoint overrides the HTTP method while
    /// translating an HTTP3 request to HTTP1 in case the request has the `GET` method
    /// and its path is `/`
    "h3_backward_compatibility": Default(false)
  },
  /// IPv6 availability
  "ipv6_available": Default(true),
  /// Time out of a TLS handshake
  "tls_handshake_timeout_secs": Default(10),
  /// Time out of a client listener
  "client_listener_timeout_secs": Default(600),
  /// Time out of tunneled TCP connections
  "tcp_connections_timeout_secs": Default(30),
  /// Time out of tunneled UDP "connections"
  "udp_connections_timeout_secs": Default(30),
  /// The forwarder codec settings
  "forward_protocol": Enum {
    Default("direct": {}),
    "socks5": {
      "address": "127.0.0.1:1080",
      /// Enable/disable extended authentication.
      /// If enabled, the username during authentication will be formatted as follows:
      ///
      /// ```<username>@<client_address>@<client_platform>@<app_name>[@]```
      ///
      /// `<client_address>` - the address of a VPN client sent the request
      /// `<client_platform>` - the name of a platform of the VPN client (_may be absent_,
      /// e.g, `uname@54.243.99.69:7777@@curl`)
      /// `<app_name>` - the name of an application initiated the request (_may be absent_,
      /// e.g, `uname@54.243.99.69:7777@Linux@`)
      ///
      /// In case the resulting string exceeds the boundaries, it's marked as truncated
      /// with `@` character (e.g., `uname@54.243.99.69:7777@Windows@very_long_app_name@`).
      ///
      /// **NOTE**: setting this to true overrides other authentication settings
      "extended_auth": Default(false)
    }
  },
  /// The list of listener codec settings
  "listen_protocols": [
    Enum {
      "http1": {},
      "http2": {
        /// The initial window size (in octets) for connection-level flow control for received data
        "initial_connection_window_size": Default(8 MB),
        /// The initial window size (in octets) for stream-level flow control for received data
        #[serde(default = "Http2Settings::default_initial_stream_window_size")]
        "initial_stream_window_size": Default(128 KB),
        /// The number of streams that the sender permits the receiver to create
        "max_concurrent_streams": Default(1000),
        /// The size (in octets) of the largest HTTP/2 frame payload that we are able to accept
        "max_frame_size": Default(16 KB),
        /// The max size of received header frames
        "header_table_size": Default(64 K)
      },
      "quic": {
        /// The size of UDP payloads that the endpoint is willing to receive. UDP datagrams with
        /// payloads larger than this limit are not likely to be processed.
        "recv_udp_payload_size": Default(1350),
        /// The size of UDP payloads that the endpoint is willing to send
        "send_udp_payload_size": Default(1350),
        /// The initial value for the maximum amount of data that can be sent on the connection
        "initial_max_data": Default(100 MB),
        /// The initial flow control limit for locally initiated bidirectional streams
        "max_stream_data_bidi_local": Default(1 MB),
        /// The initial flow control limit for peer-initiated bidirectional streams
        "max_stream_data_bidi_remote": Default(1 MB),
        /// The initial flow control limit for unidirectional streams
        "max_stream_data_uni": Default(1 MB),
        /// The initial maximum number of bidirectional streams the endpoint that receives this
        /// transport parameter is permitted to initiate
        "max_streams_bidi": Default(4K),
        /// The initial maximum number of unidirectional streams the endpoint that receives this
        /// transport parameter is permitted to initiate
        "max_streams_uni": Default(4K),
        /// The maximum size of the connection window
        "max_connection_window": Default(24 MB),
        /// The maximum size of the stream window
        "max_stream_window": Default(16 MB),
        /// Disable active connection migration on the address being used during the handshake
        "disable_active_migration": Default(true),
        /// Enable sending or receiving early data
        "enable_early_data": Default(true),
        /// The capacity of the QUIC multiplexer message queue.
        /// Decreasing it may cause packet dropping in case the multiplexer cannot keep up the pace.
        /// Increasing it may lead to high memory consumption.
        "message_queue_capacity": Default(4K)
      }
    },
    ...
  ],
  /// The client authenticator
  "authenticator": Enum {
    "file": {
      "path": "auth_info.txt"
    },
    "radius": {
      /// The RADIUS server address
      "server_address": "127.0.0.1:1813",
      /// Timeout of the authentication procedure
      "timeout_secs": Default(3),
      /// The password shared between the client and the RADIUS server
      "secret": "String",
      /// The authentication cache capacity
      #[serde(default = "RadiusAuthenticatorSettings::default_cache_size")]
      "cache_size": Default(1024),
      /// The authentication cache entry TTL
      "cache_ttl_secs": Default(10)
    }
  },
  /// The ICMP forwarding settings.
  /// Setting up this feature requires superuser rights on some systems.
  "icmp": Optional {
    /// The name of an interface to bind the ICMP socket to
    "interface_name": "eth0",
    /// Time out of tunneled ICMP requests
    "request_timeout_secs": Default(3),
    /// The capacity of the ICMP multiplexer received messages queue.
    /// Decreasing it may cause packet dropping in case the multiplexer cannot keep up the pace.
    /// Increasing it may lead to high memory consumption.
    /// Each client has its own queue.
    "recv_message_queue_capacity": Default(256)
  },
  /// The metrics handling settings
  "metrics": Optional {
    /// The address to listen on for settings export requests
    "address": Default("0.0.0.0:1987"),
    /// Time out of a metrics request
    "request_timeout_secs": Default(3)
  }
}
```

### Executable configuration

Some options reside on the application level. Such options can be configured via command
line arguments. For example:

* [Sentry DSN](https://docs.sentry.io/product/sentry-basics/dsn-explainer/) is configured
  by specifying `--sentry_dsn <url>`
* Logging level is configured by `[--log_level|-l] [info|debug|trace]` (`info` - default)
* Logging file is configured by `--log_file <path>`. If not specified, the instance logs
  to `stdout`.

To see the full set of available options, execute the following commands in Terminal:
```shell
<path/to/target>/vpn_endpoint -h
```

## Running

To run the binary through `cargo`, execute the following commands in Terminal:
```shell
cargo run --bin vpn_endpoint -- <path/to/vpn.config>
```

To run the binary directly, execute the following commands in Terminal:
```shell
<path/to/target>/vpn_endpoint <path/to/vpn.config>
```
where `<path/to/target>` is determined by the build command (by default it is `./target/debug` or
`./target/release` depending on the build type).

## Example endpoint

For a quic setup you can run the example endpoint (see [here](./examples/my_vpn)).
It shows the essential things needed to run an instance.
To start one run the following commands in Terminal:
```shell
cd ./examples/my_vpn && ./run.sh
```
It may ask you to enter some information for generating your certificate.
Skip it clicking `enter` if it does not matter.

## Testing with Google Chrome

1) 2 options:
   * Add the generated certificate to the trusted store and run the Google Chrome
   * Run the Google Chrome from Terminal like this:
    ```shell
    google-chrome --ignore-certificate-errors
    ```
   **IMPORTANT:** the second option should be used just for testing, it removes the first line
                  of defence against malicious resources
2) Set up the endpoint as an HTTPS proxy server in the browser (either via browser settings or 
using an extension like `Proxy SwitchyOmega`)

## Collecting metrics

Common ways:

* As plain text: send a GET request to `<ip>:<port>/metrics`, for example, using CURL
or a web browser
* Set up Prometheus:
  1) Configure the instance to monitor the endpoint metrics (see [here](https://prometheus.io/docs/prometheus/latest/getting_started/#configure-prometheus-to-monitor-the-sample-targets))
  2) Use [the graph interface](https://prometheus.io/docs/prometheus/latest/getting_started/#using-the-graphing-interface)

## License

Apache 2.0
