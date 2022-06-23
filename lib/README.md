# AdGuard VPN endpoint

## Building the library

### Prerequisites

* Rust 1.59.0 or higher: use a preferred way from https://www.rust-lang.org/tools/install

### Building

Execute the following commands in Terminal:
```shell
cargo build
```
to build the debug version, or
```shell
cargo build --release
```
to build the release version.

## Features description

### Traffic forwarding

As for now, the endpoint can demultiplex client's connections multiplexed in either HTTP/1, or
HTTP/2, or HTTP/3 session. An application can set up how the endpoint forwards the demultiplexed
client's connection by setting `Settings.forward_protocol`. The available options
(see `settings.ForwardProtocolSettings`) are:
* routing a connection directly to its target host
* routing a connection though a SOCKS5 proxy

#### ICMP forwarding

As an optional feature, the endpoint can also forward ICMP packets from a client. This feature
can be set up by setting `Settings.icmp`. An application MUST set up an interface name to bind
the ICMP socket to, and MAY tweak some other settings, like the timeouts and message queue size.

### Reverse proxy

The traffic received via a TLS session or QUIC connection with the SNI set to the host name
equal to `Settings.reverse_proxy.tls_info.hostname` is interpreted as a reverse proxy stream.
The stream is used for mutual client and endpoint notifications and some control messages.
The endpoint does TLS termination on such connections and translates HTTP/x traffic into
HTTP/1.1 protocol towards the server and back into original HTTP/x towards the client.
Like this:

```(client) TLS(HTTP/x) <--(endpoint)--> (server) HTTP/1.1```

The translated HTTP/1.1 requests have the custom header `X-Original-Protocol` appended.
For now, its value can be either `HTTP1`, or `HTTP3`.

### Authentication

#### Client authentication options

##### SNI authentication

A client connects to the endpoint with SNI set to `hash.domain_name`, where:
* `hash` - `md5(application_id + ':' + token + ':' + credentials)`
* `domain_name` - the endpoint's original domain name (e.g. `myvpn.org`)

##### Proxy authentication

A client connects to the endpoint using the proxy HTTP authentication mechanism with
the "basic" scheme: `Proxy-Authorization: Basic base64(token + ':' + credentials)`.

#### Endpoint authentication methods

An application can set up the authentication method being used by the endpoint
by setting `Settings.authenticator`. The application can provide its own authenticator
implementation (see the `authentication.Authenticator` trait), or use one of the implementations
provided by the library:
* `authentication.DummyAuthenticator` - authenticates any request
* `authentication.file_based.FileBasedAuthenticator` - authenticates a request basing on
  the file containing credentials (see [here](#file-based-authenticator))
* `authentication.radius.RadiusAuthenticator` - delegates authentication to an authenticator
  communicating with it by the RADIUS protocol (see [here](#radius-authenticator))
* SOCKS5 authentication - delegates authentication to the SOCKS5 forwarder (see [here](#socks5-authenticator))

**Please note**, that the first 2 are very simple authenticator implementations which are intended
mostly for testing purposes and do not respect network security practices.

##### File based authenticator

The file must contain an application id (`applicationId: <string>`), token (`token: <string>`),
and credentials (`credentials: <string>`).
Each one must be on a new line. The order does not matter.

##### RADIUS authenticator

This authenticator implementation communicates with an authentication server by [the Microsoft EAP
CHAP Extensions Protocol, Version 2](https://datatracker.ietf.org/doc/html/draft-kamath-pppext-eap-mschapv2-02)
over [the Extensible Authentication Protocol](https://www.rfc-editor.org/rfc/rfc3748.html)
over [the RADIUS protocol](https://datatracker.ietf.org/doc/html/rfc2865).

Successful authentication procedure diagram:

```mermaid
sequenceDiagram
    participant Endpoint
    participant Authenticator

    Endpoint ->> Authenticator: RADIUS: code=AccessRequest[EAP: code=Response, type=Identity, user_name]
    Authenticator ->> Endpoint: RADIUS: code=AccessChallenge[EAP: code=Request, type=MsAuth[MS-CHAP-V2: code=Challenge]]
    Endpoint ->> Endpoint: MS-CHAP-V2::GenerateNTResponse()
    Endpoint ->> Authenticator: RADIUS: code=AccessRequest[EAP: code=Response, type=MsAuth[MS-CHAP-V2: code=Response]]
    Authenticator ->> Authenticator: Verify MS-CHAP-V2 response
    Authenticator ->> Authenticator: Authenticate
    Authenticator ->> Endpoint: RADIUS: code=AccessChallenge[EAP: code=Request, type=MsAuth[MS-CHAP-V2: code=SuccessRequest]]
    Endpoint ->> Endpoint: MS-CHAP-V2::CheckAuthenticatorResponse()
    Endpoint ->> Authenticator: RADIUS: code=AccessRequest[EAP: code=Response, type=MsAuth[MS-CHAP-V2: code=SuccessResponse]]
    Authenticator ->> Endpoint: RADIUS: code=AccessAccept[EAP: code=Success, type=MsAuth]
```

Depending on the client-side authentication way, the `user_name` and `password` are as follows:
* [SNI authentication](#sni-authentication):
  * `user_name` = `sni@<id>@<hash[0..6]>` - a special value which indicates the authentication way
    * `<id>` - the id of the current authentication session
    * `<hash[0..6]>` - the first 6 characters of the SNI
  * `password` = `hash` - corresponds to `hash`, as in [SNI authentication](#sni-authentication)
* [Proxy authentication](#proxy-authentication):
  * `user_name` and `password` correspond to `token` and `credentials`, as in [Proxy authentication](#proxy-authentication)

The endpoint caches the authentication status and repeats the procedure for the client after
the cache TTL (see `RadiusAuthenticatorSettings.cache_ttl`).

##### SOCKS5 authenticator

Perform authentication according to the [RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929).
Depending on the client-side authentication way, the username and password are as follows:
* [SNI authentication](#sni-authentication):
  * username = `sni@<hash[0..6]>@<client_address>@<client_platform>@<app_name>[@]`
    * `<hash[0..6]>` - the first 6 characters of the SNI
    * `<client_address>` - the address of a VPN client sent the request (e.g. `54.243.99.69:12345`)
    * `<client_platform>` - the name of a platform of the VPN client (_may be absent_,
      e.g, `uname@54.243.99.69:12345@@curl`)
    * `<app_name>` - the name of an application initiated the request (_may be absent_,
      e.g, `uname@54.243.99.69:12345@Linux@`)

  * `password` = `hash` - corresponds to `hash`, as in [SNI authentication](#sni-authentication)

* [Proxy authentication](#proxy-authentication):
  * username = `<user_name>@<client_address>@<client_platform>@<app_name>[@]`
    * `<user_name>` - corresponds to `token`, as in [Proxy authentication](#proxy-authentication)
    * `<client_address>` - the address of a VPN client sent the request (e.g. `54.243.99.69:12345`)
    * `<client_platform>` - the name of a platform of the VPN client (_may be absent_,
      e.g, `uname@54.243.99.69:12345@@curl`)
    * `<app_name>` - the name of an application initiated the request (_may be absent_,
      e.g, `uname@54.243.99.69:12345@Linux@`)

  * password corresponds to `credentials`, as in [Proxy authentication](#proxy-authentication)

### Metrics collecting

In order to collect some metrics of a running endpoint, an application can set up it to listen for
the metrics collecting requests (see `Settings.metrics`). An endpoint running with this feature
will listen on the configured address (`MetricsSettings.address`) for plain HTTP/1 requests.
The following paths are available:
* `/health-check` - used for pinging the endpoint, so it will respond with `200 OK`
* `/metrics` - used for metrics collecting, so it will respond with a bunch of values accoring to
  [the prometheus specification](https://prometheus.io/)

## License

Apache 2.0
