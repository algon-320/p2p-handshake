# p2p-handshake
Simple experimental protocol to establish a peer-to-peer UDP channel.

## Usage

1. on a public server host:
    ```
    $ # cargo run -- [--port <port>|-p <port>]
    $ cargo run -- -p 31415
    ```
2. on client hosts:
    ```
    $ # cargo run --example chat -- <server-address> <server-port> <pre-shared-key>
    $ cargo run --example chat -- 127.0.0.1 31415 "foo-2021-08-07"
    ```

## The Handshake Protocol
By the following protocol, `C1` and `C2` could establish a peer-to-peer UDP channel.

### Prerequisites

`C1` has to share a matching key with `C2` via another communitation channel in advance.

### Matching Request
First, `C1` requests `S` to send its public key by "Hello" message.

```txt
C1 ---> S: Hello
C1 <--- S: ServerPubKey(server_pk)
```

After `C1` receive `S`'s public key,
it generates a pair of key and derives a symmetric key from `C1`'s secret key and `S`'s public key.
After that, `C1` encrypts the digest (SHA-256) of the matching key by the symmetric key (AES-GCM 256-bit).

And then, `C1` makes a "MatchRequest" and keeps sending it to `S`
until it receives a "Matched" server message.

```txt
C1 ---> S: MatchRequest(client_pubkey, encrypted_matching_key)
(repeat sending the same request until S reports a "Matched" message.)
```

For each "MatchRequest", `S` decrypts the matching key
and checks if it has been already received from another client.

(`C2` does the same process as `C1` to send the matching request.)

### Matched message

After `S` receives "MatchRequest"s associated with the same matching key from `C1` and `C2`,
it sends a Matched message to `C1` and to `C2`.
```txt
C1 <--- S: Matched(encrypted C2 address)
C2 <--- S: Matched(encrypted C1 address)
```
