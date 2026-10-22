# ce-cap

The permission system of ce-net. Every call to a ce-net service carries a capability: a signed chain that says who may do which action on which resource, until when. The service checks the chain itself before it does any work. Nothing is trusted because of where a request comes from.

Two crates:

- `ce-identity`: Ed25519 keys and node ids.
- `ce-cap`: capability chains. A holder can hand a narrower capability to someone else (attenuation), never a wider one.

A chain is accepted only if all seven checks pass: root (it starts at the resource owner's key), signature (every link is signed by the previous holder), time and revocation, resource, continuity, attenuation (each link is at most as strong as its parent) and audience (it was issued to the caller).

## Build and test

```sh
cargo test
```

## Check it yourself

`door-stranger-check` (published next to this repo) calls a running service as an anonymous caller, as a stranger with a fresh key and as the owner, and passes only when the first two are refused and the owner is accepted.

## License

AGPL-3.0, or a commercial license: see [LICENSING.md](LICENSING.md).
