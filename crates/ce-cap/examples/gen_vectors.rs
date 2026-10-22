//! Generate deterministic golden vectors for the capability wire format, so the TypeScript
//! `@ce-net/cap` port can assert — byte-for-byte — that it reproduces the Rust `ce-cap` output.
//!
//! Run: `cargo run -p ce-cap --example gen_vectors > ../ce-ts/cap/test/golden-vectors.json`
//! Identities are built from fixed single-byte seeds, so the output is fully reproducible. The shape
//! matches `ce-ts/cap/test/golden.test.ts`: each case carries the full `cap` fields (so the TS side
//! reconstructs the Capability and re-derives cap_bytes/cap_id/chain itself), plus the expected hexes.

use ce_cap::{cap_bytes, cap_id, Capability, Caveats, Resource, SignedCapability};
use ce_identity::Identity;
use serde_json::{json, Value};

fn id(seed: u8) -> Identity {
    Identity::from_secret_bytes(&[seed; 32])
}

fn resource_json(r: &Resource) -> Value {
    match r {
        Resource::Any => json!({ "kind": "any" }),
        Resource::Node(n) => json!({ "kind": "node", "node": hex::encode(n) }),
        Resource::Tag(t) => json!({ "kind": "tag", "tag": t }),
        Resource::AllOf(ts) => json!({ "kind": "allOf", "tags": ts }),
    }
}

fn caveats_json(c: &Caveats) -> Value {
    json!({
        "not_before": c.not_before,
        "not_after": c.not_after,
        "max_cpu": c.max_cpu,
        "max_mem_mb": c.max_mem_mb,
        "max_credits": c.max_credits,
        "allowed_ports": c.allowed_ports,
        "path_prefix": c.path_prefix,
    })
}

fn cap_json(c: &Capability) -> Value {
    json!({
        "issuer": hex::encode(c.issuer),
        "audience": hex::encode(c.audience),
        "abilities": c.abilities,
        "resource": resource_json(&c.resource),
        "caveats": caveats_json(&c.caveats),
        // String so u64::MAX survives JSON (JS numbers lose precision above 2^53).
        "nonce": c.nonce.to_string(),
        "parent": c.parent.map(hex::encode),
    })
}

fn main() {
    let root = id(0x11);
    let mid = id(0x22);
    let leaf = id(0x33);
    let target = id(0x44);

    // (name, abilities, resource, caveats, nonce) — every Resource variant, the Caveats Option
    // permutations, empty/multi abilities, and the u64::MAX nonce boundary. All issued by `root`.
    let specs: Vec<(&str, Vec<String>, Resource, Caveats, u64)> = vec![
        ("any_default", vec!["exec".into()], Resource::Any, Caveats::default(), 1),
        ("multi_ability", vec!["exec".into(), "sync".into(), "tunnel".into()], Resource::Any, Caveats::default(), 2),
        ("empty_abilities", vec![], Resource::Any, Caveats::default(), 3),
        ("resource_node", vec!["exec".into()], Resource::Node(target.node_id()), Caveats::default(), 4),
        ("resource_tag", vec!["exec".into()], Resource::Tag("gpu".into()), Caveats::default(), 5),
        ("resource_allof", vec!["exec".into()], Resource::AllOf(vec!["gpu".into(), "linux".into()]), Caveats::default(), 6),
        ("caveats_expiry", vec!["exec".into()], Resource::Any, Caveats { not_after: 1_000_000, ..Default::default() }, 7),
        (
            "caveats_full",
            vec!["tunnel".into()],
            Resource::Any,
            Caveats {
                not_before: 100,
                not_after: 2_000_000,
                max_cpu: Some(4),
                max_mem_mb: Some(512),
                max_credits: Some(1000),
                allowed_ports: Some(vec![22, 8080]),
                path_prefix: Some("/home/user".into()),
            },
            8,
        ),
        ("nonce_max", vec!["exec".into()], Resource::Any, Caveats::default(), u64::MAX),
    ];

    let cases: Vec<Value> = specs
        .into_iter()
        .map(|(name, abilities, resource, caveats, nonce)| {
            let signed = SignedCapability::issue(&root, leaf.node_id(), abilities, resource, caveats, nonce, None);
            json!({
                "name": name,
                "cap": cap_json(&signed.cap),
                "cap_bytes": hex::encode(cap_bytes(&signed.cap)),
                "cap_id": hex::encode(cap_id(&signed.cap)),
                "chain1": ce_cap::encode_chain(std::slice::from_ref(&signed)),
            })
        })
        .collect();

    // A continuity-correct two-link chain: root -> mid -> leaf.
    let c0 = SignedCapability::issue(&root, mid.node_id(), vec!["exec".into(), "sync".into()], Resource::Any, Caveats::default(), 100, None);
    let c1 = SignedCapability::issue(&mid, leaf.node_id(), vec!["exec".into()], Resource::Any, Caveats::default(), 101, Some(c0.id()));
    let chains = vec![json!({
        "name": "root->mid->leaf",
        "links": [cap_json(&c0.cap), cap_json(&c1.cap)],
        "link0_cap_id": hex::encode(c0.id()),
        "link1_cap_id": hex::encode(c1.id()),
        "chain2": ce_cap::encode_chain(&[c0.clone(), c1.clone()]),
    })];

    let out = json!({
        "version": "ce-cap-v1",
        "actors": {
            "root": { "seed_fill": 0x11, "node_id": root.node_id_hex() },
            "mid": { "seed_fill": 0x22, "node_id": mid.node_id_hex() },
            "leaf": { "seed_fill": 0x33, "node_id": leaf.node_id_hex() },
            "target": { "seed_fill": 0x44, "node_id": target.node_id_hex() },
        },
        "cases": cases,
        "chains": chains,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
