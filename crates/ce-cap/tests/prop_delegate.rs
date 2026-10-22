//! Property tests for [`ce_cap::delegate`] — the issuance-side companion to `authorize`.
//!
//! The unit tests in `src/delegate.rs` cover hand-picked cases. These generate *random* parent
//! abilities and *random* requested ability sets, then assert the delegation invariant an attacker
//! would probe: a delegated child can be authorized for an action **iff** the parent held it AND the
//! delegator requested it — never more — and the child can never outlive the parent. This is the
//! dual of `prop_attenuation.rs`: that one proves `authorize` REJECTS broadening; this proves the
//! `delegate` helper never PRODUCES broadening in the first place, so every app that spawns another
//! app with an attenuated cap is safe by construction.

use ce_cap::delegate::{Grant, delegate};
use ce_cap::{Caveats, Resource, SignedCapability, authorize};
use ce_identity::{Identity, NodeId};
use proptest::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn id() -> Identity {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-cap-prop-deleg-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn never_revoked(_: &NodeId, _: u64) -> bool {
    false
}

const ABILITIES: &[&str] = &["exec", "sync", "tunnel", "deploy", "kill"];

fn ability_idx_set() -> impl Strategy<Value = Vec<usize>> {
    proptest::collection::vec(0..ABILITIES.len(), 0..=ABILITIES.len())
        .prop_map(|mut v| {
            v.sort_unstable();
            v.dedup();
            v
        })
}

proptest! {
    /// For any parent ability set (non-empty) and any requested set, the delegated child authorizes
    /// for exactly `requested ∩ parent` and for nothing else in the ability universe.
    #[test]
    fn delegate_grants_exactly_the_intersection(
        parent_idx in ability_idx_set().prop_filter("non-empty parent", |v| !v.is_empty()),
        requested_idx in ability_idx_set(),
    ) {
        let root = id();
        let me = id();
        let child = id();

        let parent_abilities: Vec<String> = parent_idx.iter().map(|&i| ABILITIES[i].to_string()).collect();
        let held = vec![SignedCapability::issue(
            &root,
            me.node_id(),
            parent_abilities.clone(),
            Resource::Any,
            Caveats::default(),
            1,
            None,
        )];

        let requested: Vec<&str> = requested_idx.iter().map(|&i| ABILITIES[i]).collect();
        let expected: Vec<&str> = requested.iter().copied()
            .filter(|a| parent_abilities.iter().any(|p| p == a))
            .collect();

        let result = delegate(
            &held,
            &me,
            child.node_id(),
            &Grant { abilities: &requested, resource: None, ttl_secs: 3600, nonce: 2 },
            1_000,
        );

        if expected.is_empty() {
            // No shared ability → delegation must refuse rather than mint an empty-authority cap.
            prop_assert!(result.is_err());
        } else {
            let chain = result.unwrap();
            let roots = [root.node_id()];
            for &a in ABILITIES {
                let ok = authorize(&child.node_id(), &roots, &[], 1_500, &child.node_id(), a, &chain, &never_revoked).is_ok();
                prop_assert_eq!(ok, expected.contains(&a), "ability {} authorized={} but expected in-intersection={}", a, ok, expected.contains(&a));
            }
        }
    }

    /// A delegated child can never be authorized after the parent's expiry, for any requested ttl.
    #[test]
    fn delegate_never_outlives_parent(
        parent_exp in 1_100u64..5_000,
        ttl in 0u64..50_000,
    ) {
        let root = id();
        let me = id();
        let child = id();
        let held = vec![SignedCapability::issue(
            &root,
            me.node_id(),
            vec!["exec".to_string()],
            Resource::Any,
            Caveats { not_after: parent_exp, ..Default::default() },
            1,
            None,
        )];
        let chain = delegate(
            &held,
            &me,
            child.node_id(),
            &Grant { abilities: &["exec"], resource: None, ttl_secs: ttl, nonce: 2 },
            1_000,
        ).unwrap();
        // At any instant strictly after the parent's expiry, the child must be denied.
        let after = parent_exp + 1;
        let roots = [root.node_id()];
        prop_assert!(authorize(&child.node_id(), &roots, &[], after, &child.node_id(), "exec", &chain, &never_revoked).is_err());
    }
}
