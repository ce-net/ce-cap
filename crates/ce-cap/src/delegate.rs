//! Attenuating delegation — the issuance-side companion to [`authorize`](crate::authorize).
//!
//! [`authorize`](crate::authorize) VERIFIES that a presented chain never broadens. This module
//! PRODUCES such a chain. Given a parent chain you hold and your signing [`Identity`], it mints a
//! child capability that is, by construction, no broader than the parent — fewer-or-equal abilities,
//! a resource subset, and caveats at least as tight — so `authorize` is guaranteed to accept it.
//!
//! It is the one correct way for an app to hand a *spawned child strictly weaker authority*: a fleet
//! orchestrator delegating to the sensor apps it installs, a spawner attenuating a cap down a spawn
//! tree, an adapter narrowing what it forwards. **Privilege can only ever shrink downward.** The
//! `replicator` fleet bootstrapper hand-rolled exactly this logic; this is that logic, generalized
//! (any ability set, optional resource narrowing) and unit-tested next to the verifier it mirrors.
//!
//! ```no_run
//! use ce_cap::delegate::{delegate, Grant};
//! use ce_cap::{decode_chain, Resource};
//! use ce_identity::Identity;
//! # fn now_secs() -> u64 { 0 }
//! # fn demo(me: &Identity, child: ce_identity::NodeId, held_token: &str) -> anyhow::Result<()> {
//! // I hold a broad cap. Hand a spawned climate-sensor app *only* `building:climate:read`,
//! // for one hour, scoped to the child node — nothing more.
//! let held = decode_chain(held_token)?;
//! let child_chain = delegate(&held, me, child, &Grant {
//!     abilities: &["building:climate:read"],
//!     resource: Some(Resource::Node(child)),
//!     ttl_secs: 3600,
//!     nonce: 1,
//! }, now_secs())?;
//! # let _ = child_chain; Ok(()) }
//! ```

use anyhow::{Result, bail};
use ce_identity::{Identity, NodeId};

use crate::{Caveats, Resource, SignedCapability, ability_covers};

/// What to delegate to a child. Every field can only *narrow* the parent — [`delegate`] enforces it.
pub struct Grant<'a> {
    /// Abilities the child should hold. Intersected with the parent's (see [`narrow_abilities`]) — a
    /// request for an ability the parent lacks is dropped, never granted. Delegation only ever
    /// removes authority.
    pub abilities: &'a [&'a str],
    /// Narrow the resource set — e.g. to the specific child (`Resource::Node(child)`). `None`
    /// inherits the parent's resource unchanged. A resource broader than the parent's is rejected.
    pub resource: Option<Resource>,
    /// Time-to-live in seconds for the child cap. The resulting expiry is clamped so the child can
    /// never outlive the parent: `min(parent.not_after, now + ttl_secs)`.
    pub ttl_secs: u64,
    /// Issuer-chosen nonce for the child link (unique per issuer; names it for revocation).
    pub nonce: u64,
}

/// Intersect the parent's abilities with the requested set: exactly the requested abilities the
/// parent *covers* (via [`ability_covers`]), in requested order, de-duplicated. Never returns an
/// ability the parent lacks, so the result is always a subset of the parent's authority. A parent
/// holding `app:spawn:*` therefore grants a requested concrete `app:spawn:wasm`; a parent holding
/// only `app:spawn:wasm` never grants a broader `app:spawn:*`.
pub fn narrow_abilities(parent: &[String], requested: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for a in requested {
        if parent.iter().any(|p| ability_covers(p, a)) && !out.iter().any(|o| o == a) {
            out.push((*a).to_string());
        }
    }
    out
}

/// Tighten a parent's caveats for a child: expiry clamped to `min(parent, now + ttl_secs)` (a child
/// may never outlive its parent), every other ceiling (`not_before`, `max_*`, ports, path prefix)
/// inherited unchanged. The result is always [`Caveats::is_narrower_or_equal`] to the parent.
pub fn attenuate_caveats(parent: &Caveats, now: u64, ttl_secs: u64) -> Caveats {
    let want = now.saturating_add(ttl_secs);
    let not_after = match parent.not_after {
        0 => want,        // parent never expires → the child still gets a finite lifetime
        p => p.min(want), // never outlive the parent
    };
    Caveats { not_after, ..parent.clone() }
}

/// Extend `parent_chain` with a child capability delegated by `holder` to `child`, per `grant`.
///
/// Returns the full chain `[..parent_chain, child]`, which [`authorize`](crate::authorize) accepts
/// for `child` (rooted at the same root as the parent). The child is no broader than the parent on
/// every axis, so verification is guaranteed to pass.
///
/// Errors if the chain is empty, if `holder` is not the audience of the chain's last link (only the
/// current holder may delegate onward), if the grant intersects to no abilities, or if the requested
/// resource is broader than the parent's.
pub fn delegate(
    parent_chain: &[SignedCapability],
    holder: &Identity,
    child: NodeId,
    grant: &Grant,
    now: u64,
) -> Result<Vec<SignedCapability>> {
    let Some(parent) = parent_chain.last() else {
        bail!("cannot delegate: empty capability chain");
    };
    if parent.cap.audience != holder.node_id() {
        bail!("cannot delegate: the signing identity is not the audience of the held capability");
    }
    let abilities = narrow_abilities(&parent.cap.abilities, grant.abilities);
    if abilities.is_empty() {
        bail!(
            "cannot delegate: the parent holds none of the requested abilities {:?}",
            grant.abilities
        );
    }
    let resource = match &grant.resource {
        None => parent.cap.resource.clone(),
        Some(r) => {
            if !r.is_subset_of(&parent.cap.resource) {
                bail!("cannot delegate: requested resource is broader than the parent's");
            }
            r.clone()
        }
    };
    let caveats = attenuate_caveats(&parent.cap.caveats, now, grant.ttl_secs);
    let child_cap = SignedCapability::issue(
        holder,
        child,
        abilities,
        resource,
        caveats,
        grant.nonce,
        Some(parent.id()),
    );
    let mut chain = parent_chain.to_vec();
    chain.push(child_cap);
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorize;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn id(tag: &str) -> Identity {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ce-cap-deleg-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn never_revoked(_: &NodeId, _: u64) -> bool {
        false
    }

    /// A root (self-issued) cap held by `holder`, granting `abilities` on `Resource::Any`, never
    /// expiring — the "I hold broad authority" starting point an orchestrator would have.
    fn root_cap(root: &Identity, holder: &Identity, abilities: &[&str]) -> Vec<SignedCapability> {
        vec![SignedCapability::issue(
            root,
            holder.node_id(),
            abilities.iter().map(|s| s.to_string()).collect(),
            Resource::Any,
            Caveats::default(),
            1,
            None,
        )]
    }

    #[test]
    fn narrow_abilities_intersects_and_dedups() {
        let parent = vec!["exec".to_string(), "sync".to_string(), "spawn".to_string()];
        // requested subset preserved in requested order
        assert_eq!(narrow_abilities(&parent, &["sync", "exec"]), vec!["sync", "exec"]);
        // an ability the parent lacks is dropped
        assert_eq!(narrow_abilities(&parent, &["exec", "tunnel"]), vec!["exec"]);
        // duplicates in the request collapse
        assert_eq!(narrow_abilities(&parent, &["exec", "exec"]), vec!["exec"]);
        // nothing in common → empty
        assert!(narrow_abilities(&parent, &["tunnel"]).is_empty());
    }

    #[test]
    fn narrow_abilities_expands_a_parent_wildcard_to_concrete_tiers() {
        // A parent holding the wildcard grants any concrete tier requested under it…
        let parent = vec!["app:spawn:*".to_string()];
        assert_eq!(
            narrow_abilities(&parent, &["app:spawn:wasm", "app:spawn:native"]),
            vec!["app:spawn:wasm", "app:spawn:native"]
        );
        // …but a concrete-tier parent never yields a broader wildcard child.
        let narrow = vec!["app:spawn:wasm".to_string()];
        assert!(narrow_abilities(&narrow, &["app:spawn:*"]).is_empty());
        // and a concrete-tier parent grants only its own tier.
        assert_eq!(narrow_abilities(&narrow, &["app:spawn:wasm"]), vec!["app:spawn:wasm"]);
        assert!(narrow_abilities(&narrow, &["app:spawn:native"]).is_empty());
    }

    #[test]
    fn delegate_narrows_a_wildcard_holder_to_a_concrete_tier() {
        let root = id("root");
        let me = id("me"); // orchestrator holding the broad spawn wildcard
        let child = id("child");
        let held = root_cap(&root, &me, &["app:spawn:*"]);
        // Hand the child ONLY the wasm spawn tier.
        let chain = delegate(
            &held,
            &me,
            child.node_id(),
            &Grant { abilities: &["app:spawn:wasm"], resource: None, ttl_secs: 3600, nonce: 9 },
            1_000,
        )
        .unwrap();
        assert!(authorize(&child.node_id(), &[root.node_id()], &[], 1_500, &child.node_id(), "app:spawn:wasm", &chain, &never_revoked).is_ok());
        // The child got wasm, not native — the wildcard was narrowed to a single tier.
        assert!(authorize(&child.node_id(), &[root.node_id()], &[], 1_500, &child.node_id(), "app:spawn:native", &chain, &never_revoked).is_err());
    }

    #[test]
    fn attenuate_clamps_expiry_but_inherits_ceilings() {
        // Parent never expires: the child gets now+ttl.
        let inf = Caveats { max_cpu: Some(4), ..Default::default() };
        let c = attenuate_caveats(&inf, 1_000, 60);
        assert_eq!(c.not_after, 1_060);
        assert_eq!(c.max_cpu, Some(4), "ceilings inherited");

        // Parent expires sooner than now+ttl: child clamped to the parent.
        let finite = Caveats { not_after: 1_020, ..Default::default() };
        assert_eq!(attenuate_caveats(&finite, 1_000, 60).not_after, 1_020);

        // Parent expires later than now+ttl: child gets the shorter now+ttl.
        let later = Caveats { not_after: 9_999, ..Default::default() };
        assert_eq!(attenuate_caveats(&later, 1_000, 60).not_after, 1_060);
    }

    #[test]
    fn delegated_child_authorizes_for_exactly_its_abilities() {
        let root = id("root");
        let me = id("me"); // the orchestrator: holds a broad cap
        let child = id("child"); // a spawned app
        let held = root_cap(&root, &me, &["exec", "sync", "spawn"]);

        // Hand the child only `sync`, scoped to the child node, for an hour.
        let chain = delegate(
            &held,
            &me,
            child.node_id(),
            &Grant { abilities: &["sync"], resource: Some(Resource::Node(child.node_id())), ttl_secs: 3600, nonce: 2 },
            1_000,
        )
        .unwrap();

        // The node the child runs on (root is its accepted authority) grants `sync`…
        assert!(
            authorize(&child.node_id(), &[root.node_id()], &[], 1_500, &child.node_id(), "sync", &chain, &never_revoked)
                .is_ok()
        );
        // …but NOT `exec`, even though the orchestrator held it — authority only shrinks.
        assert!(
            authorize(&child.node_id(), &[root.node_id()], &[], 1_500, &child.node_id(), "exec", &chain, &never_revoked)
                .is_err()
        );
    }

    #[test]
    fn only_the_holder_may_delegate() {
        let root = id("root");
        let me = id("me");
        let impostor = id("impostor");
        let child = id("child");
        let held = root_cap(&root, &me, &["exec"]);
        // `impostor` is not the audience of the held cap → cannot delegate it.
        let err = delegate(
            &held,
            &impostor,
            child.node_id(),
            &Grant { abilities: &["exec"], resource: None, ttl_secs: 60, nonce: 3 },
            1_000,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not the audience"));
    }

    #[test]
    fn empty_intersection_is_refused() {
        let root = id("root");
        let me = id("me");
        let child = id("child");
        let held = root_cap(&root, &me, &["exec"]);
        let err = delegate(
            &held,
            &me,
            child.node_id(),
            &Grant { abilities: &["tunnel"], resource: None, ttl_secs: 60, nonce: 4 },
            1_000,
        )
        .unwrap_err();
        assert!(err.to_string().contains("none of the requested abilities"));
    }

    #[test]
    fn resource_broadening_is_refused() {
        let root = id("root");
        let me = id("me");
        let child = id("child");
        // Held cap is scoped to tag `gpu`; try to broaden the child to `Any`.
        let held = vec![SignedCapability::issue(
            &root,
            me.node_id(),
            vec!["exec".to_string()],
            Resource::Tag("gpu".into()),
            Caveats::default(),
            1,
            None,
        )];
        let err = delegate(
            &held,
            &me,
            child.node_id(),
            &Grant { abilities: &["exec"], resource: Some(Resource::Any), ttl_secs: 60, nonce: 5 },
            1_000,
        )
        .unwrap_err();
        assert!(err.to_string().contains("broader than the parent"));
    }

    #[test]
    fn child_cannot_outlive_parent() {
        let root = id("root");
        let me = id("me");
        let child = id("child");
        // Parent expires at 1_500; request a 10_000s ttl → child must be clamped to 1_500.
        let held = vec![SignedCapability::issue(
            &root,
            me.node_id(),
            vec!["exec".to_string()],
            Resource::Any,
            Caveats { not_after: 1_500, ..Default::default() },
            1,
            None,
        )];
        let chain = delegate(
            &held,
            &me,
            child.node_id(),
            &Grant { abilities: &["exec"], resource: None, ttl_secs: 10_000, nonce: 6 },
            1_000,
        )
        .unwrap();
        assert_eq!(chain.last().unwrap().cap.caveats.not_after, 1_500);
        // Verified end-to-end: valid before the parent's expiry, denied after it.
        assert!(authorize(&child.node_id(), &[root.node_id()], &[], 1_400, &child.node_id(), "exec", &chain, &never_revoked).is_ok());
        assert!(authorize(&child.node_id(), &[root.node_id()], &[], 1_600, &child.node_id(), "exec", &chain, &never_revoked).is_err());
    }

    #[test]
    fn multi_hop_spawn_tree_only_ever_narrows() {
        // orchestrator -> mid app -> leaf app: each hop drops an ability. Models a spawn tree where
        // every spawn attenuates its parent's cap.
        let root = id("root");
        let orch = id("orch");
        let mid = id("mid");
        let leaf = id("leaf");
        let held = root_cap(&root, &orch, &["exec", "sync", "spawn"]);

        let to_mid = delegate(
            &held,
            &orch,
            mid.node_id(),
            &Grant { abilities: &["sync", "spawn"], resource: None, ttl_secs: 3600, nonce: 2 },
            1_000,
        )
        .unwrap();
        let to_leaf = delegate(
            &to_mid,
            &mid,
            leaf.node_id(),
            &Grant { abilities: &["sync"], resource: None, ttl_secs: 3600, nonce: 3 },
            1_000,
        )
        .unwrap();

        assert_eq!(to_leaf.len(), 3, "root -> mid -> leaf");
        // The leaf can `sync` but never `spawn` or `exec`, no matter what the root held.
        assert!(authorize(&leaf.node_id(), &[root.node_id()], &[], 1_500, &leaf.node_id(), "sync", &to_leaf, &never_revoked).is_ok());
        assert!(authorize(&leaf.node_id(), &[root.node_id()], &[], 1_500, &leaf.node_id(), "spawn", &to_leaf, &never_revoked).is_err());
        assert!(authorize(&leaf.node_id(), &[root.node_id()], &[], 1_500, &leaf.node_id(), "exec", &to_leaf, &never_revoked).is_err());
    }
}
