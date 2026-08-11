//! Escalating threat responder + mesh-wide blocklist. Keyed on an opaque
//! *fingerprint* (JA3/JA4, cert serial, ASN, behavioral signature) rather than
//! IP alone, so a floating IP can't dodge the ban.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use vault_ports::{ThreatDecision, ThreatResponder};

struct Inner {
    strikes: HashMap<String, u32>,
    blocked: HashSet<String>,
}

pub struct EscalatingThreatResponder {
    inner: Mutex<Inner>,
    /// Strike count at/after which a fingerprint is permanently blocked.
    block_after: u32,
}

impl EscalatingThreatResponder {
    pub fn new(block_after: u32) -> Self {
        Self {
            inner: Mutex::new(Inner {
                strikes: HashMap::new(),
                blocked: HashSet::new(),
            }),
            block_after: block_after.max(1),
        }
    }

    /// Sensible default: block on the 3rd strike.
    pub fn with_defaults() -> Self {
        Self::new(3)
    }

    /// Whether a fingerprint is on the (mesh-wide) blocklist — checked at the
    /// earliest layer so a blocked caller never reaches app logic.
    pub fn is_blocked(&self, fingerprint: &str) -> bool {
        self.inner.lock().unwrap().blocked.contains(fingerprint)
    }

    pub fn blocked(&self) -> Vec<String> {
        self.inner.lock().unwrap().blocked.iter().cloned().collect()
    }
}

impl ThreatResponder for EscalatingThreatResponder {
    fn assess(&self, signal_fingerprint: &str, _attack_class: &str) -> ThreatDecision {
        let mut inner = self.inner.lock().unwrap();
        if inner.blocked.contains(signal_fingerprint) {
            return ThreatDecision::Block;
        }
        let strikes = inner
            .strikes
            .entry(signal_fingerprint.to_string())
            .or_insert(0);
        *strikes += 1;
        if *strikes >= self.block_after {
            inner.blocked.insert(signal_fingerprint.to_string());
            ThreatDecision::Block
        } else {
            // First strikes: tarpit (slow-drip) to waste the attacker's time.
            ThreatDecision::Tarpit
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalates_tarpit_then_permanent_block() {
        let r = EscalatingThreatResponder::new(3);
        let fp = "ja3:abcd|asn:64500";
        assert_eq!(r.assess(fp, "probe"), ThreatDecision::Tarpit);
        assert_eq!(r.assess(fp, "probe"), ThreatDecision::Tarpit);
        assert_eq!(r.assess(fp, "probe"), ThreatDecision::Block);
        assert!(r.is_blocked(fp));
        // Stays blocked afterwards.
        assert_eq!(r.assess(fp, "probe"), ThreatDecision::Block);
    }

    #[test]
    fn distinct_fingerprints_are_independent() {
        let r = EscalatingThreatResponder::new(2);
        assert_eq!(r.assess("a", "x"), ThreatDecision::Tarpit);
        assert_eq!(r.assess("b", "x"), ThreatDecision::Tarpit);
        assert!(!r.is_blocked("a"));
        assert!(!r.is_blocked("b"));
    }
}
