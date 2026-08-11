//! The active perimeter (P3): store footprints and kick attackers away.
//!
//! - [`LedgerIntrusionSink`] — an append-only, **tamper-evident** intrusion
//!   ledger (hash-chained: each entry commits to the previous), implementing
//!   `IntrusionSink`.
//! - [`EscalatingThreatResponder`] — classify a caller and escalate
//!   allow → tarpit → block, keyed on a fingerprint (JA3/JA4, cert serial, ASN,
//!   behavior) rather than IP alone, so a floating IP cannot dodge the ban.
//!   Implements `ThreatResponder` and backs a mesh-wide blocklist.

mod ledger;
mod responder;

pub use ledger::{LedgerEntry, LedgerIntrusionSink};
pub use responder::EscalatingThreatResponder;
