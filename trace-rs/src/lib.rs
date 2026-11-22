//! runopsy-trace library (finding O17): every module is exposed so the
//! integration tests decode with the *production* schema and framing, not a
//! mirror of it. The `runopsy-trace` binary is a thin shell over this crate.
//!
//! Wire contract mirrored with `internal/trace` (Go): change both together
//! (docs/tracing/protocol.md).

pub mod backend;
pub mod framing;
pub mod nix;
pub mod proc_connector;
pub mod schema;
pub mod transport;
pub mod watch;

// the eBPF backend module graph compiles on linux only (contract §2.2); on
// other platforms `backend::select_backend()` refuses before any of this
// is referenced.
#[cfg(target_os = "linux")]
pub mod ebpf_backend;
#[cfg(target_os = "linux")]
pub mod libbpf;

pub use backend::{BoundedSender, LossCounters, TraceBackend};
pub use framing::{Frame, Framer, ProtocolError, ReadOutcome};
pub use schema::{
    Capabilities, Control, ControlAck, Handshake, Health, Loss, TraceEvent, PROTOCOL_VERSION,
    PROTOCOL_VERSION_MIN, SCHEMA_VERSION,
};
pub use transport::{Tracer, QUEUE_DEPTH, TRACER_VERSION};
pub use watch::WatchSet;
