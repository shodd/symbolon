//! `symbolon`: command-line client, also used to exercise the protocol end to end.

fn main() {
    println!(
        "symbolon {} (protocol v{})",
        env!("CARGO_PKG_VERSION"),
        symbolon_core::protocol::PROTOCOL_VERSION
    );
}
