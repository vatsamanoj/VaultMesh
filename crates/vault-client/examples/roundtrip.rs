//! App-agnostic proof (see `docs/ROADMAP.md`): register, get a namespace + a
//! capability token, back up arbitrary bytes, restore them, and confirm they
//! are byte-identical — all through the Contract, with no VaultMesh-internal
//! coupling.
//!
//! Run the two services first, then this example:
//! ```sh
//! cargo run -p coordinator      # 127.0.0.1:8787
//! cargo run -p node-agent       # 127.0.0.1:8790
//! cargo run -p vault-client --example roundtrip
//! ```

use vault_client::{ContentCipher, CoordinatorClient, NodeAgentClient};
use vault_domain::{ErasureParams, Operation, Quota, RetentionPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let coordinator =
        std::env::var("VAULT_COORDINATOR_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".into());
    let sidecar =
        std::env::var("VAULT_SIDECAR_URL").unwrap_or_else(|_| "http://127.0.0.1:8790".into());

    let control = CoordinatorClient::new(coordinator);
    let data = NodeAgentClient::new(sidecar);

    // 1. Onboard an app and allocate an opaque namespace.
    let app = control
        .register_app(
            "demo-app",
            Quota::new(1 << 30, 10_000),
            RetentionPolicy::new(3, 30),
            ErasureParams::recommended(), // P1: Reed-Solomon 4-of-6
        )
        .await?;
    println!("registered app: {}", app.app_id);
    let ns = control.create_namespace(&app.app_id).await?.namespace_id;
    println!("namespace: {ns}");

    // 2. Encrypt client-side. VaultMesh never sees this key or the plaintext.
    let secret = b"an-app-held-secret-derived-per-owner";
    let cipher = ContentCipher::for_namespace(secret, ns.as_str());
    let payload = b"arbitrary bytes: this could be any app's .lfbak container";
    let ciphertext = cipher.encrypt(payload)?;

    // 3. Back up (single-op capability token).
    let put_tok = control
        .issue_capability(&app.app_id, &ns, Operation::Put, 300)
        .await?;
    let blob_id = data.put(&ns, &put_tok, &ciphertext).await?;
    println!("stored blob: {blob_id}");

    // 4. Restore and decrypt.
    let get_tok = control
        .issue_capability(&app.app_id, &ns, Operation::Get, 300)
        .await?;
    let restored_ct = data.get(&ns, &get_tok, &blob_id).await?;
    let restored = cipher.decrypt(&restored_ct)?;

    assert_eq!(restored, payload, "restore must be byte-identical");
    println!("restore OK — byte-identical ({} bytes)", restored.len());
    Ok(())
}
