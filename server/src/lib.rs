//! Provides convenient wrappers.
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub fn establish_key() {
    let server_secret = EphemeralSecret::new(OsRng);
    let server_public = PublicKey::from(&server_secret);

    let client_public = get_client_pubkey();

    let shared = server_secret.diffie_hellman(&client_public);
}
