//! Encrypted media for DM image attachments.
//!
//! Uses Web Crypto API (SubtleCrypto) for AES-256-GCM encryption of image data,
//! with the AES key encrypted for the recipient via NIP-44 shared secret.
//! This ensures images in DMs are end-to-end encrypted.

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::Blob;

/// An encrypted image payload for DM attachments.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedImage {
    /// AES-GCM ciphertext of the image data.
    pub ciphertext: Vec<u8>,
    /// 12-byte IV/nonce for AES-GCM.
    pub iv: Vec<u8>,
    /// The random AES-256 key, encrypted with NIP-44 for the recipient.
    pub encrypted_key: String,
    /// Original MIME type (e.g. "image/jpeg").
    pub content_type: String,
}

impl EncryptedImage {
    /// Deserialize from a JSON tag value.
    pub fn from_tag_value(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Deserialize: {e}"))
    }
}

/// Decrypt a DM image that was encrypted with the encrypt_image_for_dm flow.
///
/// 1. Decrypts the AES key using NIP-44 (recipient_sk + sender_pk)
/// 2. Imports the AES key into Web Crypto
/// 3. AES-GCM decrypts the image ciphertext
/// 4. Returns a Blob with the original content type
pub async fn decrypt_dm_image(
    encrypted: &EncryptedImage,
    sender_pubkey: &str,
    recipient_privkey: &[u8; 32],
) -> Result<Blob, String> {
    // Decrypt AES key via NIP-44
    let sender_pk_bytes: [u8; 32] = hex::decode(sender_pubkey)
        .map_err(|e| format!("Invalid sender pubkey: {e}"))?
        .try_into()
        .map_err(|_| "Sender pubkey must be 32 bytes".to_string())?;

    let key_hex =
        nostr_core::nip44_decrypt(recipient_privkey, &sender_pk_bytes, &encrypted.encrypted_key)
            .map_err(|e| format!("NIP-44 decrypt: {e}"))?;

    let raw_key_bytes =
        hex::decode(&key_hex).map_err(|e| format!("Invalid key hex: {e}"))?;

    // Import AES key into Web Crypto
    let crypto = web_sys::window()
        .ok_or("No window")?
        .crypto()
        .map_err(|e| format!("No crypto: {e:?}"))?;
    let subtle = crypto.subtle();

    let key_data = js_sys::Uint8Array::from(raw_key_bytes.as_slice());
    let import_algo = js_sys::Object::new();
    js_sys::Reflect::set(&import_algo, &"name".into(), &"AES-GCM".into())
        .map_err(|e| format!("{e:?}"))?;

    let key_usages = js_sys::Array::new();
    key_usages.push(&"decrypt".into());

    let crypto_key = JsFuture::from(
        subtle
            .import_key_with_object("raw", &key_data, &import_algo, false, &key_usages)
            .map_err(|e| format!("importKey: {e:?}"))?,
    )
    .await
    .map_err(|e| format!("importKey await: {e:?}"))?;

    let crypto_key: web_sys::CryptoKey = crypto_key
        .dyn_into()
        .map_err(|_| "Not a CryptoKey".to_string())?;

    // AES-GCM decrypt
    let dec_algo = js_sys::Object::new();
    js_sys::Reflect::set(&dec_algo, &"name".into(), &"AES-GCM".into())
        .map_err(|e| format!("{e:?}"))?;
    let iv_array = js_sys::Uint8Array::from(encrypted.iv.as_slice());
    js_sys::Reflect::set(&dec_algo, &"iv".into(), &iv_array.into())
        .map_err(|e| format!("{e:?}"))?;

    let ct_array = js_sys::Uint8Array::from(encrypted.ciphertext.as_slice());
    let pt_val = JsFuture::from(
        subtle
            .decrypt_with_object_and_buffer_source(&dec_algo, &crypto_key, &ct_array)
            .map_err(|e| format!("decrypt: {e:?}"))?,
    )
    .await
    .map_err(|e| format!("decrypt await: {e:?}"))?;

    let pt_bytes = js_sys::Uint8Array::new(&pt_val);

    // Create Blob with original content type
    let parts = js_sys::Array::new();
    parts.push(&pt_bytes.into());

    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type(&encrypted.content_type);

    Blob::new_with_u8_array_sequence_and_options(&parts, &opts)
        .map_err(|e| format!("Blob creation: {e:?}"))
}
