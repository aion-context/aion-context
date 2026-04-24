//! Cryptographic Test Vectors for AION v2
//!
//! This module contains comprehensive test vectors from RFCs and other standards
//! to ensure cryptographic correctness and interoperability.
//!
//! Test vectors are organized by:
//! - RFC 8032: Ed25519 signature scheme
//! - RFC 8439: ChaCha20-Poly1305 AEAD
//! - BLAKE3: Official test vectors
//! - Known-answer tests
//! - Edge cases

#![allow(clippy::expect_used)] // Test code needs `.expect()` for clarity
#![allow(clippy::unwrap_used)] // Test assertions can use unwrap
#![allow(clippy::indexing_slicing)] // Test code can safely index known data

use aion_context::crypto::{decrypt, encrypt, hash, keyed_hash, SigningKey, VerifyingKey};

// ============================================================================
// RFC 8032: Ed25519 Test Vectors
// ============================================================================

/// Test vector from RFC 8032 Section 7.1 (TEST 1)
#[test]
fn test_ed25519_rfc8032_test1() {
    // Secret key (32 bytes)
    let secret_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let secret_key = hex::decode(secret_key_hex).expect("Invalid hex");

    // Expected public key (32 bytes)
    let expected_pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let expected_pubkey = hex::decode(expected_pubkey_hex).expect("Invalid hex");

    // Message (empty)
    let message = b"";

    // Expected signature (64 bytes)
    let expected_sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    let expected_sig = hex::decode(expected_sig_hex).expect("Invalid hex");

    // Create signing key
    let secret_key_array: [u8; 32] = secret_key.try_into().expect("Wrong length");
    let signing_key =
        SigningKey::from_bytes(&secret_key_array).expect("Failed to create signing key");

    // Verify public key matches
    let verifying_key = signing_key.verifying_key();
    assert_eq!(
        &verifying_key.to_bytes()[..],
        &expected_pubkey[..],
        "Public key mismatch for RFC 8032 TEST 1"
    );

    // Sign message
    let signature = signing_key.sign(message);
    assert_eq!(
        &signature[..],
        &expected_sig[..],
        "Signature mismatch for RFC 8032 TEST 1"
    );

    // Verify signature
    assert!(
        verifying_key.verify(message, &signature).is_ok(),
        "Signature verification failed for RFC 8032 TEST 1"
    );
}

/// Test vector from RFC 8032 Section 7.1 (TEST 2)
#[test]
fn test_ed25519_rfc8032_test2() {
    let secret_key_hex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    let secret_key = hex::decode(secret_key_hex).expect("Invalid hex");

    let expected_pubkey_hex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    let expected_pubkey = hex::decode(expected_pubkey_hex).expect("Invalid hex");

    let message = hex::decode("72").expect("Invalid hex");

    let expected_sig_hex = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
    let expected_sig = hex::decode(expected_sig_hex).expect("Invalid hex");

    let secret_key_array: [u8; 32] = secret_key.try_into().expect("Wrong length");
    let signing_key =
        SigningKey::from_bytes(&secret_key_array).expect("Failed to create signing key");

    let verifying_key = signing_key.verifying_key();
    assert_eq!(&verifying_key.to_bytes()[..], &expected_pubkey[..]);

    let signature = signing_key.sign(&message);
    assert_eq!(&signature[..], &expected_sig[..]);
    assert!(verifying_key.verify(&message, &signature).is_ok());
}

/// Test vector from RFC 8032 Section 7.1 (TEST 3)
#[test]
fn test_ed25519_rfc8032_test3() {
    let secret_key_hex = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    let secret_key = hex::decode(secret_key_hex).expect("Invalid hex");

    let expected_pubkey_hex = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    let expected_pubkey = hex::decode(expected_pubkey_hex).expect("Invalid hex");

    let message = hex::decode("af82").expect("Invalid hex");

    let expected_sig_hex = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
    let expected_sig = hex::decode(expected_sig_hex).expect("Invalid hex");

    let secret_key_array: [u8; 32] = secret_key.try_into().expect("Wrong length");
    let signing_key =
        SigningKey::from_bytes(&secret_key_array).expect("Failed to create signing key");

    let verifying_key = signing_key.verifying_key();
    assert_eq!(&verifying_key.to_bytes()[..], &expected_pubkey[..]);

    let signature = signing_key.sign(&message);
    assert_eq!(&signature[..], &expected_sig[..]);
    assert!(verifying_key.verify(&message, &signature).is_ok());
}

/// Test vector from RFC 8032 Section 7.1 (TEST 1024)
/// 1023 byte message
#[test]
fn test_ed25519_rfc8032_1023_bytes() {
    let secret_key_hex = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";
    let secret_key = hex::decode(secret_key_hex).expect("Invalid hex");

    let expected_pubkey_hex = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e";
    let expected_pubkey = hex::decode(expected_pubkey_hex).expect("Invalid hex");

    // 1023 bytes: 0x08, 0xb8, 0xb2, 0xb7...
    let message_hex = "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0";
    let message = hex::decode(message_hex).expect("Invalid hex");

    let expected_sig_hex = "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03";
    let expected_sig = hex::decode(expected_sig_hex).expect("Invalid hex");

    let secret_key_array: [u8; 32] = secret_key.try_into().expect("Wrong length");
    let signing_key =
        SigningKey::from_bytes(&secret_key_array).expect("Failed to create signing key");

    let verifying_key = signing_key.verifying_key();
    assert_eq!(&verifying_key.to_bytes()[..], &expected_pubkey[..]);

    let signature = signing_key.sign(&message);
    assert_eq!(&signature[..], &expected_sig[..]);
    assert!(verifying_key.verify(&message, &signature).is_ok());
}

/// Test vector with longer message (SHA-ABC)
#[test]
fn test_ed25519_rfc8032_sha_abc() {
    let secret_key_hex = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
    let secret_key = hex::decode(secret_key_hex).expect("Invalid hex");

    let expected_pubkey_hex = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
    let expected_pubkey = hex::decode(expected_pubkey_hex).expect("Invalid hex");

    // Message: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    let message = hex::decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").expect("Invalid hex");

    let expected_sig_hex = "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704";
    let expected_sig = hex::decode(expected_sig_hex).expect("Invalid hex");

    let secret_key_array: [u8; 32] = secret_key.try_into().expect("Wrong length");
    let signing_key =
        SigningKey::from_bytes(&secret_key_array).expect("Failed to create signing key");

    let verifying_key = signing_key.verifying_key();
    assert_eq!(&verifying_key.to_bytes()[..], &expected_pubkey[..]);

    let signature = signing_key.sign(&message);
    assert_eq!(&signature[..], &expected_sig[..]);
    assert!(verifying_key.verify(&message, &signature).is_ok());
}

// ============================================================================
// RFC 8439: ChaCha20-Poly1305 Test Vectors
// ============================================================================

/// Test vector from RFC 8439 Appendix A.5 (ChaCha20-Poly1305 AEAD)
#[test]
fn test_chacha20_poly1305_rfc8439_aead() {
    // Key (256 bits = 32 bytes)
    let key_hex = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    let key = hex::decode(key_hex).expect("Invalid hex");
    let key: [u8; 32] = key.try_into().expect("Wrong length");

    // Nonce (96 bits = 12 bytes)
    let nonce_hex = "070000004041424344454647";
    let nonce = hex::decode(nonce_hex).expect("Invalid hex");
    let nonce: [u8; 12] = nonce.try_into().expect("Wrong length");

    // Plaintext
    let plaintext_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let plaintext = plaintext_str.as_bytes();

    // AAD (Additional Authenticated Data)
    let aad_hex = "50515253c0c1c2c3c4c5c6c7";
    let aad = hex::decode(aad_hex).expect("Invalid hex");

    // Encrypt
    let ciphertext = encrypt(&key, &nonce, plaintext, &aad).expect("Encryption failed");

    // Expected ciphertext + tag (from RFC 8439 Appendix A.5)
    let expected_ciphertext_hex = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691";
    let expected_ciphertext_tag = hex::decode(expected_ciphertext_hex).expect("Invalid hex");

    assert_eq!(
        ciphertext, expected_ciphertext_tag,
        "ChaCha20-Poly1305 encryption output mismatch"
    );

    // Decrypt
    let decrypted = decrypt(&key, &nonce, &ciphertext, &aad).expect("Decryption failed");

    assert_eq!(decrypted, plaintext, "ChaCha20-Poly1305 decryption failed");
}

/// Test ChaCha20-Poly1305 with empty plaintext
#[test]
fn test_chacha20_poly1305_empty_plaintext() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"";
    let aad = b"";

    let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("Encryption failed");

    // Should only contain the 16-byte authentication tag
    assert_eq!(ciphertext.len(), 16);

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

/// Test ChaCha20-Poly1305 with no AAD
#[test]
fn test_chacha20_poly1305_no_aad() {
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let plaintext = b"Test message without AAD";
    let aad = b"";

    let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("Encryption failed");

    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

// ============================================================================
// BLAKE3 Test Vectors
// ============================================================================

/// BLAKE3 test vector: empty input
#[test]
fn test_blake3_empty() {
    let input = b"";
    let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    let expected_hash = hex::decode(expected).expect("Invalid hex");

    let result = hash(input);
    assert_eq!(
        &result[..],
        &expected_hash[..],
        "BLAKE3 empty input mismatch"
    );
}

/// BLAKE3 test vector: single byte
#[test]
fn test_blake3_single_byte() {
    let input = b"\x00";
    let expected = "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213";
    let expected_hash = hex::decode(expected).expect("Invalid hex");

    let result = hash(input);
    assert_eq!(
        &result[..],
        &expected_hash[..],
        "BLAKE3 single byte mismatch"
    );
}

/// BLAKE3 test vector: "hello world"
#[test]
fn test_blake3_hello_world() {
    let input = b"hello world";
    let expected = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
    let expected_hash = hex::decode(expected).expect("Invalid hex");

    let result = hash(input);
    assert_eq!(
        &result[..],
        &expected_hash[..],
        "BLAKE3 'hello world' mismatch"
    );
}

/// BLAKE3 keyed hash test vector
#[test]
fn test_blake3_keyed_hash() {
    let key = [0u8; 32];
    let input = b"test message";

    let mac = keyed_hash(&key, input);
    assert_eq!(mac.len(), 32);

    // Same key and input should produce same MAC
    let mac2 = keyed_hash(&key, input);
    assert_eq!(mac, mac2);

    // Different key should produce different MAC
    let different_key = [1u8; 32];
    let mac3 = keyed_hash(&different_key, input);
    assert_ne!(mac, mac3);
}

// ============================================================================
// Known-Answer Tests
// ============================================================================

/// Test that signature generation is deterministic
#[test]
fn test_deterministic_signing() {
    let secret_key = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&secret_key).expect("Failed to create signing key");

    let message = b"deterministic test message";

    let sig1 = signing_key.sign(message);
    let sig2 = signing_key.sign(message);

    assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
}

/// Test signature with maximum length message
#[test]
fn test_signature_large_message() {
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // 1MB message
    let large_message = vec![0x42u8; 1024 * 1024];

    let signature = signing_key.sign(&large_message);
    assert!(verifying_key.verify(&large_message, &signature).is_ok());
}

/// Test encryption/decryption with maximum AAD length
#[test]
fn test_encryption_large_aad() {
    let key = [0xAAu8; 32];
    let nonce = [0xBBu8; 12];
    let plaintext = b"short message";

    // Large AAD (64KB)
    let large_aad = vec![0x99u8; 65536];

    let ciphertext =
        encrypt(&key, &nonce, plaintext, &large_aad).expect("Encryption with large AAD failed");

    let decrypted =
        decrypt(&key, &nonce, &ciphertext, &large_aad).expect("Decryption with large AAD failed");

    assert_eq!(decrypted, plaintext);
}

// ============================================================================
// Edge Cases
// ============================================================================

/// Test Ed25519 with all-zero secret key (should still work)
#[test]
fn test_ed25519_zero_secret() {
    let secret_key = [0u8; 32];
    let signing_key = SigningKey::from_bytes(&secret_key).expect("Should accept zero secret key");

    let message = b"test";
    let signature = signing_key.sign(message);

    let verifying_key = signing_key.verifying_key();
    assert!(verifying_key.verify(message, &signature).is_ok());
}

/// Test Ed25519 with all-ones secret key
#[test]
fn test_ed25519_ones_secret() {
    let secret_key = [0xFFu8; 32];
    let signing_key =
        SigningKey::from_bytes(&secret_key).expect("Should accept all-ones secret key");

    let message = b"test";
    let signature = signing_key.sign(message);

    let verifying_key = signing_key.verifying_key();
    assert!(verifying_key.verify(message, &signature).is_ok());
}

/// Test ChaCha20-Poly1305 with all-zero key and nonce
#[test]
fn test_chacha20_all_zeros() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"all zeros test";
    let aad = b"zero aad";

    let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("Encryption failed");

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

/// Test ChaCha20-Poly1305 with maximum values
#[test]
fn test_chacha20_max_values() {
    let key = [0xFFu8; 32];
    let nonce = [0xFFu8; 12];
    let plaintext = b"max values test";
    let aad = vec![0xFFu8; 1000];

    let ciphertext = encrypt(&key, &nonce, plaintext, &aad).expect("Encryption failed");

    let decrypted = decrypt(&key, &nonce, &ciphertext, &aad).expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

/// Test hash collision resistance (different inputs)
#[test]
fn test_blake3_collision_resistance() {
    let inputs: Vec<&[u8]> = vec![
        b"",
        b"a",
        b"aa",
        b"aaa",
        b"aaaa",
        b"aaaaa",
        b"test",
        b"test\x00",
        b"test\x00\x00",
    ];

    let mut hashes = Vec::new();
    for input in &inputs {
        hashes.push(hash(input));
    }

    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "Hash collision between inputs {:?} and {:?}",
                inputs[i], inputs[j]
            );
        }
    }
}

/// Test signature with null byte in message
#[test]
fn test_signature_null_bytes() {
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let messages = vec![
        b"\x00".as_slice(),
        b"\x00\x00\x00".as_slice(),
        b"test\x00message".as_slice(),
        b"\x00test".as_slice(),
        b"test\x00".as_slice(),
    ];

    for message in messages {
        let signature = signing_key.sign(message);
        assert!(
            verifying_key.verify(message, &signature).is_ok(),
            "Signature with null bytes failed"
        );
    }
}

// ============================================================================
// Interoperability Tests
// ============================================================================

/// Test that public key can be reconstructed correctly
#[test]
fn test_public_key_serialization_roundtrip() {
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Serialize
    let bytes = verifying_key.to_bytes();
    assert_eq!(bytes.len(), 32);

    // Deserialize
    let reconstructed =
        VerifyingKey::from_bytes(&bytes).expect("Failed to reconstruct verifying key");

    // Should match original
    assert_eq!(&verifying_key.to_bytes()[..], &reconstructed.to_bytes()[..]);

    // Should be able to verify signatures
    let message = b"interop test";
    let signature = signing_key.sign(message);
    assert!(reconstructed.verify(message, &signature).is_ok());
}

/// Test cross-verification between different instances
#[test]
fn test_cross_instance_verification() {
    let secret = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
        0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
        0xDE, 0xF0,
    ];

    // Create two independent instances from same secret
    let key1 = SigningKey::from_bytes(&secret).expect("Failed to create key1");
    let key2 = SigningKey::from_bytes(&secret).expect("Failed to create key2");

    let message = b"cross-verification test";

    // Sign with key1, verify with key2's public key
    let signature = key1.sign(message);
    let verifying_key2 = key2.verifying_key();
    assert!(verifying_key2.verify(message, &signature).is_ok());

    // Vice versa
    let signature2 = key2.sign(message);
    let verifying_key1 = key1.verifying_key();
    assert!(verifying_key1.verify(message, &signature2).is_ok());
}

/// Test that encrypted data from one instance can be decrypted by another
#[test]
fn test_encryption_interoperability() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let plaintext = b"interoperability test message";
    let aad = b"additional data";

    // Encrypt
    let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("Encryption failed");

    // Decrypt using same key/nonce (simulating different instance)
    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("Decryption failed");

    assert_eq!(decrypted, plaintext);

    // Verify determinism: encrypting again should produce same result
    let ciphertext2 = encrypt(&key, &nonce, plaintext, aad).expect("Second encryption failed");

    assert_eq!(
        ciphertext, ciphertext2,
        "Encryption should be deterministic"
    );
}

// ============================================================================
// Security Tests - Tampering Detection
// ============================================================================

/// Test that single-bit signature modifications are detected
#[test]
fn test_signature_single_bit_tampering() {
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let message = b"tamper test message";

    let valid_signature = signing_key.sign(message);

    // Test flipping each bit position in the signature
    for byte_idx in 0..64 {
        for bit_idx in 0..8 {
            let mut tampered_sig = valid_signature;
            tampered_sig[byte_idx] ^= 1 << bit_idx;

            let result = verifying_key.verify(message, &tampered_sig);
            assert!(
                result.is_err(),
                "Should detect bit flip at byte {} bit {}",
                byte_idx,
                bit_idx
            );
        }
    }
}

/// Test that single-bit message modifications are detected
#[test]
fn test_message_single_bit_tampering() {
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let message = b"original message for tampering test";

    let signature = signing_key.sign(message);

    // Test modifying each byte in the message
    for byte_idx in 0..message.len() {
        let mut tampered_message = message.to_vec();
        tampered_message[byte_idx] ^= 0x01; // Flip lowest bit

        let result = verifying_key.verify(&tampered_message, &signature);
        assert!(
            result.is_err(),
            "Should detect message modification at byte {}",
            byte_idx
        );
    }
}

/// Test ChaCha20-Poly1305 detects ciphertext tampering
#[test]
fn test_ciphertext_tampering_detection() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let plaintext = b"sensitive data";
    let aad = b"authenticated";

    let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("Encryption failed");

    // Try modifying each byte of ciphertext
    for byte_idx in 0..ciphertext.len() {
        let mut tampered = ciphertext.clone();
        tampered[byte_idx] ^= 0xFF;

        let result = decrypt(&key, &nonce, &tampered, aad);
        assert!(
            result.is_err(),
            "Should detect ciphertext tampering at byte {}",
            byte_idx
        );
    }
}

/// Test ChaCha20-Poly1305 detects AAD tampering
#[test]
fn test_aad_tampering_detection() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let plaintext = b"sensitive data";
    let aad = b"authenticated additional data";

    let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("Encryption failed");

    // Try modifying AAD
    let mut tampered_aad = aad.to_vec();
    tampered_aad[0] ^= 0x01;

    let result = decrypt(&key, &nonce, &ciphertext, &tampered_aad);
    assert!(result.is_err(), "Should detect AAD tampering");

    // Try empty AAD when original had AAD
    let result = decrypt(&key, &nonce, &ciphertext, b"");
    assert!(result.is_err(), "Should detect missing AAD");
}

/// Test wrong key detection
#[test]
fn test_wrong_key_detection() {
    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];
    let nonce = [0x24u8; 12];
    let plaintext = b"secret message";
    let aad = b"";

    let ciphertext = encrypt(&key1, &nonce, plaintext, aad).expect("Encryption failed");

    // Try decrypting with wrong key
    let result = decrypt(&key2, &nonce, &ciphertext, aad);
    assert!(result.is_err(), "Should reject wrong key");
}

/// Test wrong nonce detection
#[test]
fn test_wrong_nonce_detection() {
    let key = [0x42u8; 32];
    let nonce1 = [0x24u8; 12];
    let nonce2 = [0x25u8; 12];
    let plaintext = b"secret message";
    let aad = b"";

    let ciphertext = encrypt(&key, &nonce1, plaintext, aad).expect("Encryption failed");

    // Try decrypting with wrong nonce
    let result = decrypt(&key, &nonce2, &ciphertext, aad);
    assert!(result.is_err(), "Should reject wrong nonce");
}

/// Test truncated ciphertext detection
#[test]
fn test_truncated_ciphertext_detection() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let plaintext = b"message to truncate";
    let aad = b"";

    let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("Encryption failed");

    // Try truncated ciphertext (missing auth tag)
    for truncate_at in [1, 5, 10, 15, ciphertext.len() - 1] {
        if truncate_at < ciphertext.len() {
            let truncated = &ciphertext[..truncate_at];
            let result = decrypt(&key, &nonce, truncated, aad);
            assert!(
                result.is_err(),
                "Should detect truncation at {} bytes",
                truncate_at
            );
        }
    }
}

/// Test signature with wrong public key is rejected
#[test]
fn test_wrong_public_key_rejection() {
    let signing_key1 = SigningKey::generate();
    let signing_key2 = SigningKey::generate();

    let verifying_key2 = signing_key2.verifying_key();

    let message = b"signed by key 1";
    let signature = signing_key1.sign(message);

    // Try verifying with wrong public key
    let result = verifying_key2.verify(message, &signature);
    assert!(
        result.is_err(),
        "Should reject signature from different key"
    );
}

/// Test malformed public key rejection
#[test]
fn test_malformed_public_key_rejection() {
    // All zeros is not a valid public key
    let invalid_key = [0u8; 32];
    let result = VerifyingKey::from_bytes(&invalid_key);
    // May or may not error depending on implementation, but if it succeeds,
    // verification should fail
    if let Ok(vk) = result {
        let message = b"test";
        let fake_sig = [0u8; 64];
        assert!(vk.verify(message, &fake_sig).is_err());
    }
}

// ============================================================================
// Additional ChaCha20-Poly1305 Tests
// ============================================================================

/// Test with maximum plaintext we commonly use
#[test]
fn test_chacha20_poly1305_large_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    // 64KB plaintext
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(65536).collect();
    let aad = b"large plaintext test";

    let ciphertext = encrypt(&key, &nonce, &plaintext, aad).expect("Encryption failed");
    assert_eq!(ciphertext.len(), plaintext.len() + 16); // plaintext + 16-byte tag

    let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

// ============================================================================
// BLAKE3 Extended Test Vectors
// ============================================================================

/// BLAKE3 test with 64-byte input (one block)
#[test]
fn test_blake3_one_block() {
    let input: Vec<u8> = (0..64).collect();
    let result = hash(&input);

    // Hash should be deterministic
    let result2 = hash(&input);
    assert_eq!(result, result2);
    assert_eq!(result.len(), 32);
}

/// BLAKE3 test with 1024-byte input
#[test]
fn test_blake3_large_input() {
    let input: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let result = hash(&input);

    // Different length should produce different hash
    let shorter: Vec<u8> = (0..=255).cycle().take(1023).collect();
    let result_shorter = hash(&shorter);
    assert_ne!(result, result_shorter);
}

/// BLAKE3 keyed MAC with official test pattern
#[test]
fn test_blake3_keyed_mac_determinism() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    let input = b"test input for keyed hash";

    let mac1 = keyed_hash(&key, input);
    let mac2 = keyed_hash(&key, input);

    assert_eq!(mac1, mac2, "Keyed hash should be deterministic");

    // Different input should produce different MAC
    let mac3 = keyed_hash(&key, b"different input");
    assert_ne!(mac1, mac3);
}
