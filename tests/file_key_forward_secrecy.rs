//! 前向保密（PFS）验证测试
//!
//! 在新版 PFS 模型中：
//! 1. 每次传输（包括剪贴板长连接与文件传输独立流）必须先执行基于临时 X25519 的会话协商；
//! 2. `MSG_FILE_OFFER` 与 `MSG_FILE_RESPONSE` 均采用协商出的临时 `pfs_session_key` 加密；
//! 3. 文件的分块密钥由 `derive_bulk_key(&pfs_session_key, &stream_salt)` 派生；
//! 4. 握手完成后，临时私钥立即经 `Zeroizing` 零化抹除；
//! 5. 即使攻击者抓取了完整网络流量并在未来窃取了双方的静态两两密钥（`long_term_key`），
//!    因缺少已销毁的临时私钥，依然无法逆推 ECDH 共享秘密，无法派生 `pfs_session_key`，
//!    无法解密 `FILE_OFFER`，亦无法计算 `bulk_key`，完美实现真正的前向保密。

use muclip_core::sync::crypto::{
    KEY_SIZE, KeyExchangeSession, compute_session_auth_tag, derive_bulk_key, derive_key,
    derive_pfs_session_key,
};
use muclip_core::sync::protocol::{
    FileOfferPayload, MSG_FILE_OFFER, decode_file_offer_packet, encode_file_offer_packet,
};

fn sample_offer(salt: [u8; 16]) -> FileOfferPayload {
    FileOfferPayload {
        transfer_id: "transfer-pfs-1".into(),
        from_device_id: "node-alice".into(),
        from_device_name: "Alice".into(),
        file_name: "confidential_payroll.pdf".into(),
        file_size: 1024 * 1024,
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        mime_type: "application/pdf".into(),
        stream_nonce: None,
        stream_salt: Some(salt),
        offset: 0,
        chunk_size: 128 * 1024,
        total_chunks: 8,
    }
}

/// 静态密钥即使事后被窃取，攻击者也绝对无法解密历史传输的 FILE_OFFER 或还原 bulk_key
#[test]
fn static_key_compromise_cannot_decrypt_historical_file_or_bulk_key() {
    // 双方配对派生的长期静态两两密钥（LTK）
    let long_term_key: [u8; KEY_SIZE] = derive_key("shared-pairing-secret-ltk", None).unwrap();

    // 1. 本次传输发生时：Alice 与 Bob 各自生成临时 X25519 密钥对
    let alice_ex = KeyExchangeSession::new();
    let alice_pk = alice_ex.public_key;

    let bob_ex = KeyExchangeSession::new();
    let bob_pk = bob_ex.public_key;

    let challenge = [0x5au8; 16];

    // 2. 双方通过 LTK 互相认证并派生会话临时 PFS 密钥
    let alice_shared = alice_ex.compute_shared_secret(&bob_pk);
    let alice_session_key = derive_pfs_session_key(&*alice_shared, &long_term_key, &challenge);

    let bob_shared = bob_ex.compute_shared_secret(&alice_pk);
    let bob_session_key = derive_pfs_session_key(&*bob_shared, &long_term_key, &challenge);

    assert_eq!(*alice_session_key, *bob_session_key);

    // 3. Alice 使用 PFS 会话密钥加密发送 FILE_OFFER
    let stream_salt: [u8; 16] = [0x77; 16];
    let packet =
        encode_file_offer_packet(&*alice_session_key, 1, &sample_offer(stream_salt)).unwrap();

    // Alice 派生本次文件的数据块 bulk_key
    let alice_bulk_key = derive_bulk_key(&*alice_session_key, &stream_salt);

    // 4. Bob 成功使用协商好的 PFS 密钥解密 FILE_OFFER 并恢复相同的 bulk_key
    let (header, bob_offer) = decode_file_offer_packet(&*bob_session_key, &packet).unwrap();
    assert_eq!(header.msg_type, MSG_FILE_OFFER);
    assert_eq!(bob_offer.stream_salt.unwrap(), stream_salt);
    let bob_bulk_key = derive_bulk_key(&*bob_session_key, &stream_salt);
    assert_eq!(alice_bulk_key, bob_bulk_key);

    // 5. 会话结束，Alice 与 Bob 的临时私钥 drop，内存被 Zeroizing 抹除
    drop(alice_ex);
    drop(bob_ex);
    drop(alice_shared);
    drop(bob_shared);

    // =========================================================================
    // 6. 场景模拟：未来攻击者窃取了长期静态密钥 long_term_key，并分析历史网络抓包
    //    网络抓包包含：alice_pk, bob_pk, challenge, 以及 packet（密文）
    // =========================================================================
    let leaked_static_key = long_term_key;

    // (A) 攻击者试图直接用泄露的长期密钥解开 FILE_OFFER：解密必须失败！
    let direct_decrypt_res = decode_file_offer_packet(&leaked_static_key, &packet);
    assert!(
        direct_decrypt_res.is_err(),
        "静态密钥泄露不应解密由 PFS 会话密钥加密的 FILE_OFFER"
    );

    // (B) 攻击者试图用抓包里的 public_key 伪造 ECDH shared_secret：
    //     攻击者没有 Alice 或 Bob 的临时私钥，无论用什么假私钥算出的 shared_secret，
    //     派生出的会话密钥都必然不同，无法解密包，也无法得到真正的 bulk_key。
    let attacker_fake_ex = KeyExchangeSession::new();
    let attacker_fake_shared = attacker_fake_ex.compute_shared_secret(&alice_pk);
    let attacker_derived_key =
        derive_pfs_session_key(&*attacker_fake_shared, &leaked_static_key, &challenge);

    let attacker_decrypt_res = decode_file_offer_packet(&*attacker_derived_key, &packet);
    assert!(
        attacker_decrypt_res.is_err(),
        "攻击者无临时私钥，即使拥有静态密钥也无法还原 PFS 会话密钥"
    );

    let attacker_bulk_key = derive_bulk_key(&*attacker_derived_key, &stream_salt);
    assert_ne!(
        attacker_bulk_key, alice_bulk_key,
        "攻击者无法还原文件的数据块 bulk_key，PFS 成立！"
    );
}

/// 相同双方、相同静态密钥，不同会话的 PFS 密钥与 bulk_key 完全独立隔离
#[test]
fn session_keys_and_bulk_keys_are_fresh_and_isolated_per_session() {
    let ltk: [u8; KEY_SIZE] = derive_key("mesh-ltk", None).unwrap();
    let salt = [0x99; 16];

    // 会话 1
    let s1_alice = KeyExchangeSession::new();
    let s1_bob = KeyExchangeSession::new();
    let s1_shared = s1_alice.compute_shared_secret(&s1_bob.public_key);
    let s1_key = derive_pfs_session_key(&*s1_shared, &ltk, &[1u8; 16]);
    let s1_bulk = derive_bulk_key(&*s1_key, &salt);

    // 会话 2
    let s2_alice = KeyExchangeSession::new();
    let s2_bob = KeyExchangeSession::new();
    let s2_shared = s2_alice.compute_shared_secret(&s2_bob.public_key);
    let s2_key = derive_pfs_session_key(&*s2_shared, &ltk, &[2u8; 16]);
    let s2_bulk = derive_bulk_key(&*s2_key, &salt);

    assert_ne!(
        *s1_key, *s2_key,
        "每次协商产生的 PFS 会话密钥必须随机且独立"
    );
    assert_ne!(
        s1_bulk, s2_bulk,
        "即使采用相同的 salt，不同会话的 bulk_key 亦完全隔离"
    );
}

/// 握手认证标签防假冒与篡改测试
#[test]
fn session_auth_tag_binds_identities_and_detects_tampering() {
    let ltk: [u8; KEY_SIZE] = derive_key("auth-tag-key", None).unwrap();
    let ex = KeyExchangeSession::new();
    let challenge = [0x33; 16];

    let tag = compute_session_auth_tag(
        &ltk,
        "device-alice",
        "device-bob",
        &ex.public_key,
        None,
        "initiator",
        &challenge,
    );

    // 篡改 initiator ID
    let tampered_initiator = compute_session_auth_tag(
        &ltk,
        "device-eve",
        "device-bob",
        &ex.public_key,
        None,
        "initiator",
        &challenge,
    );
    assert_ne!(tag, tampered_initiator);

    // 篡改 responder ID
    let tampered_responder = compute_session_auth_tag(
        &ltk,
        "device-alice",
        "device-charlie",
        &ex.public_key,
        None,
        "initiator",
        &challenge,
    );
    assert_ne!(tag, tampered_responder);

    // 篡改 role
    let tampered_role = compute_session_auth_tag(
        &ltk,
        "device-alice",
        "device-bob",
        &ex.public_key,
        None,
        "responder",
        &challenge,
    );
    assert_ne!(tag, tampered_role);
}
