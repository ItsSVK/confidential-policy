//! Cross-language test vectors. Any other implementation of [`crate::entries_hash`] or [`crate::run_approval_message`]
//! (`web/src/lib/chain/run-approval.ts`, a TS package later) must reproduce these exactly. The expected values were produced by the vault's
//! original in-program implementation (anchor `Pubkey` display, `solana-sha256-hasher`), not written by hand.

use crate::RunEntryBytes;

pub struct EntriesHashVector {
    pub entries: &'static [RunEntryBytes],
    pub hash_hex: &'static str,
}

pub struct ApprovalMessageVector {
    pub vault: [u8; 32],
    pub run_id: u64,
    pub operator: [u8; 32],
    pub expires_at: i64,
    pub entries: &'static [RunEntryBytes],
    pub message: &'static str,
}

const fn entry(recipient: u8, c_lo: u8, c_hi: u8) -> RunEntryBytes {
    RunEntryBytes { recipient: [recipient; 32], c_lo: [c_lo; 32], c_hi: [c_hi; 32] }
}

/// The two entries used by the pinned approval-message test (and by `web/src/lib/chain/run-approval.test.ts`).
pub const TWO_ENTRIES: [RunEntryBytes; 2] = [entry(3, 4, 5), entry(6, 7, 8)];

pub const ENTRIES_HASH_VECTORS: &[EntriesHashVector] = &[
    // No entries: SHA-256 of the empty string. A real run always has 1..=100 entries; this pins the hash construction.
    EntriesHashVector { entries: &[], hash_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    EntriesHashVector { entries: &[entry(0x11, 0x22, 0x33)], hash_hex: "8cfa0e55b092114ec1d274d633d317f8dbce497239ae76722c0add142278ff5e" },
    EntriesHashVector { entries: &TWO_ENTRIES, hash_hex: "884bba2af2bd6310e37ba49b577d5365274a6f0b64a83387ec6043e2cea146e5" },
];

/// Keys with leading zero bytes, a large run id and a negative expiry exercise the base58 and integer formatting.
pub const APPROVAL_MESSAGE_VECTOR: ApprovalMessageVector = ApprovalMessageVector {
    vault: LEADING_ZERO_KEY,
    run_id: u64::MAX,
    operator: [0xFF; 32],
    expires_at: -1,
    entries: &[entry(0x11, 0x22, 0x33)],
    message: "Cipherpay: approve payroll run\nvault: 11QP3ud5nZLYwFWBQanmyzo9YHKh3YRTnPfCEHnGAJ\nrun: 18446744073709551615\noperator: JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG\nexpires: -1\nentries: 1\nhash: 8cfa0e55b092114ec1d274d633d317f8dbce497239ae76722c0add142278ff5e",
};

const LEADING_ZERO_KEY: [u8; 32] = {
    let mut key = [0u8; 32];
    let mut i = 2;
    while i < 32 {
        key[i] = i as u8;
        i += 1;
    }
    key
};
