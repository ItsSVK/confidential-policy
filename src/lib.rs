//! Confidential policy checks for programs that pay out of Token-2022 confidential balances.
//!
//! Pure functions over bytes: no accounts, no `Context`, no Anchor and no `solana-program` types, so any program (Anchor or
//! native) can compile it in and it can be unit-tested without a validator. It protects only programs that call it.
//!
//! One policy so far, the **exact payroll run**: an admin approves a list of `(recipient, hidden amount)` entries once, and a
//! helper may then pay only those recipients, only those amounts, each entry once.
//!
//! The binding that makes this work: the first 32 bytes of an ElGamal ciphertext are its Pedersen commitment. Token-2022
//! requires the auditor ciphertexts passed to a confidential transfer to match the ciphertext-validity proof, so pinning the
//! commitment pins the amount without the program ever reading it.

use solana_sha256_hasher::hashv;

pub mod vectors;

/// Length of a Pedersen commitment, the leading part of every ElGamal ciphertext.
pub const COMMITMENT_LEN: usize = 32;

/// Length of a (twisted) ElGamal ciphertext: commitment (32) || decrypt handle (32).
pub const CIPHERTEXT_LEN: usize = 64;

/// Why a check failed. The calling program maps each variant onto its own error type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// The entry index is out of range, or the recipient is not the one that entry approved.
    RecipientNotInRun,
    /// The amount commitments are not the ones that entry approved.
    AmountNotApproved,
    /// That entry's paid bit is already set.
    EntryAlreadyPaid,
    /// An Ed25519 precompile instruction is malformed or certifies bytes outside itself.
    InvalidAuthorization,
}

/// One approved run entry, as the policy sees it. Implement it for your own account type so the checks can read entries in
/// place (the vault implements it for its `RunEntry`); or use [`RunEntryBytes`].
pub trait RunEntryRef {
    /// The recipient's token account address.
    fn recipient(&self) -> [u8; 32];
    /// Pedersen commitment of the low 16 bits of the amount.
    fn c_lo(&self) -> &[u8; COMMITMENT_LEN];
    /// Pedersen commitment of the high 32 bits of the amount.
    fn c_hi(&self) -> &[u8; COMMITMENT_LEN];
}

/// A run entry as plain bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunEntryBytes {
    pub recipient: [u8; 32],
    pub c_lo: [u8; COMMITMENT_LEN],
    pub c_hi: [u8; COMMITMENT_LEN],
}

impl RunEntryRef for RunEntryBytes {
    fn recipient(&self) -> [u8; 32] {
        self.recipient
    }
    fn c_lo(&self) -> &[u8; COMMITMENT_LEN] {
        &self.c_lo
    }
    fn c_hi(&self) -> &[u8; COMMITMENT_LEN] {
        &self.c_hi
    }
}

/// The Pedersen commitment inside an ElGamal ciphertext (its first 32 bytes).
pub fn commitment(ciphertext: &[u8; CIPHERTEXT_LEN]) -> &[u8; COMMITMENT_LEN] {
    ciphertext[..COMMITMENT_LEN].try_into().expect("a 64-byte ciphertext starts with a 32-byte commitment")
}

/// Bytes needed for a paid bitmap of `entries` entries.
pub fn paid_bitmap_len(entries: usize) -> usize {
    entries.div_ceil(8)
}

/// Whether entry `index`'s paid bit is set (LSB first within each byte). Out of range reads as unpaid.
pub fn is_paid(paid: &[u8], index: u32) -> bool {
    let index = index as usize;
    paid.get(index / 8).is_some_and(|byte| byte & (1 << (index % 8)) != 0)
}

/// Sets entry `index`'s paid bit. The caller has already passed [`check_run_payment`], so `index` is in range (it panics
/// otherwise).
pub fn mark_paid(paid: &mut [u8], index: u32) {
    let index = index as usize;
    paid[index / 8] |= 1 << (index % 8);
}

/// Checks that paying `recipient` the amount hidden in (`ciphertext_lo`, `ciphertext_hi`) is exactly what entry `index`
/// approved, and that the entry has not been paid yet. Does not change anything: call [`mark_paid`] afterwards.
///
/// Pass the AUDITOR ciphertexts of the transfer, the ones Token-2022 checks against the validity proof.
pub fn check_run_payment<E: RunEntryRef>(
    entries: &[E],
    paid: &[u8],
    index: u32,
    recipient: &[u8; 32],
    ciphertext_lo: &[u8; CIPHERTEXT_LEN],
    ciphertext_hi: &[u8; CIPHERTEXT_LEN],
) -> Result<(), PolicyError> {
    let entry = entries.get(index as usize).ok_or(PolicyError::RecipientNotInRun)?;

    if is_paid(paid, index) {
        return Err(PolicyError::EntryAlreadyPaid);
    }
    if &entry.recipient() != recipient {
        return Err(PolicyError::RecipientNotInRun);
    }
    if commitment(ciphertext_lo) != entry.c_lo() || commitment(ciphertext_hi) != entry.c_hi() {
        return Err(PolicyError::AmountNotApproved);
    }
    Ok(())
}

/// SHA-256 over every entry in order, each as `recipient (32) || c_lo (32) || c_hi (32)`. The admin signs this hash (inside
/// [`run_approval_message`]) so the program can prove the entries uploaded by the helper are exactly the ones approved.
pub fn entries_hash<E: RunEntryRef>(entries: &[E]) -> [u8; 32] {
    let parts: Vec<[u8; 96]> = entries
        .iter()
        .map(|entry| {
            let mut bytes = [0u8; 96];
            bytes[..32].copy_from_slice(&entry.recipient());
            bytes[32..64].copy_from_slice(entry.c_lo());
            bytes[64..].copy_from_slice(entry.c_hi());
            bytes
        })
        .collect();
    let slices: Vec<&[u8]> = parts.iter().map(|part| part.as_slice()).collect();
    hashv(&slices).to_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Base58, exactly as a Solana address prints.
fn base58(key: &[u8; 32]) -> String {
    let mut out = [0u8; 44];
    let len = five8::encode_32(key, &mut out) as usize;
    out[..len].iter().map(|&byte| byte as char).collect()
}

/// The exact text the admin signs to approve a payroll run. Human-readable on purpose, because the wallet shows it verbatim.
/// **A cross-language contract with `web/src/lib/chain/run-approval.ts`: both sides pin the exact literal in tests (see
/// [`vectors`]), so change one and you change both, or every approval fails.** A run is approved once (its PDA is unique and
/// sealing needs it pending), so it needs no replay counter.
pub fn run_approval_message(
    vault: &[u8; 32],
    run_id: u64,
    operator: &[u8; 32],
    expires_at: i64,
    entry_count: u32,
    entries_hash: &[u8; 32],
) -> String {
    format!(
        "Cipherpay: approve payroll run\nvault: {}\nrun: {run_id}\noperator: {}\nexpires: {expires_at}\nentries: {entry_count}\nhash: {}",
        base58(vault),
        base58(operator),
        hex(entries_hash)
    )
}

/// Reads the data of an Ed25519 signature-verification precompile instruction and returns the (public key, message) it
/// certifies. The runtime verifies the signature itself before the program runs; this only reads WHAT it certified, so the
/// caller can compare both with what it expects. Loading the instruction (instructions sysvar) and checking its program id
/// stay with the caller.
///
/// Layout (one signature, as every standard builder emits it):
///   [0]      number of signatures (we require exactly 1)
///   [1]      padding
///   [2..16]  offsets: signature, signature ix index, pubkey, pubkey ix index, message, message len, message ix index
///   [16..48] public key
///   [48..112] signature
///   [112..]  message
/// Every "instruction index" must be `u16::MAX`, which means "this instruction": otherwise the precompile would be
/// certifying bytes living in some OTHER instruction, and the bytes we read here would not be the bytes the runtime verified.
pub fn ed25519_signed_payload(data: &[u8]) -> Result<([u8; 32], &[u8]), PolicyError> {
    if data.len() < 16 || data[0] != 1 || data[1] != 0 {
        return Err(PolicyError::InvalidAuthorization);
    }

    let u16_at = |offset: usize| -> u16 { u16::from_le_bytes([data[offset], data[offset + 1]]) };
    let signature_instruction_index = u16_at(4);
    let public_key_offset = u16_at(6) as usize;
    let public_key_instruction_index = u16_at(8);
    let message_data_offset = u16_at(10) as usize;
    let message_data_size = u16_at(12) as usize;
    let message_instruction_index = u16_at(14);

    if signature_instruction_index != u16::MAX
        || public_key_instruction_index != u16::MAX
        || message_instruction_index != u16::MAX
    {
        return Err(PolicyError::InvalidAuthorization);
    }

    let public_key_end = public_key_offset.checked_add(32).ok_or(PolicyError::InvalidAuthorization)?;
    let message_end = message_data_offset
        .checked_add(message_data_size)
        .ok_or(PolicyError::InvalidAuthorization)?;
    if public_key_end > data.len() || message_end > data.len() {
        return Err(PolicyError::InvalidAuthorization);
    }

    let public_key: [u8; 32] =
        data[public_key_offset..public_key_end].try_into().map_err(|_| PolicyError::InvalidAuthorization)?;
    Ok((public_key, &data[message_data_offset..message_end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn entry(recipient: [u8; 32], lo: u8, hi: u8) -> RunEntryBytes {
        RunEntryBytes { recipient, c_lo: [lo; 32], c_hi: [hi; 32] }
    }

    fn ciphertext(commitment: u8) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].fill(commitment);
        bytes[32..].fill(0xEE); // the handle half is irrelevant to the check
        bytes
    }

    #[test]
    fn accepts_the_approved_recipient_and_amount_once() {
        let a = key(0xA1);
        let entries = [entry(a, 1, 2)];
        let mut paid = [0u8; 1];

        assert_eq!(check_run_payment(&entries, &paid, 0, &a, &ciphertext(1), &ciphertext(2)), Ok(()));
        mark_paid(&mut paid, 0);
        assert_eq!(
            check_run_payment(&entries, &paid, 0, &a, &ciphertext(1), &ciphertext(2)),
            Err(PolicyError::EntryAlreadyPaid)
        );
    }

    #[test]
    fn rejects_another_recipient_another_amount_and_a_bad_index() {
        let (a, b) = (key(0xA1), key(0xB2));
        let entries = [entry(a, 1, 2)];
        let paid = [0u8; 1];

        assert_eq!(
            check_run_payment(&entries, &paid, 0, &b, &ciphertext(1), &ciphertext(2)),
            Err(PolicyError::RecipientNotInRun)
        );
        assert_eq!(
            check_run_payment(&entries, &paid, 0, &a, &ciphertext(9), &ciphertext(2)),
            Err(PolicyError::AmountNotApproved)
        );
        assert_eq!(
            check_run_payment(&entries, &paid, 0, &a, &ciphertext(1), &ciphertext(9)),
            Err(PolicyError::AmountNotApproved)
        );
        assert_eq!(
            check_run_payment(&entries, &paid, 1, &a, &ciphertext(1), &ciphertext(2)),
            Err(PolicyError::RecipientNotInRun)
        );
    }

    #[test]
    fn paid_bits_are_per_entry() {
        let (a, b) = (key(0xA1), key(0xB2));
        let entries: Vec<RunEntryBytes> = (0..9).map(|i| entry(if i == 8 { b } else { a }, i, i)).collect();
        let mut paid = [0u8; 2];
        assert_eq!(paid.len(), paid_bitmap_len(entries.len()));

        mark_paid(&mut paid, 8);
        assert!(is_paid(&paid, 8) && !is_paid(&paid, 7) && !is_paid(&paid, 99));
        assert_eq!(
            check_run_payment(&entries, &paid, 8, &b, &ciphertext(8), &ciphertext(8)),
            Err(PolicyError::EntryAlreadyPaid)
        );
        assert_eq!(check_run_payment(&entries, &paid, 7, &a, &ciphertext(7), &ciphertext(7)), Ok(()));
    }

    /// The text the admin signs is a contract with the web client (`web/src/lib/chain/run-approval.ts` pins the same literal).
    #[test]
    fn the_approval_message_is_exactly_what_the_client_builds() {
        let vault = [1; 32];
        let operator = [2; 32];
        let entries = [
            RunEntryBytes { recipient: [3; 32], c_lo: [4; 32], c_hi: [5; 32] },
            RunEntryBytes { recipient: [6; 32], c_lo: [7; 32], c_hi: [8; 32] },
        ];
        let hash = entries_hash(&entries);
        let message = run_approval_message(&vault, 42, &operator, 1_700_000_000, 2, &hash);
        assert_eq!(
            message,
            "Cipherpay: approve payroll run\nvault: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nrun: 42\noperator: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nexpires: 1700000000\nentries: 2\nhash: 884bba2af2bd6310e37ba49b577d5365274a6f0b64a83387ec6043e2cea146e5"
        );
    }

    #[test]
    fn the_published_vectors_hold() {
        for vector in vectors::ENTRIES_HASH_VECTORS {
            assert_eq!(hex(&entries_hash(vector.entries)), vector.hash_hex);
        }
        let v = &vectors::APPROVAL_MESSAGE_VECTOR;
        let hash = entries_hash(v.entries);
        assert_eq!(run_approval_message(&v.vault, v.run_id, &v.operator, v.expires_at, v.entries.len() as u32, &hash), v.message);
    }

    #[test]
    fn commitment_is_the_first_half_of_a_ciphertext() {
        let mut bytes = ciphertext(7);
        bytes[31] = 0x42;
        assert_eq!(commitment(&bytes)[..31], [7; 31]);
        assert_eq!(commitment(&bytes)[31], 0x42);
    }

    /// One-signature precompile data with everything in this instruction, as `Ed25519Program.createInstructionWithPublicKey` builds it.
    fn ed25519_data(public_key: [u8; 32], message: &[u8]) -> Vec<u8> {
        let mut data = vec![1u8, 0];
        for value in [48u16, u16::MAX, 16, u16::MAX, 112, message.len() as u16, u16::MAX] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        data.extend_from_slice(&public_key);
        data.extend_from_slice(&[0u8; 64]); // signature: verified by the runtime, not read here
        data.extend_from_slice(message);
        data
    }

    #[test]
    fn reads_the_key_and_message_of_a_well_formed_ed25519_instruction() {
        let data = ed25519_data(key(9), b"hello");
        assert_eq!(ed25519_signed_payload(&data), Ok((key(9), &b"hello"[..])));
    }

    #[test]
    fn refuses_ed25519_data_that_points_outside_itself_or_is_malformed() {
        let good = ed25519_data(key(9), b"hello");

        let mut elsewhere = good.clone();
        elsewhere[14..16].copy_from_slice(&0u16.to_le_bytes()); // message lives in instruction 0
        assert_eq!(ed25519_signed_payload(&elsewhere), Err(PolicyError::InvalidAuthorization));

        let mut two_signatures = good.clone();
        two_signatures[0] = 2;
        assert_eq!(ed25519_signed_payload(&two_signatures), Err(PolicyError::InvalidAuthorization));

        let mut too_long = good.clone();
        too_long[12..14].copy_from_slice(&999u16.to_le_bytes());
        assert_eq!(ed25519_signed_payload(&too_long), Err(PolicyError::InvalidAuthorization));

        assert_eq!(ed25519_signed_payload(&good[..15]), Err(PolicyError::InvalidAuthorization));
    }
}
