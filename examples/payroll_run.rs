//! A payroll run checked end to end with the library alone, no validator: `cargo run --example payroll_run`.
//!
//! The bytes are placeholders. In a real program the commitments come from the client at approval time and the
//! ciphertexts are the auditor ciphertexts of the confidential transfer the program is about to make.

use confidential_policy::{check_run_payment, entries_hash, mark_paid, paid_bitmap_len, run_approval_message, PolicyError, RunEntryBytes};

/// A 64-byte ElGamal ciphertext whose first 32 bytes (its Pedersen commitment) are `commitment`.
fn ciphertext(commitment: [u8; 32]) -> [u8; 64] {
    let mut ct = [0xAA; 64];
    ct[..32].copy_from_slice(&commitment);
    ct
}

fn main() {
    let (alice, bob, mallory) = ([1u8; 32], [2u8; 32], [9u8; 32]);
    let entries = [
        RunEntryBytes { recipient: alice, c_lo: [11; 32], c_hi: [12; 32] },
        RunEntryBytes { recipient: bob, c_lo: [21; 32], c_hi: [22; 32] },
    ];
    let mut paid = vec![0u8; paid_bitmap_len(entries.len())];

    // What the admin signs once, offline: the run's terms plus a hash of every entry.
    let message = run_approval_message(&[7; 32], 1, &[8; 32], 1_800_000_000, entries.len() as u32, &entries_hash(&entries));
    println!("admin signs:\n{message}\n");

    let mut attempt = |label: &str, index: u32, recipient: [u8; 32], c_lo: [u8; 32], c_hi: [u8; 32]| {
        let result = check_run_payment(&entries, &paid, index, &recipient, &ciphertext(c_lo), &ciphertext(c_hi));
        if result.is_ok() {
            mark_paid(&mut paid, index);
        }
        println!("{label:<40} {result:?}");
        result
    };

    assert_eq!(attempt("pay Alice her approved amount", 0, alice, [11; 32], [12; 32]), Ok(()));
    assert_eq!(attempt("pay Alice again", 0, alice, [11; 32], [12; 32]), Err(PolicyError::EntryAlreadyPaid));
    assert_eq!(attempt("pay Mallory using Bob's entry", 1, mallory, [21; 32], [22; 32]), Err(PolicyError::RecipientNotInRun));
    assert_eq!(attempt("pay Bob a different amount", 1, bob, [99; 32], [22; 32]), Err(PolicyError::AmountNotApproved));
    assert_eq!(attempt("pay an entry that does not exist", 5, bob, [21; 32], [22; 32]), Err(PolicyError::RecipientNotInRun));
    assert_eq!(attempt("pay Bob his approved amount", 1, bob, [21; 32], [22; 32]), Ok(()));
}
