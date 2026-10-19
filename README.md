# confidential-policy

**Spending rules for Solana confidential transfers, enforced on amounts nobody can read.**

Token-2022 Confidential Transfers hide amounts. That is the point, but it means a program usually cannot enforce rules
about value: who gets paid how much. Companies end up choosing between privacy and spending controls. This library lets
a Solana program enforce an exact, admin-approved payout list on hidden amounts, without ever decrypting them.

> Status: v0.1.0, written for a hackathon submission. Unit-tested here and exercised end to end in a confidential payroll
> vault (litesvm, a local validator, and devnet). **Not audited, not production-ready.**

## How it works

```
  APPROVE (once, offline)                    PAY (later, any number of transactions)
  ───────────────────────                    ───────────────────────────────────────
  Admin builds the run:                      Helper key sends a confidential transfer
    Alice  -> commitment(amount A)             to Alice, carrying ciphertexts of A
    Bob    -> commitment(amount B)                        │
  and signs ONE message containing                        ▼
  a hash of every entry.                     check_run_payment():
           │                                   recipient == approved recipient?
           ▼                                   ciphertext[0..32] == approved commitment?
  Program stores the entries and              entry not paid yet?
  verifies the admin's signature.                         │
                                                  yes ──► mark paid, transfer
                                                  no  ──► transaction fails
```

The key fact: **the first 32 bytes of an ElGamal ciphertext are its Pedersen commitment**, and Token-2022 requires the
auditor ciphertexts passed to a confidential transfer to match the transfer's zero-knowledge validity proof. So comparing
those 32 bytes with the commitment the admin approved pins the amount exactly, while the program never sees it.

## What it refuses

Once a run is approved, a helper key (even a stolen one) can only ever do a subset of exactly what was approved:

| Attempt                                                   | Result                                  | Enforced by                       |
| --------------------------------------------------------- | --------------------------------------- | --------------------------------- |
| Pay someone not on the run                                | `RecipientNotInRun`                     | this library                      |
| Pay an approved person a different amount                 | `AmountNotApproved`                     | this library                      |
| Pay the same entry twice                                  | `EntryAlreadyPaid`                      | this library                      |
| Forge it: approved commitments, proofs for another amount | `Balance mismatch`                      | Token-2022 itself                 |
| Change an entry after the admin signed                    | signature does not match `entries_hash` | this library + Ed25519 precompile |

Every row is covered by tests in the reference integration (the forgery row by
`approved_commitments_with_proofs_for_another_amount_are_refused_by_token_2022`), and was verified on a real local
validator.

## Try it in ten seconds

```bash
cargo run --example payroll_run
```

```
pay Alice her approved amount            Ok(())
pay Alice again                          Err(EntryAlreadyPaid)
pay Mallory using Bob's entry            Err(RecipientNotInRun)
pay Bob a different amount               Err(AmountNotApproved)
pay an entry that does not exist         Err(RecipientNotInRun)
pay Bob his approved amount              Ok(())
```

## Use it in your program

It is a library you compile in, not a program you call: a policy matters when money moves, and money moves when the
program that owns the token account tells Token-2022 to transfer. So that program runs the check, right before its CPI.

```toml
[dependencies]
confidential-policy = { git = "https://github.com/itssvk/confidential-policy", tag = "v0.1.0" }
```

```rust
use confidential_policy::{check_run_payment, mark_paid, RunEntryRef};

// In your pay instruction, before the confidential transfer CPI:
check_run_payment(&run.entries, &run.paid, entry_index, &recipient_token_account,
                  &auditor_ciphertext_lo, &auditor_ciphertext_hi)
    .map_err(MyError::from)?;
mark_paid(&mut run.paid, entry_index);
// ...then CPI the Token-2022 transfer, passing the SAME auditor ciphertexts.
```

Implement `RunEntryRef` for your own account type so entries are read in place, or use `RunEntryBytes`. Your program
owns the storage layout and maps `PolicyError` onto its own errors.

Pure functions over bytes: **no Anchor, no `solana-program` types**, so Anchor and native programs can both use it.
Dependencies: `solana-sha256-hasher` (a syscall on-chain) and `five8` (base58).

## API

```rust
pub enum PolicyError { RecipientNotInRun, AmountNotApproved, EntryAlreadyPaid, InvalidAuthorization }

pub trait RunEntryRef {
    fn recipient(&self) -> [u8; 32];
    fn c_lo(&self) -> &[u8; 32];   // commitment of the low 16 bits of the amount
    fn c_hi(&self) -> &[u8; 32];   // commitment of the high 32 bits
}
pub struct RunEntryBytes { pub recipient: [u8; 32], pub c_lo: [u8; 32], pub c_hi: [u8; 32] }

// Paying
pub fn check_run_payment<E: RunEntryRef>(entries: &[E], paid: &[u8], index: u32, recipient: &[u8; 32],
    ciphertext_lo: &[u8; 64], ciphertext_hi: &[u8; 64]) -> Result<(), PolicyError>;
pub fn mark_paid(paid: &mut [u8], index: u32);
pub fn is_paid(paid: &[u8], index: u32) -> bool;
pub fn paid_bitmap_len(entries: usize) -> usize;
pub fn commitment(ciphertext: &[u8; 64]) -> &[u8; 32];

// Approving
pub fn entries_hash<E: RunEntryRef>(entries: &[E]) -> [u8; 32];
pub fn run_approval_message(vault: &[u8; 32], run_id: u64, operator: &[u8; 32], expires_at: i64,
    entry_count: u32, entries_hash: &[u8; 32]) -> String;
pub fn ed25519_signed_payload(data: &[u8]) -> Result<([u8; 32], &[u8]), PolicyError>;
```

- `entries_hash` is SHA-256 over `recipient || c_lo || c_hi` for each entry, in order.
- `run_approval_message` is human-readable on purpose (wallets show it verbatim). It is a cross-language contract: a
  client must build the same text. `src/vectors.rs` holds test vectors any other implementation must reproduce.
- `ed25519_signed_payload` parses what the Ed25519 precompile certified. The runtime verifies the signature; the caller
  must load the instruction, check its program id, and compare key and message.

## Honest limits

- **The amount binding relies on Token-2022**, not on this crate: it holds because Token-2022 rejects a transfer whose
  auditor ciphertexts don't match the validity proof. Pass the auditor ciphertexts that actually go into the CPI.
- **Not atomic across a run.** A confidential payment takes several transactions (proofs and the 1232-byte limit), so a
  run cannot be one transaction. Unpaid entries stay locked to their exact amounts until the run expires or is cancelled.
- **Not enforced here:** who may pay, run status, expiry, pausing, replay of the approval. Those live in the calling
  program's accounts.
- The client must build the transfer with the same Pedersen openings it used for the approved commitments.

## Roadmap

- **Enforced splits:** prove on-chain that parts follow a ratio (e.g. 79 / 20 / 1) while even the total stays hidden,
  using commitment arithmetic and a batched range proof.
- **Capped percentage fee:** "1%, max X", matching Token-2022's `PercentageWithCap` semantics.
- **Merkle runs:** a root instead of a stored list, for payrolls beyond about 100 entries.
- **TypeScript package:** the client half (commitments at approval, transfers reusing the openings, the approval message).

## License

Apache-2.0. See [LICENSE](LICENSE).
