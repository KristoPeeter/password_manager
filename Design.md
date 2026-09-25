# Local, CLI-based password manager

The application is written entirely in Rust to leverage its native memory safety, strong typing, and ownership model, which prevents buffer overflows and dangling pointers.

Crates (probably) used:
- inquire
- argon2
- zeroize
- aes-gcm
- serde

### Privilege Separation pattern implemented via Rust modules

**Frontend:** The "dumb" interaction layer. Displays the interactive menu, accepts user input, and masks keystrokes. It passes inputs to the backend and waits for a response.

**Backend:** Contains the cryptographic operations, file system interactions, and memory management. Designed to be stateless.

**Storage:** Data is persisted locally using an encrypted storage backend.

Must have:
- Per-User isolation
- Data at rest must be encrypted
- Data in memory will have minimized lifespan and be cleared asap.

### Cryptography

**Authentication:** Master Password + Auth Salt hashed via Argon2id. Compared against stored hash to grant access.
**Encryption:** Master Password + Crypto Salt hashed via Argon2id to derive a 256-bit AES key.
**Data Integrity:** Payload encrypted using AES-256-GCM.

### Threat mitigation

**Buffer Overflows** Mitigated by Rust's compiler and strict ownership model.
**Terminal History / Keylogging:** Mitigated by masking terminal echo natively on all sensitive inputs. No passwords accepted via command-line arguments.
**Memory Scraping:** Mitigated by the stateless backend architecture and explicit memory overwriting using `zeroize`.
