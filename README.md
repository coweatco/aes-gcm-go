# AES classroom demo

Run `go run .` or `go run . -tui` to open the terminal interface. Enter a menu
number and press Enter. The interface starts in GCM with a generated 32-byte key.
Menu 7 switches between GCM and ECB; menu 8 accepts a 64-character hexadecimal key
or generates a fresh key when left blank. `-tui -key <hex> -aad <text>` sets initial
key and AAD values. Run the TUI with `go run .`, which includes both Go source files.

The menu supports text encryption and decryption and file round trips.
Intermediate inspection always
appears after successful text encryption/decryption and file round trips in both
GCM and ECB. The first block is expanded into AES steps to keep output bounded.
There is no separate inspection option; the other menu numbers are unchanged.
Decryption can reuse the last
encrypted result in the selected mode, including its original AAD, or accept
ciphertext/nonce/tag as hex. Manual GCM input uses the current AAD setting. Changing
the key clears the last result. File recovery refuses to overwrite
existing files. Type `0` or `q` to quit; end-of-input also exits cleanly.

Command-line flags still run the original GCM demo without opening the menu:

```powershell
go run . -text "Hello AES" -aad "class demo" -trace -tamper
go run . -text "My message" -key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
go run . -in example.txt -out restored.txt -save encrypted.json
go run . -in photo.png -out restored.png -save photo-encrypted.json
```

Output includes plaintext and restored text (or file hashes), byte count, demo
key, nonce, AAD, ciphertext, authentication tag, authentication status, exact
round-trip verification, and encryption/decryption times. File ciphertext output
is limited to a 64-byte preview; `-save` stores the complete ciphertext and public
decryption parameters as JSON hex fields. The key is not saved in the bundle.
Output files must not already exist. To compare timings, run the file command
with different input sizes; short operations may be below the timer resolution.

`-trace` prints all 15 round keys, GCM's H and J0, the first counter and keystream
block, and AES state after each SubBytes, ShiftRows, MixColumns and AddRoundKey
step for that counter block. State bytes are column-major. It also prints GHASH,
the tag mask, and the resulting tag. This traces the full AES-256 cipher, rather
than a separate reduced cipher. AES does not have an RC4-style S array or shift
register. `-tamper` changes a tag bit and demonstrates authentication rejection.

This is educational code: output exposes the key and intermediate state, and
table-based AES is not constant-time. Use Go's standard cryptography packages for
production. The CLI currently demonstrates encryption followed immediately by
decryption; it does not load saved bundles in a separate decrypt command.

Counter-mode AES blocks are processed by bounded goroutines for messages of at
least 32 KiB when `GOMAXPROCS` permits multiple workers. Each worker handles a
contiguous, block-aligned range with its own counter and shares the expanded key
read-only. Smaller messages run sequentially. Both encryption and decryption use
this path; authentication is checked before decryption. GHASH remains sequential,
so total speedup depends on message size, CPU availability, and authentication cost.

Validation: `go test ./...` and `go vet ./...`. Where CGO and a C compiler are
available, use `go test -race ./...` to check for data races.

## AES-256-ECB

`enc/ebc.go` implements ECB (the filename preserves the project's spelling).
Call `enc.AES256ECBEncrypt(key, plaintext)` and
`enc.AES256ECBDecrypt(key, ciphertext)`, each returning `([]byte, error)`.
Keys must contain exactly 32 bytes. Encryption always adds PKCS#7 padding,
including a full block for empty or block-aligned messages. Decryption validates
and removes padding, returning `enc.ErrInvalidPadding` on malformed padding.
Both operations leave inputs unchanged and use bounded goroutines for larger
messages. ECB has no nonce or authentication tag; repeated plaintext blocks
produce repeated ciphertext blocks. The flag-based CLI demonstrates GCM; the TUI
supports both modes.
