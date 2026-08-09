# `@darknyx/browser-client`

Production browser implementation of Darknyx's narrow custody lifecycle.

The UI can provision, unlock, lock, back up, and restore the note credential.
The 64-byte seed remains in a dedicated bundled Worker; IndexedDB receives only
AES-256-GCM ciphertext wrapped by a WebAuthn-PRF-derived, non-extractable key.
The portable backup is the existing version-2 scrypt envelope.

This boundary reduces accidental secret exposure to UI components. It does not
protect against malicious JavaScript delivered by the trusted application
origin; origin and release integrity remain part of the browser custody model.

The package deliberately exports no raw seed, generic signing, arbitrary
proving, note-opening, or witness API.
