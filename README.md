# CovertDataStore
## Encrypted archive interface

CDS is a small, easy-to-use wrapper for [libzip](https://github.com/nih-at/libzip) with a primary focus on building encrypted on-disk storage spaces as one file.
My primary use case is saving files from remote sources (such as those received from a network connection) onto disk, without their plaintext contents ever being written.

The library has the ability to move data between its 'vault' and the disk, with decryption happening on removal and encryption on insertion.
Encryption keys can also be rotated, by cycling through and re-encrypting every item inside the vault with a newly provided key.

## Memory safety

The functions `vault_open`, `vault_get`, `vault_list_items` require freeing, to prevent memory leaks.
- `vault_close()` frees the vault opened. (and can also save changes to disk)
- call `free()` to free the return value of `vault_get`.
- call `vault_list_free()` to free the return value of `vault_list`.

## Dependencies

This library depends on `libzip` (and `zlib`).