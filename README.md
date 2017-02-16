# SPARX block ciphers implementations for Rust

[SPARX](https://www.cryptolux.org/index.php/SPARX) is a family of lightweight block ciphers allowing small processors to securely encrypt information for a fraction of the cost a standard algorithm would require.

Due to the use of ARX operations, these block ciphers are inherently more secure against side-channel attacks than an S-Box-based cipher such as AES.

Furthermore, unlike all other ARX-based, which share those advantages, SPARX ciphers are the only ARX-based block ciphers for which bounds on the probability of differential and linear trails can be proved.

To sum up, SPARX has:
* the lightweightness and side-channel resilience of an ARX-based cipher,
* the security argument of an S-Box-based cipher, and
* a flexible structure easing implementation trade-offs.

# Usage

This crate implements SPARX-64/128 (64 bit block size, 128 bit key) in the `sparx64` module and SPARX-128/128 (128 bit block size, 128 bit key) in the `sparx128` module.

It doesn't require the Rust standard library.

## Encryption of a single block
```rust
let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88, 0xbb,
                           0xaa, 0xdd, 0xcc, 0xff, 0xee];
let mut block: [u8; BLOCK_SIZE] = [0x23, 0x01, 0x67, 0x45, 0xab, 0x89, 0xef, 0xcd];
let ks = key_schedule_encrypt(&key); // key schedule - can be reused with multiple blocks
encrypt_block(&mut block, &ks);
// ...
```

`decrypt_block()` is not implemented yet.

## Encryption of an arbitrary-sized buffer

This uses SPARX in counter mode as well as a 160-bit nonce in order to encrypt multiple blocks.

The internal counter size for this construction with SPARX-64/128 is 32 bits (no more than 32 GB should be encrypted with the same `(key, nonce)` tuple) and 48 bits with SPARX-128/128 (allowing up to 4 PB to be encrypted with the same `(key, nonce)` tuple).

The nonce is large enough to be randomly chosen; the probably of a collision to occur will be negligible.

Note that this construction does not add any authentication tags to the message.

```rust
let nonce: [u8; NONCE_SIZE] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                               19, 20];
let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88, 0xbb,
                           0xaa, 0xdd, 0xcc, 0xff, 0xee];
let input = b"The quick brown fox jumps over the lazy dog";
let mut buf = input.to_vec();
encrypt_ctr(&mut buf, &nonce, &key);
// ...
decrypt_ctr(&mut buf, &nonce, &key);
```

# References

* [Design Strategies for ARX with Provable Bounds: SPARX and LAX](https://eprint.iacr.org/2016/984.pdf) (Daniel Dinu, Léo Perrin, Aleksei Udovenko, Vesselin Velichkov, Johann Großschädl, Alex Biryukov).
