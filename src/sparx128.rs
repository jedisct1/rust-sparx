//! SPARX-128/128 block cipher.

use byteorder::{ByteOrder, LittleEndian};

pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 16;
pub const NONCE_SIZE: usize = (BLOCK_SIZE - 6) + 10;

const ROUNDS: usize = 32;
const ROUNDS_PER_STEP: usize = 4;
const STEPS: usize = ROUNDS / ROUNDS_PER_STEP;

pub type KeySchedule = [u32; ROUNDS_PER_STEP * (4 * STEPS + 1)];

#[inline]
fn spec_key(k: &mut u32) {
    let mut left = *k as u16;
    let mut right = (*k >> 16) as u16;
    left = left.rotate_right(7).wrapping_add(right);
    right = right.rotate_left(2) ^ left;
    *k = (left as u32) | ((right as u32) << 16)
}

#[inline]
fn spec_key_inv(k: &mut u32) {
    let mut left = *k as u16;
    let mut right = (*k >> 16) as u16;
    right = (right ^ left).rotate_right(2);
    left = left.wrapping_sub(right).rotate_left(7);
    *k = (left as u32) | ((right as u32) << 16)
}

#[inline]
fn key_perm(k: &mut [u32; 4], c: u16) {
    spec_key(&mut k[0]);
    k[1] = ((k[1] as u16).wrapping_add(k[0] as u16) as u32) |
           (((k[1] >> 16) as u16).wrapping_add((k[0] >> 16) as u16) as u32) << 16;
    spec_key(&mut k[2]);
    k[3] = ((k[3] as u16).wrapping_add(k[2] as u16) as u32) |
           (((k[3] >> 16) as u16).wrapping_add((k[2] >> 16) as u16).wrapping_add(c) as u32) << 16;
    let tmp = k[3];
    k[3] = k[2];
    k[2] = k[1];
    k[1] = k[0];
    k[0] = tmp;
}

/// Compute the key schedule from the master key `key`
pub fn key_schedule_encrypt(key: &[u8; KEY_SIZE]) -> KeySchedule {
    let mut ks = [0u32; ROUNDS_PER_STEP * (4 * STEPS + 1)];
    let mut k = [0u32; 4];
    k[0] = LittleEndian::read_u32(&key[0 * 4..]);
    k[1] = LittleEndian::read_u32(&key[1 * 4..]);
    k[2] = LittleEndian::read_u32(&key[2 * 4..]);
    k[3] = LittleEndian::read_u32(&key[3 * 4..]);
    let mut j = 0;
    for c in 0..(4 * STEPS + 1) {
        for &ksp in k.iter().take(ROUNDS_PER_STEP) {
            ks[j] = ksp;
            j += 1;
        }
        key_perm(&mut k, c as u16 + 1);
    }
    ks
}

/// Compute the key schedule from the master key `key`, for decryption
pub fn key_schedule_decrypt(key: &[u8; KEY_SIZE]) -> KeySchedule {
    key_schedule_encrypt(key)
}

/// Encrypt a single block `block` using the key schedule `ks`
pub fn encrypt_block(block: &mut [u8; BLOCK_SIZE], ks: &KeySchedule) {
    let mut ksi = ks.iter();
    for _ in 0..STEPS {
        for b in 0..4 {
            for _ in 0..ROUNDS_PER_STEP {
                let mut tmp = LittleEndian::read_u32(&block[4 * b..]) ^ ksi.next().unwrap();
                spec_key(&mut tmp);
                LittleEndian::write_u32(&mut block[4 * b..], tmp);
            }
        }
        let x0 = LittleEndian::read_u32(&block[4 * 0..]);
        let x1 = LittleEndian::read_u32(&block[4 * 1..]);
        let mut x2 = LittleEndian::read_u32(&block[4 * 2..]);
        let mut x3 = LittleEndian::read_u32(&block[4 * 3..]);
        let tmp = ((x0 as u16) ^ ((x0 >> 16) as u16) ^ (x1 as u16) ^ ((x1 >> 16) as u16))
            .rotate_left(8);
        let tmp = (tmp as u32) | ((tmp as u32) << 16);
        x2 = ((((x2 as u16) ^ (x1 as u16)) as u32) |
              ((((x2 >> 16) as u16) ^ ((x0 >> 16) as u16)) as u32) << 16) ^ tmp;
        x3 = ((((x3 as u16) ^ (x0 as u16)) as u32) |
              ((((x3 >> 16) as u16) ^ ((x1 >> 16) as u16)) as u32) << 16) ^ tmp;
        LittleEndian::write_u32(&mut block[4 * 0..], x2);
        LittleEndian::write_u32(&mut block[4 * 1..], x3);
        LittleEndian::write_u32(&mut block[4 * 2..], x0);
        LittleEndian::write_u32(&mut block[4 * 3..], x1);
    }
    for b in 0..4 {
        let tmp = LittleEndian::read_u32(&block[4 * b..]) ^ ksi.next().unwrap();
        LittleEndian::write_u32(&mut block[4 * b..], tmp);
    }
}

/// Decrypt a single block `block` using the key schedule `ks`
pub fn decrypt_block(block: &mut [u8; BLOCK_SIZE], ks: &KeySchedule) {
    let mut ksi = ks.iter().rev();
    for b in (0..4).rev() {
        let tmp = LittleEndian::read_u32(&block[4 * b..]) ^ ksi.next().unwrap();
        LittleEndian::write_u32(&mut block[4 * b..], tmp);
    }
    for _ in 0..STEPS {
        let x0 = LittleEndian::read_u32(&block[4 * 2..]);
        let x1 = LittleEndian::read_u32(&block[4 * 3..]);
        let mut x2 = LittleEndian::read_u32(&block[4 * 0..]);
        let mut x3 = LittleEndian::read_u32(&block[4 * 1..]);
        let tmp = ((x0 as u16) ^ ((x0 >> 16) as u16) ^ (x1 as u16) ^ ((x1 >> 16) as u16))
            .rotate_left(8);
        let tmp = (tmp as u32) | ((tmp as u32) << 16);
        x2 = ((((x2 as u16) ^ (x1 as u16)) as u32) |
              ((((x2 >> 16) as u16) ^ ((x0 >> 16) as u16)) as u32) << 16) ^ tmp;
        x3 = ((((x3 as u16) ^ (x0 as u16)) as u32) |
              ((((x3 >> 16) as u16) ^ ((x1 >> 16) as u16)) as u32) << 16) ^ tmp;
        LittleEndian::write_u32(&mut block[4 * 0..], x0);
        LittleEndian::write_u32(&mut block[4 * 1..], x1);
        LittleEndian::write_u32(&mut block[4 * 2..], x2);
        LittleEndian::write_u32(&mut block[4 * 3..], x3);
        for b in (0..4).rev() {
            for _ in 0..ROUNDS_PER_STEP {
                let mut tmp = LittleEndian::read_u32(&block[4 * b..]);
                spec_key_inv(&mut tmp);
                LittleEndian::write_u32(&mut block[4 * b..], tmp ^ ksi.next().unwrap());
            }
        }
    }
}

/// Encrypt an arbitrary-long message `buf` using SPARX in counter mode with the nonce `nonce` and the master key `key`.
pub fn encrypt_ctr(buf: &mut [u8], nonce: &[u8; NONCE_SIZE], key: &[u8; KEY_SIZE]) {
    if buf.is_empty() {
        return;
    }
    let mut key2 = [0u8; KEY_SIZE];
    for (i, &x) in key.iter().enumerate().take(10) {
        key2[i] = x ^ nonce[BLOCK_SIZE - 6 + i];
    }
    let ks = key_schedule_encrypt(&key2);
    let full_blocks_count = (buf.len() / BLOCK_SIZE) as u64;
    let mut ib = [0u8; BLOCK_SIZE];
    let mut nc = [0u8; BLOCK_SIZE];
    for i in 0..(BLOCK_SIZE - 6) {
        nc[i] = nonce[i];
    }
    let mut n = 0;
    for i in 0..full_blocks_count {
        ib.copy_from_slice(&nc);
        LittleEndian::write_u32(&mut ib[BLOCK_SIZE - 6..], i as u32);
        LittleEndian::write_u16(&mut ib[BLOCK_SIZE - 2..], (i >> 32) as u16);
        encrypt_block(&mut ib, &ks);
        for (j, &ob) in ib.iter().enumerate() {
            buf[n + j] ^= ob;
        }
        n += BLOCK_SIZE;
    }
    let remaining_bytes = buf.len() % BLOCK_SIZE;
    if remaining_bytes > 0 {
        ib.copy_from_slice(&nc);
        LittleEndian::write_u32(&mut ib[BLOCK_SIZE - 6..], full_blocks_count as u32);
        LittleEndian::write_u16(&mut ib[BLOCK_SIZE - 2..], (full_blocks_count >> 32) as u16);
        encrypt_block(&mut ib, &ks);
        for (j, &ob) in ib.iter().enumerate().take(remaining_bytes) {
            buf[n + j] ^= ob
        }
    }
}

/// Decrypt an arbitrary-long message `buf` using SPARX in counter mode with the nonce `nonce` and the master key `key`.
pub fn decrypt_ctr(buf: &mut [u8], nonce: &[u8; NONCE_SIZE], key: &[u8; KEY_SIZE]) {
    encrypt_ctr(buf, nonce, key)
}

#[test]
fn test_vector() {
    let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88, 0xbb,
                               0xaa, 0xdd, 0xcc, 0xff, 0xee];
    let mut block: [u8; BLOCK_SIZE] = [0x23, 0x01, 0x67, 0x45, 0xab, 0x89, 0xef, 0xcd, 0xdc, 0xfe,
                                       0x98, 0xba, 0x54, 0x76, 0x10, 0x32];
    let ks = key_schedule_encrypt(&key);
    let block2 = block;
    encrypt_block(&mut block, &ks);
    assert_eq!([0xee, 0x1c, 0x40, 0x75, 0xbf, 0x7d, 0xd8, 0x23, 0xee, 0xe0, 0x97, 0x15, 0x28,
                0xf4, 0xd8, 0x52],
               block);
    decrypt_block(&mut block, &ks);
    assert_eq!(block2, block);
}

#[test]
fn test_ctr() {
    let nonce: [u8; NONCE_SIZE] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                                   19, 20];
    let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88, 0xbb,
                               0xaa, 0xdd, 0xcc, 0xff, 0xee];
    let input = b"The quick brown fox jumps over the lazy dog";
    let mut buf = input.to_vec();
    let expected: [u8; 43] = [187, 164, 175, 197, 150, 51, 7, 71, 250, 16, 102, 26, 154, 89, 226,
                              186, 171, 49, 0, 228, 255, 249, 53, 223, 223, 97, 25, 144, 13, 185,
                              170, 216, 79, 219, 40, 137, 95, 164, 73, 201, 65, 42, 58];
    encrypt_ctr(&mut buf, &nonce, &key);
    assert_eq!(buf[..], expected[..]);
    decrypt_ctr(&mut buf, &nonce, &key);
    assert_eq!(buf[..], input[..]);
}
