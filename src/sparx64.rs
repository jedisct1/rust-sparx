use byteorder::{ByteOrder, LittleEndian};

pub const BLOCK_SIZE: usize = 8;
pub const KEY_SIZE: usize = 16;
pub const NONCE_SIZE: usize = (BLOCK_SIZE - 4) + KEY_SIZE;

const ROUNDS: usize = 24;
const ROUNDS_PER_STEP: usize = 3;
const STEPS: usize = ROUNDS / ROUNDS_PER_STEP;

pub type KeySchedule = [u32; ROUNDS_PER_STEP * (2 * STEPS + 1)];

#[inline]
fn spec_key(k: &mut u32) {
    let mut left = *k as u16;
    let mut right = (*k >> 16) as u16;
    left = left.rotate_right(7).wrapping_add(right);
    right = right.rotate_left(2) ^ left;
    *k = (left as u32) | ((right as u32) << 16)
}

#[inline]
fn key_perm(k: &mut [u32; 4], c: u16) {
    spec_key(&mut k[0]);
    k[1] = ((k[1] as u16).wrapping_add(k[0] as u16) as u32) |
           (((k[1] >> 16) as u16).wrapping_add((k[0] >> 16) as u16) as u32) << 16;
    k[3] = ((k[3] as u16) as u32) | (((k[3] >> 16) as u16).wrapping_add(c) as u32) << 16;
    let tmp = k[3];
    k[3] = k[2];
    k[2] = k[1];
    k[1] = k[0];
    k[0] = tmp;
}

pub fn key_schedule_encrypt(key: &[u8; KEY_SIZE]) -> KeySchedule {
    let mut ks = [0u32; ROUNDS_PER_STEP * (2 * STEPS + 1)];
    let mut k = [0u32; 4];
    k[0] = LittleEndian::read_u32(&key[0 * 4..]);
    k[1] = LittleEndian::read_u32(&key[1 * 4..]);
    k[2] = LittleEndian::read_u32(&key[2 * 4..]);
    k[3] = LittleEndian::read_u32(&key[3 * 4..]);
    let mut j = 0;
    for c in 0..(2 * STEPS + 1) {
        for &ksp in k.iter().take(ROUNDS_PER_STEP) {
            ks[j] = ksp;
            j += 1;
        }
        key_perm(&mut k, c as u16 + 1);
    }
    ks
}

pub fn encrypt_block(block: &mut [u8; BLOCK_SIZE], ks: &KeySchedule) {
    let mut j = 0;
    for _ in 0..STEPS {
        for b in 0..2 {
            for _ in 0..ROUNDS_PER_STEP {
                let mut tmp = LittleEndian::read_u32(&block[4 * b..]) ^ ks[j];
                j += 1;
                spec_key(&mut tmp);
                LittleEndian::write_u32(&mut block[4 * b..], tmp);
            }
        }
        let mut x = [0u32; 2];
        x[0] = LittleEndian::read_u32(&block[4 * 0..]);
        x[1] = LittleEndian::read_u32(&block[4 * 1..]);
        let tmp = ((x[0] as u16) ^ ((x[0] >> 16) as u16)).rotate_left(8);
        let tmp = (tmp as u32) | ((tmp as u32) << 16);
        x[1] = ((((x[1] as u16) ^ (x[0] as u16)) as u32) |
                ((((x[1] >> 16) as u16) ^ ((x[0] >> 16) as u16)) as u32) << 16) ^
               tmp;
        LittleEndian::write_u32(&mut block[4 * 0..], x[1]);
        LittleEndian::write_u32(&mut block[4 * 1..], x[0]);
    }
    for b in 0..2 {
        let tmp = LittleEndian::read_u32(&block[4 * b..]) ^ ks[j];
        j += 1;
        LittleEndian::write_u32(&mut block[4 * b..], tmp);
    }
}

pub fn encrypt_ctr(buf: &mut [u8], nonce: &[u8; NONCE_SIZE], key: &[u8; KEY_SIZE]) {
    if buf.is_empty() {
        return;
    }
    let mut key2 = [0u8; KEY_SIZE];
    for (i, &x) in key.iter().enumerate() {
        key2[i] = x ^ nonce[4 + i];
    }
    let ks = key_schedule_encrypt(&key2);
    let full_blocks_count = (buf.len() / BLOCK_SIZE) as u64;
    let mut ib = [0u8; BLOCK_SIZE];
    let nc = (LittleEndian::read_u32(nonce) as u64) << 32;
    let mut n = 0;
    for i in 0..full_blocks_count {
        LittleEndian::write_u64(&mut ib, nc.wrapping_add(i));
        encrypt_block(&mut ib, &ks);
        for (j, &ob) in ib.iter().enumerate() {
            buf[n + j] ^= ob;
        }
        n += BLOCK_SIZE;
    }
    let remaining_bytes = buf.len() % BLOCK_SIZE;
    if remaining_bytes > 0 {
        LittleEndian::write_u64(&mut ib, nc.wrapping_add(full_blocks_count));
        encrypt_block(&mut ib, &ks);
        for (j, &ob) in ib.iter().enumerate().take(remaining_bytes) {
            buf[n + j] ^= ob
        }
    }
}

pub fn decrypt_ctr(buf: &mut [u8], nonce: &[u8; NONCE_SIZE], key: &[u8; KEY_SIZE]) {
    encrypt_ctr(buf, nonce, key)
}

#[test]
fn test_vector() {
    let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88, 0xbb,
                               0xaa, 0xdd, 0xcc, 0xff, 0xee];
    let mut block: [u8; BLOCK_SIZE] = [0x23, 0x01, 0x67, 0x45, 0xab, 0x89, 0xef, 0xcd];
    let ks = key_schedule_encrypt(&key);
    encrypt_block(&mut block, &ks);
    assert_eq!([0xbe, 0x2b, 0x52, 0xf1, 0xf5, 0x01, 0x98, 0x5f], block);
}

#[test]
fn test_ctr() {
    let nonce: [u8; NONCE_SIZE] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                                   19, 20];
    let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88, 0xbb,
                               0xaa, 0xdd, 0xcc, 0xff, 0xee];
    let input = b"The quick brown fox jumps over the lazy dog";
    let mut buf = input.to_vec();
    let expected: [u8; 43] = [219, 13, 239, 221, 244, 204, 168, 236, 26, 35, 237, 153, 212, 69,
                              20, 70, 29, 84, 131, 31, 39, 107, 91, 149, 216, 14, 65, 237, 67,
                              149, 55, 73, 249, 94, 132, 5, 243, 108, 17, 153, 247, 147, 113];
    encrypt_ctr(&mut buf, &nonce, &key);
    assert_eq!(buf[..], expected[..]);
    decrypt_ctr(&mut buf, &nonce, &key);
    assert_eq!(buf[..], input[..]);
}
