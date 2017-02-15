use byteorder::{ByteOrder, LittleEndian};

pub const BLOCK_SIZE: usize = 8;
pub const KEY_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 4 + KEY_SIZE;

const ROUNDS: usize = 24;
const ROUNDS_PER_STEP: usize = 3;
const STEPS: usize = ROUNDS / ROUNDS_PER_STEP;

pub type KeySchedule = [u16; STEPS * 12 + 4];

#[inline]
fn spec_key(left: &mut u16, right: &mut u16) {
    *left = (*left).rotate_right(7).wrapping_add(*right);
    *right = (*right).rotate_left(2) ^ *left;
}

pub fn key_schedule_encrypt(key: &[u8; KEY_SIZE]) -> KeySchedule {
    let mut ks = [0u16; STEPS * 12 + 4];
    for (i, subkey) in ks.iter_mut().enumerate().take(6) {
        *subkey = LittleEndian::read_u16(&key[i * 2..]);
    }
    let mut t0 = LittleEndian::read_u16(&key[6 * 2..]);
    let mut t1 = LittleEndian::read_u16(&key[7 * 2..]);
    for i in 1..(2 * STEPS) {
        ks[6 * i + 0] = t0;
        ks[6 * i + 1] = t1.wrapping_add(i as u16);
        t0 = ks[6 * (i - 1) + 0];
        t1 = ks[6 * (i - 1) + 1];
        spec_key(&mut t0, &mut t1);
        ks[6 * i + 2] = t0;
        ks[6 * i + 3] = t1;
        ks[6 * i + 4] = t0.wrapping_add(ks[6 * (i - 1) + 2]);
        ks[6 * i + 5] = t1.wrapping_add(ks[6 * (i - 1) + 3]);
        t0 = ks[6 * (i - 1) + 4];
        t1 = ks[6 * (i - 1) + 5];
    }
    ks[6 * 2 * STEPS + 0] = t0;
    ks[6 * 2 * STEPS + 1] = t1.wrapping_add(2 * STEPS as u16);
    t0 = ks[6 * (2 * STEPS - 1) + 0];
    t1 = ks[6 * (2 * STEPS - 1) + 1];
    spec_key(&mut t0, &mut t1);
    ks[6 * 2 * STEPS + 2] = t0;
    ks[6 * 2 * STEPS + 3] = t1;
    ks
}

#[inline]
fn round(left: &mut u32, right: &mut u32, ks: &[u16], i: usize) {
    for j in 0..3 {
        *left ^= (ks[i * 12 + j * 2] as u32) | ((ks[i * 12 + j * 2 + 1] as u32) << 16);
        let mut b0_l = *left as u16;
        let mut b0_r = (*left >> 16) as u16;
        spec_key(&mut b0_l, &mut b0_r);
        *left = (b0_l as u32) | ((b0_r as u32) << 16);
    }
    for j in 3..6 {
        *right ^= (ks[i * 12 + j * 2] as u32) | ((ks[i * 12 + j * 2 + 1] as u32) << 16);
        let mut b1_l = *right as u16;
        let mut b1_r = (*right >> 16) as u16;
        spec_key(&mut b1_l, &mut b1_r);
        *right = (b1_l as u32) | ((b1_r as u32) << 16);
    }
    let tmp = *left;
    *right ^= *left ^ (*left).rotate_left(8) ^ (*left).rotate_right(8);
    *left = *right;
    *right = tmp;
}

pub fn encrypt_block(block: &mut [u8; BLOCK_SIZE], ks: &KeySchedule) {
    let mut left = LittleEndian::read_u32(&block[0..]);
    let mut right = LittleEndian::read_u32(&block[4..]);
    for i in 0..STEPS {
        round(&mut left, &mut right, ks, i)
    }
    left ^= (ks[STEPS * 12] as u32) | ((ks[STEPS * 12 + 1] as u32) << 16);
    right ^= (ks[STEPS * 12 + 2] as u32) | ((ks[STEPS * 12 + 3] as u32) << 16);
    LittleEndian::write_u32(&mut block[0..], left);
    LittleEndian::write_u32(&mut block[4..], right);
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
    let mut n = 0;
    let nc = (LittleEndian::read_u32(nonce) as u64) << 32;
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
