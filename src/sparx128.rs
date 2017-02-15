use byteorder::{ByteOrder, LittleEndian};

pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 16;
pub const NONCE_SIZE: usize = (BLOCK_SIZE - 6) + 10;

const ROUNDS: usize = 32;
const ROUNDS_PER_STEP: usize = 4;
const STEPS: usize = ROUNDS / ROUNDS_PER_STEP;

pub type KeySchedule = [u16; 2 * ROUNDS_PER_STEP * (4 * STEPS + 1)];

#[inline]
fn spec_key(k: &mut [u16], i: usize) {
    let mut left = k[i];
    let mut right = k[i + 1];
    left = left.rotate_right(7).wrapping_add(right);
    right = right.rotate_left(2) ^ left;
    k[i] = left;
    k[i + 1] = right;
}

#[inline]
fn key_perm(k: &mut [u16], c: u16) {
    spec_key(k, 0);
    k[2] = k[2].wrapping_add(k[0]);
    k[3] = k[3].wrapping_add(k[1]);
    spec_key(k, 4);
    k[6] = k[6].wrapping_add(k[4]);
    k[7] = k[7].wrapping_add(k[5]).wrapping_add(c);
    let tmp0 = k[6];
    let tmp1 = k[7];
    k[7] = k[5];
    k[6] = k[4];
    k[5] = k[3];
    k[4] = k[2];
    k[3] = k[1];
    k[2] = k[0];
    k[0] = tmp0;
    k[1] = tmp1;
}

pub fn key_schedule_encrypt(key: &[u8; KEY_SIZE]) -> KeySchedule {
    let mut ks = [0u16; 2 * ROUNDS_PER_STEP * (4 * STEPS + 1)];
    let mut k = [0u16; 8];
    for (i, kp) in k.iter_mut().enumerate() {
        *kp = LittleEndian::read_u16(&key[i * 2..]);
    }
    let mut j = 0;
    for c in 0..(4 * STEPS + 1) {
        for &ksp in &k {
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
        for b in 0..4 {
            for _ in 0..ROUNDS_PER_STEP {
                let mut tmp = [0u16; 2];
                tmp[0] = LittleEndian::read_u16(&block[2 * (2 * b)..]) ^ ks[j];
                tmp[1] = LittleEndian::read_u16(&block[2 * (2 * b + 1)..]) ^ ks[j + 1];
                j += 2;
                spec_key(&mut tmp, 0);
                LittleEndian::write_u16(&mut block[2 * (2 * b)..], tmp[0]);
                LittleEndian::write_u16(&mut block[2 * (2 * b + 1)..], tmp[1]);
            }
        }
        let mut x = [0u16; 8];
        for (i, xp) in x.iter_mut().enumerate() {
            *xp = LittleEndian::read_u16(&block[2 * i..]);
        }
        let tmp = (x[0] ^ x[1] ^ x[2] ^ x[3]).rotate_left(8);
        x[4] ^= x[2] ^ tmp;
        x[5] ^= x[1] ^ tmp;
        x[6] ^= x[0] ^ tmp;
        x[7] ^= x[3] ^ tmp;
        x.swap(0, 4);
        x.swap(1, 5);
        x.swap(2, 6);
        x.swap(3, 7);
        for (i, xp) in x.iter().enumerate() {
            LittleEndian::write_u16(&mut block[2 * i..], *xp);
        }
    }

    for b in 0..4 {
        let mut tmp = [0u16; 2];
        tmp[0] = LittleEndian::read_u16(&block[2 * (2 * b)..]) ^ ks[j];
        tmp[1] = LittleEndian::read_u16(&block[2 * (2 * b + 1)..]) ^ ks[j + 1];
        j += 2;
        LittleEndian::write_u16(&mut block[2 * (2 * b)..], tmp[0]);
        LittleEndian::write_u16(&mut block[2 * (2 * b + 1)..], tmp[1]);
    }
}

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
    encrypt_block(&mut block, &ks);
    assert_eq!([0xee, 0x1c, 0x40, 0x75, 0xbf, 0x7d, 0xd8, 0x23, 0xee, 0xe0, 0x97, 0x15, 0x28,
                0xf4, 0xd8, 0x52],
               block);
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
