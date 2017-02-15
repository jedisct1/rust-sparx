#![feature(test)]

extern crate sparx;
extern crate test;

mod benches64 {
    use test::Bencher;
    use sparx::sparx64::{KEY_SIZE, BLOCK_SIZE, NONCE_SIZE, key_schedule_encrypt, encrypt_block,
                         encrypt_ctr};

    #[bench]
    fn bench_sparx64_1(b: &mut Bencher) {
        let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88,
                                   0xbb, 0xaa, 0xdd, 0xcc, 0xff, 0xee];
        b.iter(|| {
            let ks = key_schedule_encrypt(&key);
            ks
        })
    }

    #[bench]
    fn bench_sparx64_2(b: &mut Bencher) {
        let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88,
                                   0xbb, 0xaa, 0xdd, 0xcc, 0xff, 0xee];
        let mut block: [u8; BLOCK_SIZE] = [0x23, 0x01, 0x67, 0x45, 0xab, 0x89, 0xef, 0xcd];
        let ks = key_schedule_encrypt(&key);
        b.iter(|| {
            encrypt_block(&mut block, &ks);
            block
        })
    }

    #[bench]
    fn bench_sparx64_3(b: &mut Bencher) {
        let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88,
                                   0xbb, 0xaa, 0xdd, 0xcc, 0xff, 0xee];
        let mut block: [u8; BLOCK_SIZE] = [0x23, 0x01, 0x67, 0x45, 0xab, 0x89, 0xef, 0xcd];
        b.iter(|| {
            let ks = key_schedule_encrypt(&key);
            encrypt_block(&mut block, &ks);
            block
        })
    }

    #[bench]
    fn bench_sparx64_4(b: &mut Bencher) {
        let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88,
                                   0xbb, 0xaa, 0xdd, 0xcc, 0xff, 0xee];
        let nonce = [0u8; NONCE_SIZE];
        let mut buf = [0u8; 4000];
        b.iter(|| {
            encrypt_ctr(&mut buf, &nonce, &key);
            buf
        })
    }
}

mod benches128 {
    use test::Bencher;
    use sparx::sparx128::{KEY_SIZE, BLOCK_SIZE, NONCE_SIZE, key_schedule_encrypt, encrypt_block,
                          encrypt_ctr};

    #[bench]
    fn bench_sparx128_1(b: &mut Bencher) {
        let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88,
                                   0xbb, 0xaa, 0xdd, 0xcc, 0xff, 0xee];
        b.iter(|| {
            let ks = key_schedule_encrypt(&key);
            ks
        })
    }

    #[bench]
    fn bench_sparx128_2(b: &mut Bencher) {
        let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88,
                                   0xbb, 0xaa, 0xdd, 0xcc, 0xff, 0xee];
        let mut block: [u8; BLOCK_SIZE] = [0x23, 0x01, 0x67, 0x45, 0xab, 0x89, 0xef, 0xcd, 0xdc,
                                           0xfe, 0x98, 0xba, 0x54, 0x76, 0x10, 0x32];
        let ks = key_schedule_encrypt(&key);
        b.iter(|| {
            encrypt_block(&mut block, &ks);
            block
        })
    }

    #[bench]
    fn bench_sparx128_3(b: &mut Bencher) {
        let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88,
                                   0xbb, 0xaa, 0xdd, 0xcc, 0xff, 0xee];
        let mut block: [u8; BLOCK_SIZE] = [0x23, 0x01, 0x67, 0x45, 0xab, 0x89, 0xef, 0xcd, 0xdc,
                                           0xfe, 0x98, 0xba, 0x54, 0x76, 0x10, 0x32];
        b.iter(|| {
            let ks = key_schedule_encrypt(&key);
            encrypt_block(&mut block, &ks);
            block
        })
    }

    #[bench]
    fn bench_sparx128_4(b: &mut Bencher) {
        let key: [u8; KEY_SIZE] = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88,
                                   0xbb, 0xaa, 0xdd, 0xcc, 0xff, 0xee];
        let nonce = [0u8; NONCE_SIZE];
        let mut buf = [0u8; 4000];
        b.iter(|| {
            encrypt_ctr(&mut buf, &nonce, &key);
            buf
        })
    }
}
