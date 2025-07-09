use crate::rand::SimpleRng;

#[inline]
pub fn generate_password(matrix: usize, password: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(matrix);
    let password_len = password.len();

    if password_len == 0 {
        result.resize(matrix, 0);
        return result;
    }

    let repeats = matrix / password_len;
    let remainder = matrix % password_len;

    for _ in 0..repeats {
        result.extend_from_slice(password);
    }
    if remainder > 0 {
        result.extend_from_slice(&password[..remainder]);
    }

    result
}


pub fn shuffle(data: &mut [u8], seed: u64,step: usize) {
    let mut rng = SimpleRng::new(seed);
    let len=data.len();
    for i in (1..len).rev().step_by(step) {
        let j = rng.gen_range(0 as f64, i as f64) as usize;
        data.swap(i, j);
    }
}

pub fn unshuffle(data: &mut [u8], seed: u64,step: usize) {
    let mut rng = SimpleRng::new(seed);
    let len=data.len();
    let swap_count = len / step + if len % step != 0 { 1 } else { 0 };
    let mut swaps = Vec::with_capacity(swap_count);

    for i in (1..len).rev().step_by(step) {
            let j = rng.gen_range(0 as f64, i as f64) as usize;
            swaps.push((i, j));
    }

    for &(i, j) in swaps.iter().rev() {
        data.swap(i, j);
    }
}


#[inline]
pub fn mix(block_size: usize, buf: &mut [u8], key: &[u8]) {
    let mut prev_block = key;

    for block in buf.chunks_exact_mut(block_size) {
        for j in 0..block_size {
            block[j] ^= prev_block[j];
        }
        prev_block = block;
    }
}

#[inline]
pub fn unmix(block_size: usize, buf: &mut [u8], key: &[u8]) {
    let mut chunks = buf.chunks_exact_mut(block_size).collect::<Vec<_>>();

    for i in (0..chunks.len()).rev() {
        if i == 0 {
            for j in 0..block_size {
                chunks[i][j] ^= key[j];
            }
        } else {
            for j in 0..block_size {
                chunks[i][j] ^= chunks[i - 1][j];
            }
        };
    }
}
