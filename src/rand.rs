use std::time::{SystemTime, UNIX_EPOCH};

pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    /// Creates a new random number generator with a seed
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn new_with_time_seed() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self::new(seed)
    }

    /// Generates a random u32 number
    pub fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }

    /// Generates a random u64 number
    pub fn next_u64(&mut self) -> u64 {
        let high = self.next_u32() as u64;
        let low = self.next_u32() as u64;
        (high << 32) | low
    }

    /// Generates a random number in the range [0, 1)
    pub fn next_f64(&mut self) -> f64 {
        let val = self.next_u32();
        f64::from(val) / f64::from(u32::MAX)
    }

    /// Generates a random number in the given range [low, high)
    pub fn gen_range(&mut self, low: f64, high: f64) -> f64 {
        low + (high - low) * self.next_f64()
    }

    pub fn get_random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len);
        let chunks = len / 4;
        let remainder = len % 4;

        // Process 4-byte chunks
        for _ in 0..chunks {
            let random = self.next_u32();
            bytes.extend_from_slice(&random.to_le_bytes());
        }

        // Process remaining bytes (0-3)
        if remainder > 0 {
            let random = self.next_u32().to_le_bytes();
            bytes.extend_from_slice(&random[..remainder]);
        }

        bytes
    }
}