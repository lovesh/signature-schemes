extern crate rand;
extern crate amcl;

use rand::RngCore;
use rand::rngs::EntropyRng;

use self::amcl::rand::{RAND};

pub fn get_seeded_RNG(entropy_size: usize, rng: Option<EntropyRng>) -> RAND {
    // initialise from at least 128 byte string of raw random entropy
    let mut entropy = vec![0; entropy_size];
    match rng {
        Some(mut rng) =>  rng.fill_bytes(&mut entropy.as_mut_slice()),
        None => {
            let mut rng = EntropyRng::new();
            rng.fill_bytes(&mut entropy.as_mut_slice());
        }
    }
    let mut r = RAND::new();
    r.clean();
    r.seed(entropy_size, &entropy);
    r
}