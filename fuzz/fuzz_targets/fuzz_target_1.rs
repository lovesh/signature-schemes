#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate multi_sigs;

use multi_sigs::bls::amcl_utils::{get_G1_point_from_bytes, get_G2_point_from_bytes,
                                  hash_on_GroupG1, hash_on_GroupG2, hash_as_BigNum as hash_bls};
use multi_sigs::musig::amcl_utils::hash_as_BigNum as hash_musig;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = get_G1_point_from_bytes(data);
    let _ = get_G2_point_from_bytes(data);
    let _ = hash_on_GroupG1(data);
    let _ = hash_on_GroupG2(data);
    let _ = hash_bls(data);
    let _ = hash_musig(data);
});
