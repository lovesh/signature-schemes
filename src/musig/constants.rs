extern crate amcl;

use self::amcl::arch::Chunk;
use SchnorrCurve::rom;
use SchnorrCurve::big::{NLEN, MODBYTES as secp256k1_MODBYTES};
use super::types::{GroupG, BigNum};

pub const CURVE_ORDER: [Chunk; NLEN] = rom::CURVE_ORDER;
pub const MODBYTES: usize = secp256k1_MODBYTES;
// Byte size of element in group G
pub const GroupG_Size: usize = (2 * MODBYTES + 1) as usize;

lazy_static! {
    pub static ref GeneratorG: GroupG = GroupG::generator();
    pub static ref CurveOrder: BigNum = BigNum::new_ints(&CURVE_ORDER);
}
