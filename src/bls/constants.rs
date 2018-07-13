extern crate amcl;

use self::amcl::arch::Chunk;
use BLSCurve::rom;
use BLSCurve::big::{NLEN, MODBYTES as bls381_MODBYTES};
use super::types::{GroupG1, GroupG2};

pub const CURVE_ORDER: [Chunk; NLEN] = rom::CURVE_ORDER;
pub const MODBYTES: usize = bls381_MODBYTES;
pub const FP12_SIZE: usize = (12 * MODBYTES) as usize;
// Byte size of element in group G2
pub const GroupG2_SIZE: usize = (4 * MODBYTES) as usize;

lazy_static! {
    pub static ref GeneratorG1: GroupG1 = GroupG1::generator();
    pub static ref GeneratorG2: GroupG2 = GroupG2::generator();
}
