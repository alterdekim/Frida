// Veil
// Make it hidden.

/*fn main() {
    let mut small_rng = SmallRng::from_entropy();
    let b = Veil::init(&mut small_rng);
    println!("Hello, world! Noise val: {}", b.noise(10.0));
}*/

use core::f32::consts::E;
use core::f32::consts::PI;
use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;
use rand::RngCore;

pub struct Veil {
    factor_e: f32,
    factor_pi: f32,
    factor_f: f32,
    scale_e: f32,
    scale_pi: f32,
    scale_f: f32,
    factor_t: f32
}

impl Veil {
    fn default() -> Veil {
        Veil{ factor_e: -1.2, factor_pi: 1.9, factor_f: -3.2, factor_t: 0.3, scale_e: -1.7, scale_f: -1.3, scale_pi: 0.7 }
    }

    fn init(small_rng: &mut SmallRng) -> Veil {
        Veil { factor_e: gen_rnd(small_rng), 
            factor_pi: gen_rnd(small_rng), 
            factor_f: gen_rnd(small_rng), 
            scale_e: gen_rnd(small_rng), 
            scale_pi: gen_rnd(small_rng), 
            scale_f: gen_rnd(small_rng), 
            factor_t: gen_rnd(small_rng) }
    }

    fn noise(&self, x: f32) -> f32 {
        self.factor_t * (self.factor_f * (self.scale_f * x).sin() + self.factor_e*(self.scale_e * E * x).sin() + self.factor_pi * (self.scale_pi * PI * x).sin())
    }
}

fn gen_rnd(small_rng: &mut SmallRng) -> f32 {
    (small_rng.gen_range(-8..=8) as f32) / 2.0
}
