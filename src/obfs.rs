use chrono::{Timelike, Utc};
use rand::{rngs::OsRng, RngCore};

pub struct VEIL {
}

pub struct XOR {

}

pub struct DNS {
    rng: OsRng
}

impl Obfuscator for DNS {
    fn obfuscate(&mut self, plain: Vec<u8>) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        let mut tr_id = [0u8; 2];
        self.rng.fill_bytes(&mut tr_id);
        result.extend(tr_id);
        let flags = [01u8, 00];
        result.extend(flags);
        let mut questions = [0u8; 2];
        self.rng.fill_bytes(&mut questions);
        result.extend(questions);
        let rr = [0u8,0,0,0,0,0];
        result.extend(rr);
        result.extend(&plain[..]);
        let end = [0u8, 1, 0, 1];
        result.extend(end);
        result
    }

    fn deobfuscate(&mut self, obfs: Vec<u8>) -> Vec<u8> {
        let s = &mut obfs[11..].to_vec();
        s.truncate(s.len()-4);
        s.to_vec()
    }
}

impl Obfuscator for XOR {
    fn obfuscate(&mut self, plain: Vec<u8>) -> Vec<u8> {
        let t: u8 = Utc::now().minute() as u8;
        plain.iter().map(|i| i ^ t).collect::<Vec<u8>>()
    }

    fn deobfuscate(&mut self, obfs: Vec<u8>) -> Vec<u8> {
        self.obfuscate(obfs)
    }
}

pub trait Obfuscator {
    fn obfuscate(&mut self, plain: Vec<u8>) -> Vec<u8>;
    fn deobfuscate(&mut self, obfs: Vec<u8>) -> Vec<u8>;
}