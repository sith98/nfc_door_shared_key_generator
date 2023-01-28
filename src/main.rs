use hex::encode_upper as hex_encode;
use hex_literal::hex;
use hkdf::Hkdf;
use sha2::Sha256;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        println!("Please pass in a password");
        return;
    }
    let password = args[1..].join(" ");
    let ikm = &password;
    let salt = hex!("3c ca 2d 88 15 fd a8 31 48 e7 74 e4 7b 05 53 2d");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), ikm.as_bytes());
    let mut okm = [0u8; 16];
    hk.expand(&info, &mut okm)
        .expect("42 is a valid length for Sha256 to output");

    let hex_string = hex_encode(okm);

    println!("{}", hex_string);
}
