use std::io::{self, BufRead};
use std::convert::TryInto;
use std::env;

use colored::*;

const BLOCK_SIZE: usize = 24;
const EXTENDED_W_SIZE: usize = 30;
const TOTAL_ROUNDS: usize = 30;
const F_CONSTANTS:   [u32; 3] = [0xFE887401, 0x44C38316, 0x21221602];
const INITIAL_STATE: [u32; 4] = [0x5AC24860, 0xDA545106, 0x716ADFDB, 0x4DA893CC];

fn main() {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-t" => {
                run_tests();
                return;
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                return;
            }
        }
    }

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let hash = hash_message(&line);
        let formatted_hash = format_hash(&hash);
        println!("{}", formatted_hash);
    }
}

fn run_tests() {
    println!("Running hash tests...\n");

    let a_48000 = "a".repeat(48000);
    let a_48479 = "a".repeat(48479);
    let a_48958: String = "a".repeat(48958);
    
    let test_cases = vec![
        ("", "D6 25 F3 C2 59 B7 7B 18 5B 2D 37 FB A3 F2 B4 FD"),
        ("AbCxYz", "6C 9A BE 55 99 76 89 7E 50 22 49 F3 4E 02 86 13"),
        ("1234567890", "AE A3 7E 2D 47 1B 11 33 62 16 43 55 70 6B 2E 0A"),
        ("Ala ma kota, kot ma ale.", "CA 3D 4E E7 E2 49 BC 6A 83 5A F6 D8 1A 47 BC 18"),
        ("Ty, ktory wchodzisz, zegnaj sie z nadzieja.", "C4 08 85 6C 1A CA EC 4A 77 CF 9B 48 8D 0A 99 38"),
        ("Litwo, Ojczyzno moja! ty jestes jak zdrowie;", "70 56 97 1F 29 EE C0 81 1E F2 EA E8 61 91 72 DC"),
        (&a_48000, "76 B5 92 8C B3 F7 E1 FA 18 65 FA AA 35 9A CB AB"),
        (&a_48479, "96 3C E9 F8 EA 72 65 F9 EC 17 9A 5E CE E1 4D 62"),
        (&a_48958, "7D 50 64 ED 2A 8B 39 9D CE F1 34 E7 51 E9 4F EB"),
    ];

    for (input, expected_hash) in test_cases {
        let calculated_hash = hash_message(input);
        let formatted_hash = format_hash(&calculated_hash);

        println!("Expected:\t{}", expected_hash);
        println!("Calculated:\t{}", formatted_hash);
        println!("Test result:\t{}\n", if expected_hash == formatted_hash 
            { "Passed".green() } else { "Failed".red() });
    }
}

fn hash_message(message: &str) -> Vec<u8> {
    hash_message_bytes(message.as_bytes())
}

fn hash_message_bytes(bytes: &[u8]) -> Vec<u8> {
    let padded_message = pad_message(bytes);
    state_processing(&padded_message)
}

fn pad_message(message: &[u8]) -> Vec<u8> {
    let length_with_padding = (message.len() + BLOCK_SIZE) / BLOCK_SIZE * BLOCK_SIZE;
    let mut padded = message.to_vec();

    padded.push(0x80);
    while padded.len() < length_with_padding {
        padded.push(0x00);
    }

    padded
}

fn state_processing(padded_message: &[u8]) -> Vec<u8> {
    let initial_state_bytes: Vec<u8> = INITIAL_STATE
        .iter()
        .flat_map(|&x| x.to_be_bytes())
        .collect();

    process_blocks(&initial_state_bytes, padded_message)
}

fn process_blocks(state: &[u8], padded_message: &[u8]) -> Vec<u8> {
    let mut state = state.to_vec();

    for block in padded_message.chunks(BLOCK_SIZE) {
        state = process_block(&state, block);
    }

    state
}

fn process_block(state: &[u8], block: &[u8]) -> Vec<u8> {
    let mut w = [0u32; EXTENDED_W_SIZE];
    for (i, chunk) in block.chunks(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().expect("Invalid block slice length"));
    }

    extend_message_schedule(&mut w);

    let (mut a, mut b, mut c, mut d) = (
        u32::from_be_bytes(state[0..4].try_into().unwrap()),
        u32::from_be_bytes(state[4..8].try_into().unwrap()),
        u32::from_be_bytes(state[8..12].try_into().unwrap()),
        u32::from_be_bytes(state[12..16].try_into().unwrap()),
    );

    for i in 0..TOTAL_ROUNDS {
        let new_d = process_round(i, a, b, c, d, w[i]);
        (a, b, c, d) = (b, c, d, new_d);
    }

    [a, b, c, d].iter().flat_map(|&num| num.to_be_bytes().to_vec()).collect::<Vec<u8>>()
}

fn extend_message_schedule(w: &mut [u32]) {
    for i in 0..EXTENDED_W_SIZE - 6 {
        w[i + 6] = (w[i] ^ w[i + 1] ^ w[i + 3].wrapping_add(w[i + 5])).rotate_left(3);
    }
}

fn process_round(i: usize, a: u32, b: u32, c: u32, d: u32, wi: u32) -> u32 {
    match i {
        0..=9 => (a & b).wrapping_add(c.rotate_left(4) ^ !d).wrapping_add(wi).wrapping_add(F_CONSTANTS[0]),
        10..=19 => (a & b) ^ (!a & c) ^ (c & d.rotate_left(2)) ^ wi ^ F_CONSTANTS[1],
        20..=29 => (a ^ b.rotate_left(2) ^ c.rotate_left(4) ^ d.rotate_left(7)).wrapping_add(wi ^ F_CONSTANTS[2]),
        _ => 0,
    }
}

fn format_hash(hash: &[u8]) -> String {
    hash.iter().map(|byte| format!("{:02X} ", byte)).collect::<Vec<String>>().join("").trim().to_string()
}
