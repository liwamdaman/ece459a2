// Starter code for ECE 459 Lab 2, Winter 2021

// YOU SHOULD MODIFY THIS FILE TO USE THREADING AND SHARED MEMORY

#![warn(clippy::all)]

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use std::{env, thread, time};
use std::sync::{Arc, Mutex};
use threadpool::ThreadPool;

const DEFAULT_ALPHABETS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

type HmacSha256 = Hmac<Sha256>;

// Check if a JWT secret is correct
fn is_secret_valid(msg: &[u8], sig: &[u8], secret: &[u8]) -> bool {
    let mut mac = HmacSha256::new_varkey(secret).unwrap();
    mac.update(msg);
    mac.verify(sig).is_ok()
}

// Contextual info for solving a JWT
struct JwtSolver {
    alphabet: Vec<u8>, // set of possible bytes in the secret
    max_len: usize,    // max length of the secret
    msg: Vec<u8>,      // JWT message
    sig64: Vec<u8>,    // JWT signature (base64 decoded)
}

impl JwtSolver {
    // Iteratively check every possible secret string using iterative deepening DFS, returning the correct secret if it exists.
    // This function was changed from recursive logic to iterative because I was running into issues with sharing the thread-pool itself into recursive threads.
    // Iterative deepening DFS is also much more performant compared to recursion (regular DFS) if the max_len is overestimated.
    fn check_all(&self, secret: Vec<u8>) -> Vec<u8> {
        let thread_pool = ThreadPool::new(num_cpus::get());
        let answer = Arc::new(Mutex::new(Vec::new()));

        for depth in 1..self.max_len {
            let mut stack: Vec<Vec<u8>> = vec![];
            stack.push(secret.clone());
            while !stack.is_empty() {
                let curr_secret = stack.pop().unwrap();
                // println!("{}", std::str::from_utf8(&curr_secret).expect("answer not a valid string"));

                let msg = self.msg.clone();
                let sig64 = self.sig64.clone();
                let curr_secret_clone = curr_secret.clone();

                let thread_answer = Arc::clone(&answer);
                thread_pool.execute(move || {
                    if is_secret_valid(&msg, &sig64, &curr_secret_clone) {
                        let mut ans = thread_answer.lock().unwrap();
                        *ans = curr_secret_clone;
                    }
                });

                if curr_secret.len() <= depth {
                    for &c in self.alphabet.iter() {
                        // allocate space for a secret one character longer
                        let mut new_secret = Vec::with_capacity(curr_secret.len() + 1);
                        // build the new secret
                        new_secret.extend(curr_secret.iter().chain(&mut [c].iter()));
                        // check this secret, and recursively check longer ones
                        stack.push(new_secret);
                    }
                }
                // check once per iteration to see if we have already found the secret
                {
                    let ans = answer.lock().unwrap();
                    if !ans.is_empty() {
                        return (*ans).clone();
                    }
                }
            }
        }

        // Block until we get the answer, we assume that we will not test with unsolvable test cases.
        loop {
            let ans = answer.lock().unwrap();
            if !ans.is_empty() {
                return (*ans).clone();
            }
            thread::sleep(time::Duration::from_millis(250));
        }
    }
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 3 {
        eprintln!("Usage: <token> <max_len> [alphabet]");
        return;
    }

    let token = &args[1];

    let max_len = match args[2].parse::<u32>() {
        Ok(len) => len,
        Err(_) => {
            eprintln!("Invalid max length");
            return;
        }
    };

    let alphabet = args
        .get(3)
        .map(|a| a.as_bytes())
        .unwrap_or(DEFAULT_ALPHABETS)
        .into();

    // find index of last '.'
    let dot = match token.rfind('.') {
        Some(pos) => pos,
        None => {
            eprintln!("No dot found in token");
            return;
        }
    };

    // message is everything before the last dot
    let msg = token.as_bytes()[..dot].to_vec();
    // signature is everything after the last dot
    let sig = &token.as_bytes()[dot + 1..];

    // convert base64 encoding into binary
    let sig64 = match base64::decode_config(sig, base64::URL_SAFE_NO_PAD) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("Invalid signature");
            return;
        }
    };

    // build the solver and run it to get the answer
    let solver = JwtSolver {
        alphabet,
        max_len: max_len as usize,
        msg,
        sig64,
    };

    let ans = solver.check_all(b"".to_vec());
    println!("{}", std::str::from_utf8(&ans).expect("answer not a valid string"));
}
