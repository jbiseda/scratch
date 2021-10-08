//use rand::{Rng, SeedableRng, StdRng};
use procfs::process::FDTarget;
use procfs::process::Process;
use rand::distributions::{Distribution, Uniform};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::collections::HashMap;
use std::time::Instant;

fn get_seed() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = rng.gen_range(0, u8::MAX);
    }
    //println!("seed: {:?}", seed);
    seed
}

fn test_existing() {
    let mut rng = ChaChaRng::from_seed(get_seed());
    for _ in 0..1_000 {
        let _x = rng.gen_range(1, u128::from(std::u16::MAX));
    }
}

fn test_updated() {
    let mut rng = ChaChaRng::from_seed(get_seed());
    let between = Uniform::from(1..std::u16::MAX);
    for _ in 0..1_000 {
        let _x = between.sample(&mut rng);
    }
}

fn _test_random_perf() {
    let ts = Instant::now();
    for _ in 0..1_000 {
        test_existing();
    }
    let elapsed = ts.elapsed();
    println!("existing: {}us", elapsed.as_micros());

    let ts = Instant::now();
    for _ in 0..1_000 {
        test_updated();
    }
    let elapsed = ts.elapsed();
    println!("updated: {}us", elapsed.as_micros());
}

fn test_socket_stuff() {
    let all_procs = procfs::process::all_processes().unwrap();

    // build up a map between socket inodes and processes:
    let mut map: HashMap<u64, &Process> = HashMap::new();
    for process in &all_procs {
        if let Ok(fds) = process.fd() {
            for fd in fds {
                if let FDTarget::Socket(inode) = fd.target {
                    map.insert(inode, process);
                }
            }
        }
    }

    // get the tcp table
    let tcp = procfs::net::tcp().unwrap();
    let tcp6 = procfs::net::tcp6().unwrap();
    println!(
        "{:<26} {:<26} {:<15} {:<8} {}",
        "Local address", "Remote address", "State", "Inode", "PID/Program name"
    );
    for entry in tcp.into_iter().chain(tcp6) {
        // find the process (if any) that has an open FD to this entry's inode
        let local_address = format!("{}", entry.local_address);
        let remote_addr = format!("{}", entry.remote_address);
        let state = format!("{:?}", entry.state);
        if let Some(process) = map.get(&entry.inode) {
            println!(
                "{:<26} {:<26} {:<15} {:<12} {}/{}",
                local_address, remote_addr, state, entry.inode, process.stat.pid, process.stat.comm,
            );
        } else {
            // We might not always be able to find the process assocated with this socket
            println!(
                "{:<26} {:<26} {:<15} {:<12} -",
                local_address, remote_addr, state, entry.inode
            );
        }
    }

    // get the udp table
    let udp = procfs::net::udp().unwrap();
    let udp6 = procfs::net::udp6().unwrap();
    for entry in udp.into_iter().chain(udp6) {
        println!("{:?}", entry);
        if let Some(process) = map.get(&entry.inode) {
            println!(
                "{:<26} {:<26} {:<15} {:<12} {}/{}",
                entry.local_address,
                entry.remote_address,
                entry.state,
                entry.inode,
                process.stat.pid,
                process.stat.comm,
            );
        } else {
            // We might not always be able to find the process assocated with this socket
            println!(
                "{:<26} {:<26} {:<15} {:<12} -",
                entry.local_address, entry.remote_address, entry.state, entry.inode,
            );
        }
    }
}

fn main() {
    println!("Hello, world!");

    test_socket_stuff();
}
