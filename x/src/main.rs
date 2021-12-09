//use rand::{Rng, SeedableRng, StdRng};
#[cfg(target_os = "linux")]
use procfs::process::FDTarget;
#[cfg(target_os = "linux")]
use procfs::process::Process;

use bincode::config::Options;
use rand::distributions::{Distribution, Uniform};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::collections::HashMap;
use std::time::Instant;
use std::fs::File;
use std::io::{BufRead, BufReader};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;


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

#[cfg(target_os = "linux")]
fn test_socket_stuff() {
    let all_procs = procfs::process::all_processes().unwrap();

    // build up a map between socket inodes and processes:
    let mut map: HashMap<u64, &Process> = HashMap::new();
    for process in &all_procs {
        println!("process: {:?}", process.exe());
        println!("       : {:?}", process.cmdline());
        if let Ok(fds) = process.fd() {
            for fd in fds {
                println!("  fd:{:?}", fd);
                if let FDTarget::Socket(inode) = fd.target {
                    println!("  inode:{}", inode);
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
                "{:<26} {:<26} {:?} {:<12} {}/{}",
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
                "{:<26} {:<26} {:?} {:<12} -",
                entry.local_address, entry.remote_address, entry.state, entry.inode,
            );
        }
    }

    let dev_stat = procfs::net::dev_status().unwrap();
    for entry in dev_stat {
        println!("{:?}", entry);
    }
}

fn read_udp_stats(file_path: &str) -> Result<HashMap<String, usize>, String> {
    let file = File::open(file_path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);

    let mut udp_lines = Vec::default();
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.starts_with("Udp:") {
            udp_lines.push(line);
            if udp_lines.len() == 2 {
                break;
            }
        }
    }
    if udp_lines.len() != 2 {
        return Err(format!("parse error, expected 2 lines, num lines: {}", udp_lines.len()));
    }

    let pairs: Vec<_> = udp_lines[0].split_ascii_whitespace().zip(udp_lines[1].split_ascii_whitespace()).collect();
    let udp_stats: HashMap<_, _> = pairs[1..].iter().map(|(label, val)| (label.to_string(), val.parse::<usize>().unwrap())).collect();

    Ok(udp_stats)
}



fn read_snmp_file() {

    //let file_path = "/proc/net/snmp";
    let file_path = "/Volumes/solana/tmp/mock.snmp";

    /*
    Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti
    Udp: 27 7 0 30 0 0 0 0
    */

    let udp_stats = read_udp_stats(file_path).unwrap();

    let out_datagrams = udp_stats.get("OutDatagrams").unwrap();

    println!("out_datagrams: {}", out_datagrams);
}


#[derive(Debug, Default, Clone)]
struct TestStruct {
    one: u64,
    two: u64,
}

impl TestStruct {

    fn sum(&self) -> u64 {
        self.one + self.two
    }
}



fn main() {
    println!("Hello, world!");

    //test_socket_stuff();

    read_snmp_file();

    let platform = format!(
        "{}/{}/{}",
        std::env::consts::FAMILY,
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    println!("platform string: {}", platform);

    let t = TestStruct::default();

    println!("TestStruct {:?}", &t);
    println!("TestStruct sum:{}", t.sum());
}

#[cfg(test)]
mod tests {
    use {
        super::*,
    };
    /*
    use {
        super::*,
        bincode::serialize,
        solana_ledger::{blockstore::Blockstore, blockstore_meta::SlotMeta, get_tmp_ledger_path},
        solana_perf::test_tx::test_tx,
        solana_sdk::{clock::DEFAULT_TICKS_PER_SLOT, hash::hash},
        std::sync::mpsc::sync_channel,
    };

    #[test]
    fn test_poh_recorder_no_zero_tick() {
        let prev_hash = Hash::default();
        let ledger_path = get_tmp_ledger_path!();
        {
        }
    }
    */

    #[test]
    fn test_teststruct() {
        let t = TestStruct::default();
        let sum = t.sum();
        assert_eq!(sum, 0);
    }
}
