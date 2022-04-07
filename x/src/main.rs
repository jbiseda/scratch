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
use std::mem::size_of;
//use std::intrinsics::discriminant_value;
use core::mem::discriminant;
use sha2::{Digest, Sha256};


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



pub type Slot = u64;
pub type Nonce = u32;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ContactInfo {
    abc: u64,
}



/// Window protocol messages
#[derive(Serialize, Deserialize, Debug)]
#[repr(C)]
pub enum RepairProtocol {
    WindowIndex(ContactInfo, Slot, u64),
    HighestWindowIndex(ContactInfo, Slot, u64),
    Orphan(ContactInfo, Slot),
    WindowIndexWithNonce(ContactInfo, Slot, u64, Nonce),
    HighestWindowIndexWithNonce(ContactInfo, Slot, u64, Nonce),
    OrphanWithNonce(ContactInfo, Slot, Nonce),
    AncestorHashes(ContactInfo, Slot, Nonce),
    CodingWithNonce(ContactInfo, Slot, u64, Nonce),
}

#[repr(C)]
pub enum Enum1 {
    Zero = 0,
    One = 1,
    Two = 2,
}


fn abc() {

    let x = RepairProtocol::Orphan(ContactInfo::default(), Slot::default());
    dbg!(size_of::<RepairProtocol>());
    dbg!(&x);
    //dbg!(discriminant_value(&x));
    dbg!(discriminant(&x));
    dbg!(size_of::<Enum1>());
}


fn sysctl_read(name: &str) {
    use sysctl::{CtlValue::String, Sysctl};
    if let Ok(ctl) = sysctl::Ctl::new(name) {
        //info!("Old {} value {:?}", name, ctl.value());

        println!("name={}", name);
        println!("ctl={:?}", ctl);
        println!("ctl.description()={:?}", ctl.description());
        println!("ctl.value()={:?}", ctl.value());
        println!("ctl.value_string()={:?}", ctl.value_string());


//        let my_int = my_string.parse::<i32>().unwrap();

        let value_string = ctl.value_string().unwrap();
        let my_int = value_string.parse::<i64>().unwrap();

        println!(">>> {}", my_int);


        /*
        let ctl_value = String(value.to_string());
        match ctl.set_value(String(value.to_string())) {
            Ok(v) if v == ctl_value => info!("Updated {} to {:?}", name, ctl_value),
            Ok(v) => info!(
                "Update returned success but {} was set to {:?}, instead of {:?}",
                name, v, ctl_value
            ),
            Err(e) => error!("Failed to set {} to {:?}. Err {:?}", name, ctl_value, e),
        }
        */
    } else {
        //error!("Failed to find sysctl {}", name);
    }
}


type QHash = [u8; 1];
type QProof = Vec<QHash>;

pub struct MerkleTree {
    tree: Vec<QHash>,
    nleaves: usize,
}

impl MerkleTree {
    pub fn new(_leaf_count: usize) -> Self {
        Self {
            tree: Vec::with_capacity(16 * 2 - 1),
            nleaves: 16,
        }
    }
}


fn qhash(bufs: &[&[u8]]) -> QHash {
    let mut hasher = Sha256::new();
    for b in bufs {
        hasher.update(b);
    }
    let h = hasher.finalize();
    let mut ret = [0u8; 1];
    ret[..].copy_from_slice(&h.as_slice()[0..1]);
    ret
}


// leaves padded to power of 2
fn gen_tree(leaves: &Vec<QHash>) -> Vec<[u8; 1]> {
    let tree_size = leaves.len() * 2 - 1;
    let mut tree = Vec::with_capacity(tree_size);

    println!("--- gen tree ---");

    for i in 0..leaves.len() {
        //tree[i] = leaves[i];
        tree.push(leaves[i]);
    }

    let mut base = 0;
    let mut level_leaves = leaves.len();
    while level_leaves > 1 {
        for i in (0..level_leaves).step_by(2) {
            let hash = qhash(&[&tree[base+i], &tree[base+i+1]]);
            //tree[base+i/2] = hash;
            println!("push({:?})", &hash);
            tree.push(hash);
        }
        println!("");
        base += level_leaves;
        level_leaves /= 2;
    }

    tree
}

fn gen_proof(tree: &Vec<[u8; 1]>, nleaves: usize, idx: usize) -> QProof {
    let mut proof = Vec::new();
    let mut level_leaves = nleaves;
    let mut i = idx;
    let mut base = 0;
    while level_leaves > 1 {
        if i % 2 == 0 {
            proof.push(tree[base + i + 1]);
        } else {
            proof.push(tree[base + i - 1]);
        }
        base += level_leaves;
        i /= 2;
        level_leaves /= 2;
    }
    proof
}

fn check_proof(proof: &QProof, root: &QHash, start: &QHash, idx: usize) -> bool {
    println!("--- proving {:?} for {:?} --- ", start, root);
    let mut hash = start.clone();
    let mut j = idx;
    for i in 0..proof.len() {
        hash = if j % 2 == 0 {
            qhash(&[&hash, &proof[i]])
        } else {
            qhash(&[&proof[i], &hash])
        };
        println!("{:?}", &hash);
        j /= 2;
    }
    &hash == root
}


fn merkle_stuff() {

    let mut rng = rand::thread_rng();

    let mut packets = Vec::default();

    for i in 0..16 {
        let buf: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
        packets.push(buf);
    }

    let leaves: Vec<[u8; 1]> = packets.iter().map(|p| qhash(&[&p])).collect();

    let tree = gen_tree(&leaves);

    let mut base = 0;
    let mut nleaves = 16;
    while nleaves > 0 {
        println!("{:?}", &tree[base..base+nleaves]);
        base += nleaves;
        nleaves /= 2;
    }

    println!("tree: {:?}", &tree);

    let root = tree[tree.len() - 1];
    println!("root: {:?}", &root);

    let proof5 = gen_proof(&tree, 16, 5);
    println!("proof5: {:?}", &proof5);

    let res = check_proof(&proof5, &root, &leaves[5], 5);
    println!("res: {}", res);

}

fn main() {
    merkle_stuff();

    //test_socket_stuff();

    //read_snmp_file();

    /*
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

    abc();

    sysctl_read("security.mac.amfi.platform_ident_for_hardened_proc");
    */
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
