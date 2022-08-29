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
use std::{
    net::{UdpSocket, SocketAddr},
    thread::{Builder, JoinHandle},
    time::{SystemTime, Duration},
    sync::Arc,
};
//use std::intrinsics::discriminant_value;
use core::mem::discriminant;
use generic_array::{typenum::U64, GenericArray};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use bytemuck::{Pod, Zeroable};
//use ed25519_dalek::Signer as DalekSigner;
//use ed25519_dalek_bip32::Error as Bip32Error;
use ed25519_dalek;
use ed25519_dalek::Signer as DalekSigner;
//use ed25519_dalek::Digest;
use sha2::{Sha256, Digest};
use bincode::{serialize, deserialize};
use rand::{AsByteSliceMut, CryptoRng, RngCore, rngs::OsRng};





/// Size of a hash in bytes.
pub const HASH_BYTES: usize = 32;

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Clone,
    Copy,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
)]
#[repr(transparent)]
pub struct Hash(pub(crate) [u8; HASH_BYTES]);

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}


pub type Nonce = u32;

#[repr(transparent)]
#[derive(
    Serialize, Deserialize, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Debug,
)]
pub struct Signature(GenericArray<u8, U64>);

impl Signature {
    pub fn new(signature_slice: &[u8]) -> Self {
        Self(GenericArray::clone_from_slice(signature_slice))
    }
}

#[derive(Debug)]
pub struct Keypair(ed25519_dalek::Keypair);

impl Keypair {
    /// Constructs a new, random `Keypair` using a caller-provided RNG
    pub fn generate<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        Self(ed25519_dalek::Keypair::generate(csprng))
    }

    /// Constructs a new, random `Keypair` using `OsRng`
    pub fn new() -> Self {
        let mut rng = OsRng::default();
        Self::generate(&mut rng)
    }

    /// Recovers a `Keypair` from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ed25519_dalek::SignatureError> {
        ed25519_dalek::Keypair::from_bytes(bytes).map(Self)
    }

    /// Returns this `Keypair` as a byte array
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// Recovers a `Keypair` from a base58-encoded string
    pub fn from_base58_string(s: &str) -> Self {
        Self::from_bytes(&bs58::decode(s).into_vec().unwrap()).unwrap()
    }

    /// Returns this `Keypair` as a base58-encoded string
    pub fn to_base58_string(&self) -> String {
        bs58::encode(&self.0.to_bytes()).into_string()
    }

    /// Gets this `Keypair`'s SecretKey
    pub fn secret(&self) -> &ed25519_dalek::SecretKey {
        &self.0.secret
    }
}

pub trait Signer {
    /// Infallibly gets the implementor's public key. Returns the all-zeros
    /// `Pubkey` if the implementor has none.
    fn pubkey(&self) -> Pubkey {
        self.try_pubkey()
    }
    /// Fallibly gets the implementor's public key
    fn try_pubkey(&self) -> Pubkey;
    /// Infallibly produces an Ed25519 signature over the provided `message`
    /// bytes. Returns the all-zeros `Signature` if signing is not possible.
    fn sign_message(&self, message: &[u8]) -> Signature {
        self.try_sign_message(message)
    }
    /// Fallibly produces an Ed25519 signature over the provided `message` bytes.
    fn try_sign_message(&self, message: &[u8]) -> Signature;
    /// Whether the impelmentation requires user interaction to sign
    fn is_interactive(&self) -> bool;
}

impl Signer for Keypair {
    fn pubkey(&self) -> Pubkey {
        Pubkey::new(self.0.public.as_ref())
    }

    fn try_pubkey(&self) -> Pubkey {
        self.pubkey()
    }

    fn sign_message(&self, message: &[u8]) -> Signature {
        Signature::new(&self.0.sign(message).to_bytes())
    }

    fn try_sign_message(&self, message: &[u8]) -> Signature {
        self.sign_message(message)
    }

    fn is_interactive(&self) -> bool {
        false
    }
}


//#[wasm_bindgen]
#[repr(transparent)]
#[derive(
    BorshDeserialize,
    BorshSchema,
    BorshSerialize,
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Pod,
    Serialize,
    Zeroable,
    Debug,
)]
pub struct Pubkey(pub(crate) [u8; 32]);

impl Pubkey {
    pub fn new(pubkey_vec: &[u8]) -> Self {
        Self(
            <[u8; 32]>::try_from(<&[u8]>::clone(&pubkey_vec))
                .expect("Slice must be the same length as a Pubkey"),
        )
    }
}


#[derive(Debug, Deserialize, Serialize)]
pub struct PingInner<T> {
    from: Pubkey,
    token: T,
    signature: Signature,
}

type Ping = PingInner<[u8; 32]>;
type Slot = u64;

#[derive(Debug, Deserialize, Serialize)]
pub struct PongInner {
    from: Pubkey,
    hash: Hash, // Hash of received ping token.
    signature: Signature,
}

impl PongInner {
    pub fn new<T: Serialize>(
        ping: &PingInner<T>,
        keypair: &Keypair,
    ) -> Self {
        let token = serialize(&ping.token).unwrap();
//        let hash = if domain {
//            hash::hashv(&[PING_PONG_HASH_PREFIX, &token])
//        } else {
//            hash::hash(&token)
//        };
        let hashval = hash(&token);
        let pong = PongInner {
            from: keypair.pubkey(),
            hash: hashval,
            signature: keypair.sign_message(hashval.as_ref()),
        };
        pong
    }

    pub fn from(&self) -> &Pubkey {
        &self.from
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct RepairRequestHeader {
    signature: Signature,
    sender: Pubkey,
    recipient: Pubkey,
    timestamp: u64,
    nonce: Nonce,
}

/// Window protocol messages
#[derive(Serialize, Deserialize, Debug)]
pub enum RepairProtocol {
    LegacyWindowIndex,
    LegacyHighestWindowIndex,
    LegacyOrphan,
    LegacyWindowIndexWithNonce,
    LegacyHighestWindowIndexWithNonce,
    LegacyOrphanWithNonce,
    LegacyAncestorHashes,
    Pong(PongInner),
    WindowIndex,
    HighestWindowIndex,
    Orphan {
        header: RepairRequestHeader,
        slot: Slot,
    },
    AncestorHashes,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum RepairResponse {
    Ping(Ping),
}


#[derive(Clone, Default)]
pub struct Hasher {
    hasher: Sha256,
}

impl Hasher {
    pub fn hash(&mut self, val: &[u8]) {
        self.hasher.update(val);
    }
    pub fn hashv(&mut self, vals: &[&[u8]]) {
        for val in vals {
            self.hash(val);
        }
    }
    pub fn result(self) -> Hash {
        // At the time of this writing, the sha2 library is stuck on an old version
        // of generic_array (0.9.0). Decouple ourselves with a clone to our version.
        Hash(<[u8; HASH_BYTES]>::try_from(self.hasher.finalize().as_slice()).unwrap())
    }
}

pub fn hashv(vals: &[&[u8]]) -> Hash {
    // Perform the calculation inline, calling this from within a program is
    // not supported
    {
        let mut hasher = Hasher::default();
        hasher.hashv(vals);
        hasher.result()
    }
}

pub fn hash(val: &[u8]) -> Hash {
    hashv(&[val])
}

#[macro_export]
macro_rules! unchecked_div_by_const {
    ($num:expr, $den:expr) => {{
        // Ensure the denominator is compile-time constant
        let _ = [(); ($den - $den) as usize];
        // Compile-time constant integer div-by-zero passes for some reason
        // when invoked from a compilation unit other than that where this
        // macro is defined. Do an explicit zero-check for now. Sorry about the
        // ugly error messages!
        // https://users.rust-lang.org/t/unexpected-behavior-of-compile-time-integer-div-by-zero-check-in-declarative-macro/56718
        let _ = [(); ($den as usize) - 1];
        #[allow(clippy::integer_arithmetic)]
        let quotient = $num / $den;
        quotient
    }};
}

pub fn duration_as_ms(d: &Duration) -> u64 {
    d.as_secs()
        .saturating_mul(1000)
        .saturating_add(unchecked_div_by_const!(
            u64::from(d.subsec_nanos()),
            1_000_000
        ))
}

pub fn timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("create timestamp in timing");
    duration_as_ms(&now)
}

/*
impl FromStr for Pubkey {
    type Err = ParsePubkeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_BASE58_LEN {
            return Err(ParsePubkeyError::WrongSize);
        }
        let pubkey_vec = bs58::decode(s)
            .into_vec()
            .map_err(|_| ParsePubkeyError::Invalid)?;
        if pubkey_vec.len() != mem::size_of::<Pubkey>() {
            Err(ParsePubkeyError::WrongSize)
        } else {
            Ok(Pubkey::new(&pubkey_vec))
        }
    }
}
*/

pub const SIGNATURE_BYTES: usize = 64;

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}


pub fn repair_proto_to_bytes(
    request: &RepairProtocol,
    keypair: &Keypair,
) -> Vec<u8> {
    let mut payload = serialize(&request).unwrap();
    let signable_data = [&payload[..4], &payload[4 + SIGNATURE_BYTES..]].concat();
    let signature = keypair.sign_message(&signable_data[..]);
    payload[4..4 + SIGNATURE_BYTES].copy_from_slice(signature.as_ref());
    payload
}



fn send_pong(
    keypair: &Keypair,
    socket: &UdpSocket,
    to: &SocketAddr,
    ping: &PingInner<[u8; 32]>
) {
    let pong_inner = PongInner::new(ping, keypair);
    let req = RepairProtocol::Pong(pong_inner);
    let pktbuf = serialize(&req).unwrap();
    socket.send_to(&pktbuf, to).unwrap();
}


/*
fn start_recver(keypair: Arc<Keypair>, socket: Arc<UdpSocket>) -> JoinHandle<()> {
    Builder::new()
        .name("recv".to_string())
        .spawn(move || {
            loop {
                let mut buffer: Vec<u8> = vec![0; 1500];
                match socket.recv_from(&mut buffer) {
                    Err(e) => break,
                    Ok((nrecv, from)) => {
                        println!("recv {} bytes from {:?}", nrecv, &from);
                        let rsp: RepairResponse = deserialize(&buffer[..nrecv]).unwrap();
                        match rsp {
                            RepairResponse::Ping(ping) => {
                                send_pong(&keypair, &socket, &from, &ping);
                            }
                        };
                    },
                }
            };
        })
        .unwrap()
}
*/

/*
fn send_orphans(keypair: &Keypair, target_pubkey: &Pubkey) {
    let mut nonce: u32 = 123;
    let mut slot: u64 = 123;
    loop {
        let req = RepairProtocol::Orphan {
            header: RepairRequestHeader {
                signature: Signature::default(),
                sender: keypair.pubkey(),
                recipient: *target_pubkey,
                timestamp: timestamp(),
                nonce,
            },
            slot,
        };
        nonce += 1;
        slot += 1;
    }
}
*/

fn send_orphan(
    keypair: &Keypair,
    socket: &UdpSocket,
    target_pubkey: &Pubkey,
    target_addr: &SocketAddr,
) {
    let nonce: u32 = 123;
    let slot: u64 = 123;
    let req = RepairProtocol::Orphan {
        header: RepairRequestHeader {
            signature: Signature::default(),
            sender: keypair.pubkey(),
            recipient: *target_pubkey,
            timestamp: timestamp(),
            nonce,
        },
        slot,
    };
    let pktbuf = repair_proto_to_bytes(&req, keypair);
    println!("sending to {:?} --- {:?} --- {:?}", &target_addr, &req, &pktbuf);
    socket.send_to(&pktbuf, target_addr).unwrap();
}




fn test_ping() {
    println!("TEST PING");

    let argv: Vec<String> = std::env::args().collect();

    //let keypair = Keypair::new();
    //let keypair = Arc::new(keypair);

    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let socket = Arc::new(socket);
    println!("bind to socket {:?}", &socket);

    //let recv_handle = start_recver(keypair.clone(), socket.clone());
    //recv_handle.join();

    let target_addr: SocketAddr = argv[1].parse().unwrap();
    let pubkey_vec = bs58::decode(argv[2].to_string()).into_vec().unwrap();
    let target_pubkey = Pubkey::new(&pubkey_vec);

    loop {
        let keypair = Keypair::new();
        send_orphan(&keypair, &socket, &target_pubkey, &target_addr);
        let mut buffer: Vec<u8> = vec![0; 1500];

        socket.set_read_timeout(Some(Duration::new(1, 0))).unwrap();

        match socket.recv_from(&mut buffer) {
            Err(e) => {
                println!("ERR: {:?}", &e);
            },
            Ok((nrecv, from)) => {
                println!("recv {} bytes from {:?}", nrecv, &from);
                let rsp: RepairResponse = deserialize(&buffer[..nrecv]).unwrap();
                match rsp {
                    RepairResponse::Ping(ping) => {
                        println!("sending pong");
                        send_pong(&keypair, &socket, &from, &ping);
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(1_000));
    }

}



fn main() {

    test_ping();

}

#[cfg(test)]
mod tests {
    use {
        super::*,
    };


    #[test]
    fn test_teststruct() {
    }
}
