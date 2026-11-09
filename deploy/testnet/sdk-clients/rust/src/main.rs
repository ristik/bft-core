//! The public Rust SDK's trust-base acceptance client (bft-core #430 row 2): the SDK's own Session + FileStore against a live aggregator.
//! It verifies the trust-base entries the SDK supports; it is NOT a bridge verifier. One JSON object on stdout.
//!   sdk-trustbase-client --agg-url URL --network-id N --genesis-pin HEX --genesis FILE --store DIR --mode cold|warm|restart [--negatives DIR]
//!   sdk-trustbase-client --negatives DIR   (the offline negatives alone)
use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use serde_json::{json, Value};
use unicity_token::api::bft::trust_base_cache::{
    Authority, CacheError, Diagnostic, Flush, PinSpec, Session, SessionError, SessionOptions, StoreCas,
    StoreRead, TrustBaseStore,
};
use unicity_token::api::bft::trust_base_file_store::FileStore;
use unicity_token::api::bft::trust_base_update::{update, TrustBaseSource, UpdateOptions};
use unicity_token::api::bft::{Appended, HistoryError, TrustBaseEntry, TrustBaseError, TrustBaseHistory};
use unicity_token::api::NetworkId;
use unicity_token::client::HttpAggregatorClient;

static VT: RawWakerVTable = RawWakerVTable::new(|_| RawWaker::new(std::ptr::null(), &VT), |_| {}, |_| {}, |_| {});

fn block_on<F: Future>(f: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn sdk_commit() -> String {
    std::env::var("SDK_COMMIT").unwrap_or_else(|_| "unknown".into())
}

fn bytes(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

fn ids(h: &TrustBaseHistory) -> Value {
    let mut m = serde_json::Map::new();
    for e in h.entries() {
        m.insert(e.epoch.to_string(), json!(hex::encode(e.entry_id())));
    }
    Value::Object(m)
}

fn live(a: &HashMap<String, String>, out: &mut Value) -> Result<(), String> {
    let mode = a["mode"].as_str();
    let genesis_bundle = bytes(&a["genesis"]);
    let pin = PinSpec::from_bundle(&genesis_bundle).map_err(|e| e.to_string())?;
    let network = NetworkId::new(a["network-id"].parse().map_err(|_| "bad --network-id")?).map_err(|e| e.to_string())?;
    if pin.network_id != network {
        return Err(format!("the genesis is of network {}, not {}", pin.network_id.id(), network.id()));
    }
    if hex::encode(pin.genesis_entry_id) != a["genesis-pin"].trim().to_lowercase().trim_start_matches("0x") {
        return Err("the shipped genesis is not the pinned EntryID".into());
    }
    let dir = &a["store"];
    if mode == "cold" && Path::new(dir).exists() && fs::read_dir(dir).map_err(|e| e.to_string())?.next().is_some() {
        return Err("cold needs an empty store".into());
    }
    let store = FileStore::new(dir);
    let open = |store: FileStore| block_on(Session::open(network, Authority::local(&genesis_bundle).unwrap(), store, SessionOptions::default()));
    if mode == "warm" {
        // seed the store through the SDK's own store API with the epoch-1 entry alone (the shipped genesis bundle); the session reopened below must load it
        let (probe, _) = open(store.clone()).map_err(|e| e.to_string())?;
        match block_on(store.compare_and_swap(probe.key(), None, &genesis_bundle)).map_err(|e| format!("{e:?}"))? {
            StoreCas::Written(_) => {}
            StoreCas::Changed => return Err("the warm seed was not written".into()),
        }
    }
    let (mut session, diagnostics) = open(store.clone()).map_err(|e| e.to_string())?;
    out["genesisEpoch"] = json!(session.history().map_err(|e| e.to_string())?.genesis().epoch);
    out["heldAtOpen"] = json!(session.history().map_err(|e| e.to_string())?.entries().len());
    out["diagnostics"] = json!(diagnostics
        .iter()
        .map(|d| match d {
            Diagnostic::CacheRejected(r) => format!("CacheRejected:{r:?}"),
            Diagnostic::CacheUnavailable(e) => format!("CacheUnavailable:{e:?}"),
        })
        .collect::<Vec<_>>());

    // The SDK's fetch loop works on a history; the session takes what it fetched entry by entry (each authenticated again from the session's tip).
    let held = session.history().map_err(|e| e.to_string())?.latest().epoch;
    let mut fetched = session.history().map_err(|e| e.to_string())?.clone();
    let client = HttpAggregatorClient::new_insecure_http(a["agg-url"].clone());
    let sources: [&dyn TrustBaseSource; 1] = [&client];
    update(&mut fetched, &sources, &UpdateOptions::default()).map_err(|e| format!("{e}: {:?}", e.causes))?;
    let mut appended = 0;
    for e in fetched.entries().iter().filter(|e| e.epoch > held) {
        if session.append(e.clone()).map_err(|e| e.to_string())? == Appended::Added {
            appended += 1;
        }
    }
    out["fetched"] = json!(appended);
    out["flush"] = match block_on(session.flush()) {
        Flush::Saved { wrote, .. } => json!({"status": "saved", "wrote": wrote}),
        Flush::Pending(e) => json!({"status": "pending", "error": e.to_string()}),
    };
    let h = session.history().map_err(|e| e.to_string())?;
    out["tipEpoch"] = json!(h.latest().epoch);
    out["entryIds"] = ids(h);
    // what the store holds now, re-verified strictly from the pin by the SDK's own decoder
    let stored = match block_on(store.read(session.key(), 16 << 20)).map_err(|e| format!("{e:?}"))? {
        StoreRead::Present { bytes, .. } => bytes,
        StoreRead::Absent => return Err("the store holds nothing after the flush".into()),
    };
    let reloaded = TrustBaseHistory::from_bundle(&stored, Some(pin.genesis_entry_id)).map_err(|e| e.to_string())?;
    out["persisted"] = json!(reloaded.entries().len() == h.entries().len() && reloaded.latest().entry_id() == h.latest().entry_id());
    Ok(())
}

fn variant(dbg: String) -> String {
    dbg.split(|c: char| c == '{' || c == '(' || c == ' ').next().unwrap_or("").to_string()
}

fn negatives(dir: &str) -> Value {
    let f = |n: &str| bytes(&format!("{dir}/{n}"));
    let entry = |n: &str| TrustBaseEntry::from_cbor(&f(n)).expect("a real entry");
    let open = |bundle: &[u8]| {
        let mem = unicity_token::api::bft::trust_base_cache::MemoryStore::new();
        let network = PinSpec::from_bundle(bundle).unwrap().network_id;
        block_on(Session::open(network, Authority::local(bundle).unwrap(), mem, SessionOptions::default())).unwrap().0
    };
    let name = |e: &SessionError| match e {
        SessionError::Refused(h) => format!("Refused({})", match h {
            HistoryError::Entry(t) => format!("Entry({})", variant(format!("{t:?}"))),
            other => variant(format!("{other:?}")),
        }),
        other => variant(format!("{other:?}")),
    };
    let tried = |s: &mut Session<_>, n: &str, typed: &dyn Fn(&SessionError) -> bool| -> Value {
        match s.append(entry(n)) {
            Ok(o) => json!({"refused": false, "outcome": format!("{o:?}")}),
            Err(e) => json!({"refused": true, "error": name(&e), "typed": typed(&e), "message": e.to_string().chars().take(160).collect::<String>(),
                             "tipAfter": s.history().unwrap().latest().epoch}),
        }
    };
    let mut res = serde_json::Map::new();
    let g = f("genesis.bundle.cbor");
    let other = f("genesis.othernet.bundle.cbor");

    // 1. missing middle, nothing fetched: the session holds the genesis only and is offered the epoch-3 entry
    let mut s = open(&g);
    let mut r = tried(&mut s, "entry-3.cbor", &|e| matches!(e, SessionError::Refused(HistoryError::Gap { .. })));
    let mut s = open(&g);
    r["control"] = json!({"accepted": s.append(entry("entry-2.cbor")).is_ok() && s.append(entry("entry-3.cbor")).is_ok(), "tipAfter": s.history().unwrap().latest().epoch});
    res.insert("missingMiddle".into(), r);

    // 2. entry 2 with its signatures reduced below the predecessor's quorum
    let mut s = open(&g);
    let mut r = tried(&mut s, "entry-2.weak.cbor", &|e| matches!(e, SessionError::Refused(HistoryError::Entry(TrustBaseError::Signature(_)))));
    let mut s = open(&g);
    r["control"] = json!({"accepted": s.append(entry("entry-2.cbor")).is_ok(), "tipAfter": s.history().unwrap().latest().epoch});
    res.insert("belowQuorum".into(), r);

    // 3. a session of another network than the entries' (its genesis is the real genesis with another network id)
    let mut s = open(&other);
    let mut r = tried(&mut s, "entry-2.cbor", &|e| matches!(e, SessionError::Refused(HistoryError::WrongNetwork)));
    // and the session configured for another network than its own pin: refused at open
    let real_network = PinSpec::from_bundle(&g).unwrap().network_id;
    let wrong_config = block_on(Session::open(
        PinSpec::from_bundle(&other).unwrap().network_id,
        Authority::local(&g).unwrap(),
        unicity_token::api::bft::trust_base_cache::MemoryStore::new(),
        SessionOptions::default(),
    ));
    r["openWithOtherNetwork"] = match wrong_config {
        Err(e @ CacheError::PinMismatch) => json!({"refused": true, "error": "PinMismatch", "typed": true, "message": e.to_string()}),
        Err(e) => json!({"refused": true, "error": variant(format!("{e:?}")), "typed": false}),
        Ok(_) => json!({"refused": false}),
    };
    let mut s = open(&g);
    r["control"] = json!({"accepted": s.append(entry("entry-2.cbor")).is_ok(), "tipAfter": s.history().unwrap().latest().epoch, "network": real_network.id()});
    res.insert("wrongNetwork".into(), r);
    Value::Object(res)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut a = HashMap::new();
    for pair in argv.chunks(2) {
        a.insert(pair[0].trim_start_matches("--").to_string(), pair.get(1).cloned().unwrap_or_default());
    }
    let mut out = json!({"sdk": "rust", "commit": sdk_commit(), "mode": a.get("mode")});
    let mut failure = None;
    if a.contains_key("mode") {
        if let Err(e) = live(&a, &mut out) {
            failure = Some(e);
        }
    }
    if failure.is_none() {
        if let Some(dir) = a.get("negatives") {
            out["negatives"] = negatives(dir);
        }
    }
    if let Some(e) = failure {
        out["error"] = json!(e);
        println!("{out}");
        std::process::exit(1);
    }
    println!("{out}");
}
