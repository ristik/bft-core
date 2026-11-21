//! Copy to crates/unicity/execution/tests at the Ureth pin in README.md.
//! The EVM deploys the production contracts and executes the real native B1 calls.

use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, address, hex, keccak256};
use alloy_sol_types::SolValue;
use reth_unicity_b1::{Operation, Pins, REGISTRY};
use reth_unicity_execution::evm_factory::UnicityEvmFactory;
use revm::{
    DatabaseCommit, Inspector,
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::{
        ContextTr,
        result::{ExecutionResult, Output},
    },
    database::{CacheDB, EmptyDB},
    interpreter::{CallInputs, CallOutcome},
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const SENDER: Address = address!("1000000000000000000000000000000000000001");
const CHAIN: u64 = 31337;
const GAS: u64 = 24_000_000;
type Db = CacheDB<EmptyDB>;

fn raw(path: impl AsRef<Path>) -> Vec<u8> {
    fs::read(path.as_ref()).unwrap_or_else(|e| panic!("{}: {e}", path.as_ref().display()))
}

fn read_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&raw(path)).unwrap()
}

fn word(s: &str) -> U256 {
    U256::from_be_slice(&hex::decode(s).unwrap())
}

fn sha(bytes: impl AsRef<[u8]>) -> B256 {
    B256::from_slice(&Sha256::digest(bytes.as_ref()))
}

fn hash(label: &str, fields: &[&[u8]]) -> B256 {
    let mut preimage = keccak256(format!("UNICITY/NB2/CONT/1.1/{label}")).to_vec();
    for field in fields {
        preimage.extend_from_slice(field);
    }
    keccak256(preimage)
}

fn environment() -> EvmEnv<SpecId> {
    let cfg = CfgEnv::new_with_spec(SpecId::CANCUN).with_chain_id(CHAIN);
    EvmEnv::new(
        cfg,
        BlockEnv {
            gas_limit: GAS,
            ..Default::default()
        },
    )
}

fn deploy(
    db: &mut Db,
    pins: Pins,
    out: &Path,
    name: &str,
    args: Vec<u8>,
) -> (Address, B256, Value) {
    let artifact = read_json(out.join(format!("{name}.sol/{name}.json")));
    let mut init = hex::decode(artifact["bytecode"]["object"].as_str().unwrap()).unwrap();
    init.extend(args);
    let init_hash = keccak256(&init);
    let nonce = db.cache.accounts[&SENDER].info.nonce;
    let tx = TxEnv {
        caller: SENDER,
        nonce,
        kind: TxKind::Create,
        data: init.into(),
        gas_limit: GAS,
        chain_id: Some(CHAIN),
        ..Default::default()
    };
    let result = UnicityEvmFactory::new(pins)
        .create_evm(db.clone(), environment())
        .transact_raw(tx)
        .unwrap();
    let ExecutionResult::Success {
        output: Output::Create(code, Some(addr)),
        ..
    } = result.result
    else {
        panic!("{name} constructor: {:?}", result.result)
    };
    let runtime_hash = keccak256(code);
    db.commit(result.state);
    (
        addr,
        runtime_hash,
        json!({
            "address": hex::encode(addr),
            "createNonce": nonce,
            "initHash": hex::encode(init_hash),
            "runtimeHash": hex::encode(runtime_hash),
        }),
    )
}

fn call(db: &Db, pins: Pins, target: Address, data: &[u8]) -> (ExecutionResult, NativeCalls) {
    let mut native = NativeCalls::default();
    let result = UnicityEvmFactory::new(pins)
        .create_evm_with_inspector(db.clone(), environment(), &mut native)
        .transact_raw(TxEnv {
            caller: SENDER,
            nonce: db.cache.accounts[&SENDER].info.nonce,
            kind: TxKind::Call(target),
            data: data.to_vec().into(),
            gas_limit: GAS,
            chain_id: Some(CHAIN),
            ..Default::default()
        })
        .unwrap()
        .result;
    (result, native)
}

#[derive(Default)]
struct NativeCalls {
    cert: Vec<Bytes>,
    cert_output: Vec<Bytes>,
    member_count: usize,
}

impl<CTX: ContextTr> Inspector<CTX> for NativeCalls {
    fn call(&mut self, ctx: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        if inputs.bytecode_address == Operation::CertBatch.address() {
            self.cert.push(inputs.input.bytes(ctx));
        }
        if inputs.bytecode_address == Operation::Member.address() {
            self.member_count += 1;
        }
        None
    }

    fn call_end(&mut self, _: &mut CTX, inputs: &CallInputs, outcome: &mut CallOutcome) {
        if inputs.bytecode_address == Operation::CertBatch.address() {
            self.cert_output.push(outcome.output().clone());
        }
    }
}

fn field<'a>(cursor: &mut &'a [u8]) -> &'a [u8] {
    let n = u32::from_be_bytes(cursor[..4].try_into().unwrap()) as usize;
    let (field, rest) = cursor[4..].split_at(n);
    *cursor = rest;
    field
}

fn check_event(result: ExecutionResult, recovery: Address, topics: &[u8], data: &[u8]) {
    let ExecutionResult::Success { logs, .. } = result else {
        panic!("{result:?}")
    };
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].address, recovery);
    let actual: Vec<_> = logs[0]
        .data
        .topics()
        .iter()
        .flat_map(|t| t.as_slice().to_vec())
        .collect();
    assert_eq!(actual, topics);
    assert_eq!(logs[0].data.data.as_ref(), data);
}

fn check_refusal(result: ExecutionResult, error: &str) {
    let ExecutionResult::Revert { output, .. } = result else {
        panic!("{result:?}")
    };
    assert_eq!(output.as_ref(), &keccak256(format!("{error}()"))[..4]);
}

fn cases(db: &Db, pins: Pins, dir: &Path, ordinary: Address, recovery: Address, gamma: Vec<u8>) {
    for name in ["b1-rollover", "b1-rollover-refusals", "cross-cut-conflict"] {
        let case = dir.join(name);
        let context = read_json(case.join("context.json"));
        assert_eq!(
            pins.genesis_commitment,
            word(context["GenesisCommitment"].as_str().unwrap())
        );
        assert_eq!(
            pins.profile_hash,
            word(context["RegistryProfile"].as_str().unwrap())
        );
        let mut state = db.clone();
        for (slot, value) in context["Registry"].as_object().unwrap() {
            state
                .insert_account_storage(REGISTRY, word(slot), word(value.as_str().unwrap()))
                .unwrap();
        }
        if name == "b1-rollover" {
            let mut input = keccak256("verifyReturn(bytes,bytes)")[..4].to_vec();
            input.extend(
                (
                    Bytes::from(gamma.clone()),
                    Bytes::from(raw(case.join("evidence.bin"))),
                )
                    .abi_encode_params(),
            );
            let (result, _) = call(&state, pins, ordinary, &input);
            assert!(result.is_success(), "{result:?}");
            assert_eq!(
                result.output().unwrap().as_ref(),
                raw(case.join("verdict.bin"))
            );
            println!("{name}: ordinary verified");
        }

        if name == "b1-rollover-refusals" {
            for error in ["BadStep", "BadPage"] {
                let (result, native) = call(
                    &state,
                    pins,
                    recovery,
                    &raw(case.join(format!("{error}.calldata.bin"))),
                );
                check_refusal(result, error);
                // The first flush actually runs and fails. The second does
                // not run, even when the verifier finds an unused valid page.
                assert_eq!(native.cert.len(), 1);
                assert_eq!(native.cert[0].as_ref(), raw(case.join("batch-1.bin")));
                assert_eq!(
                    native.cert_output[0].as_ref(),
                    (U256::from(2), false).abi_encode_params()
                );
                assert_eq!(native.member_count, 16);
                println!("{name}: {error} after a false native first batch");
            }
            continue;
        }

        let trace = Command::new("gzip")
            .arg("-dc")
            .arg(case.join("trace.bin.gz"))
            .output()
            .unwrap();
        assert!(trace.status.success());
        let mut frames = trace.stdout.as_slice();
        let mut index = 0;
        while !frames.is_empty() {
            let packet = field(&mut frames);
            let _before = field(&mut frames);
            let _after = field(&mut frames);
            let topics = field(&mut frames);
            let data = field(&mut frames);
            let _receipt = field(&mut frames);
            if name == "cross-cut-conflict" && index == 1 {
                let (result, native) = call(
                    &state,
                    pins,
                    recovery,
                    &raw(case.join("BadStep.calldata.bin")),
                );
                check_refusal(result, "BadStep");
                assert_eq!(
                    native.cert.len(),
                    1,
                    "only the predecessor receipt is certified"
                );
                assert_eq!(
                    native.member_count, 1,
                    "the conflicting source never reaches membership"
                );
            }
            let (result, native) = call(&state, pins, recovery, packet);
            check_event(result, recovery, topics, data);
            if name == "b1-rollover" && index == 0 {
                assert_eq!(native.cert.len(), 2);
                for (i, input) in native.cert.iter().enumerate() {
                    assert_eq!(
                        input.as_ref(),
                        raw(case.join(format!("batch-{}.bin", i + 1)))
                    );
                }
                for output in native.cert_output {
                    assert_eq!(output.as_ref(), (U256::from(2), true).abi_encode_params());
                }
                assert_eq!(native.member_count, 16);
            }
            index += 1;
        }
        assert_eq!(index, 2);
        println!("{name}: {index} recovery events matched");
    }
}

#[test]
fn deployable_nb2_flat_supplement() {
    let dir = PathBuf::from(env::var_os("NB2_FLAT_SUPPLEMENT").expect("NB2_FLAT_SUPPLEMENT"));
    let bft = PathBuf::from(env::var_os("NB2_FLAT_BFT").expect("NB2_FLAT_BFT"));
    let out = PathBuf::from(env::var_os("NB2_FLAT_FORGE_OUT").expect("NB2_FLAT_FORGE_OUT"));
    let base = bft.join("testvectors/nb2-continuation-v1.1");
    let fixture = read_json(base.join("transcripts/root/context.json"));
    let pins = Pins {
        genesis_commitment: word(fixture["GenesisCommitment"].as_str().unwrap()),
        profile_hash: word(fixture["RegistryProfile"].as_str().unwrap()),
    };
    let registry = read_json(bft.join("b1registry/seal-registry.json"));
    let registry_code = hex::decode(registry["runtimeBytecode"].as_str().unwrap()).unwrap();
    let registry_hash = keccak256(&registry_code);
    assert_eq!(
        registry_hash,
        registry["codeHash"]
            .as_str()
            .unwrap()
            .parse::<B256>()
            .unwrap()
    );
    let mut db = Db::new(EmptyDB::default());
    db.insert_account_info(
        REGISTRY,
        AccountInfo {
            code_hash: registry_hash,
            code: Some(Bytecode::new_raw(registry_code.into())),
            ..Default::default()
        },
    );
    db.insert_account_info(
        SENDER,
        AccountInfo {
            balance: U256::from(10u64.pow(18)),
            ..Default::default()
        },
    );

    let descriptor = |name: &str| sha(raw(dir.join(format!("descriptors/{name}.json"))));
    let profile = descriptor("semantic-profile");
    let (receipts, receipts_hash, receipts_info) =
        deploy(&mut db, pins, &out, "FlatReceipts", vec![]);
    let (lineage, lineage_hash, lineage_info) = deploy(
        &mut db,
        pins,
        &out,
        "FlatLineage",
        (receipts,).abi_encode_params(),
    );
    let (ordinary, ordinary_hash, ordinary_info) = deploy(
        &mut db,
        pins,
        &out,
        "NativeBridgeVerifier11",
        (lineage, lineage_hash, profile, registry_hash).abi_encode_params(),
    );
    let mut gamma = raw(base.join("gamma.bin"));
    // The fixed-width CBOR payloads are profile (field 13), ordinary address
    // (14) and ordinary runtime hash (15). Preserve their CBOR headers.
    assert_eq!(gamma[217..219], [0x58, 32]);
    assert_eq!(gamma[251], 0x54);
    assert_eq!(gamma[272..274], [0x58, 32]);
    gamma[219..251].copy_from_slice(profile.as_slice());
    gamma[252..272].copy_from_slice(ordinary.as_slice());
    gamma[274..306].copy_from_slice(ordinary_hash.as_slice());

    let descriptors = [
        "cert-batch-v2",
        "rsmt-member-v1",
        "registry-layout",
        "execution",
        "build-index",
        "primitive-vectors",
    ]
    .map(descriptor);
    let [cert, member, layout, exec, build, primitive] = descriptors;
    let release = hash("RELEASE", &descriptors.each_ref().map(|d| d.as_slice()));
    let registry_digest = hash("REGISTRY", &[registry_hash.as_slice(), layout.as_slice()]);
    let mut records = Vec::new();
    for (role, address, digest) in [
        (1u16, ordinary, ordinary_hash),
        (2, receipts, receipts_hash),
        (3, Operation::CertBatch.address(), cert),
        (4, Operation::Member.address(), member),
        (5, REGISTRY, registry_digest),
        (256, lineage, lineage_hash),
    ] {
        records.extend(role.to_be_bytes());
        records.extend_from_slice(address.as_slice());
        records.extend_from_slice(digest.as_slice());
    }
    let dependency_pins = hash("PINS", &[release.as_slice(), &[0, 6], &records]);
    let salt = sha("unicity/1108/t1-supplement/release-generation");
    let (recovery, recovery_hash, recovery_info) = deploy(
        &mut db,
        pins,
        &out,
        "NativeBridgeRecovery11",
        (
            Bytes::from(gamma.clone()),
            ordinary,
            salt,
            (cert, member, layout, exec, build, primitive),
            dependency_pins,
        )
            .abi_encode_params(),
    );

    let identity = json!({
        "Contracts": {
            "FlatReceipts": receipts_info,
            "FlatLineage": lineage_info,
            "NativeBridgeVerifier11": ordinary_info,
            "NativeBridgeRecovery11": recovery_info,
        },
        "Deployer": hex::encode(SENDER),
        "Domain": hex::encode(sha(&gamma)),
        "Generation": hex::encode(hash("GEN", &[salt.as_slice(), sha(&gamma).as_slice()])),
        "Pins": hex::encode(dependency_pins),
        "RecoveryAddress": hex::encode(recovery),
        "RecoveryRuntimeHash": hex::encode(recovery_hash),
        "RegistryRuntimeHash": hex::encode(registry_hash),
        "Release": hex::encode(release),
    });
    let mut identity = serde_json::to_vec_pretty(&identity).unwrap();
    identity.push(b'\n');
    let seed = env::var_os("NB2_FLAT_SEED").is_some();
    for (name, value) in [
        ("deployment.json", identity),
        ("gamma.bin", gamma.clone()),
        ("generation-salt.bin", salt.to_vec()),
        ("pin-records.bin", records),
    ] {
        if seed {
            fs::write(dir.join(name), value).unwrap();
        } else {
            assert_eq!(value, raw(dir.join(name)), "{name}");
        }
    }
    if !seed {
        cases(&db, pins, &dir, ordinary, recovery, gamma);
    }
}
