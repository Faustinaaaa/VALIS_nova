mod artifact;
mod circuit;
mod gadgets;
mod hashchain;
mod metrics;
mod myers;
mod statement;

use artifact::{distinct_paths, load, save, Shape};
use circuit::{EditCircuit, E1, E2};
use myers::myers_diff;
use nova_snark::{
    nova::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey},
    provider::ipa_pc::EvaluationEngine,
    spartan::snark::RelaxedR1CSSNARK,
    traits::snark::RelaxedR1CSSNARKTrait,
};
use statement::Statement;
use std::{env, fs, path::Path, time::Instant};

type S1 = RelaxedR1CSSNARK<E1, EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, EvaluationEngine<E2>>;
type PP = PublicParams<E1, E2, EditCircuit>;
type PK = ProverKey<E1, E2, EditCircuit, S1, S2>;
type VK = VerifierKey<E1, E2, EditCircuit, S1, S2>;
type Proof = CompressedSNARK<E1, E2, EditCircuit, S1, S2>;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn read_statement(path: impl AsRef<Path>) -> Result<Statement> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn main() -> Result<()> {
    let result = run();
    // 失败命令也报告已发生的进程内存峰值。
    metrics::print_memory();
    result
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args_os().collect();
    let command = args.get(1).and_then(|s| s.to_str()).unwrap_or("");
    match (command, args.len()) {
        ("diff", 5) => {
            distinct_paths(&[Path::new(&args[2]), Path::new(&args[4])])?;
            distinct_paths(&[Path::new(&args[3]), Path::new(&args[4])])?;
            let before = fs::read(&args[2])?;
            let after = fs::read(&args[3])?;
            let start = Instant::now();
            let edits = myers_diff(&before, &after);
            let elapsed = start.elapsed();
            for edit in &edits {
                println!("{edit}");
            }
            let public = Statement {
                before_len: before.len(),
                before_commitment: hashchain::encode(hashchain::commitment(&before)),
                after,
                edits,
            };
            public.circuit()?;
            fs::write(&args[4], serde_json::to_vec_pretty(&public)?)?;
            println!("myers: {:.6} s", elapsed.as_secs_f64());
        }
        ("setup", 5) => {
            distinct_paths(&[
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
            ])?;
            let public = read_statement(&args[2])?;
            let (circuit, _) = public.circuit()?;
            let shape = Shape::from(&circuit);
            let start = Instant::now();
            let pp = PP::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor())?;
            let pp_time = start.elapsed();
            metrics::print_constraints(&pp);
            let phase = Instant::now();
            let (pk, vk) = Proof::setup(&pp)?;
            let key_time = phase.elapsed();
            save(&args[3], "prover", &shape, &(pp, pk))?;
            save(&args[4], "verifier", &shape, &vk)?;
            println!(
                "setup: {:.6} s (public parameters: {:.6} s, compression keys: {:.6} s)",
                (pp_time + key_time).as_secs_f64(),
                pp_time.as_secs_f64(),
                key_time.as_secs_f64()
            );
        }
        ("prove", 6) => {
            distinct_paths(&[
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
                Path::new(&args[5]),
            ])?;
            let before = fs::read(&args[2])?;
            let public = read_statement(&args[3])?;
            let (mut circuit, z0) = public.circuit()?;
            let tape = circuit::chunks(&public.edits);
            // new 会执行第一步，必须先装入第 0 块。首次 prove_step 仅登记该步。
            let mut source_offset = circuit.set_source_step(&before, 0, &tape[0])?;
            let shape = Shape::from(&circuit);
            let (pp, pk): (PP, PK) = load(&args[4], "prover", &shape)?;
            metrics::print_constraints(&pp);
            let phase = Instant::now();
            let mut recursive = RecursiveSNARK::new(&pp, &circuit, &z0)?;
            let mut recursive_time = phase.elapsed();
            for (i, edit) in tape.iter().enumerate() {
                if i > 0 {
                    source_offset = circuit.set_source_step(&before, source_offset, edit)?;
                }
                let phase = Instant::now();
                recursive.prove_step(&pp, &circuit)?;
                recursive_time += phase.elapsed();
            }
            let phase = Instant::now();
            let output = recursive.verify(&pp, circuit.steps, &z0)?;
            if !circuit.completed(&z0, &output) {
                return Err("incomplete final state".into());
            }
            let self_check_time = phase.elapsed();
            let phase = Instant::now();
            let proof = Proof::prove(&pp, &pk, &recursive)?;
            let compression_time = phase.elapsed();
            // 仅导出零知识压缩证明，绝不导出含私有 witness 的 RecursiveSNARK。
            save(&args[5], "proof", &shape, &proof)?;
            println!(
                "prove: {:.6} s (recursive: {:.6} s, compression: {:.6} s)",
                (recursive_time + compression_time).as_secs_f64(),
                recursive_time.as_secs_f64(),
                compression_time.as_secs_f64()
            );
            println!(
                "prover self-check: {:.6} s; proof: {} bytes",
                self_check_time.as_secs_f64(),
                fs::metadata(&args[5])?.len()
            );
        }
        ("verify", 5) => {
            let public = read_statement(&args[2])?;
            let (circuit, z0) = public.circuit()?;
            let shape = Shape::from(&circuit);
            let vk: VK = load(&args[3], "verifier", &shape)?;
            let proof: Proof = load(&args[4], "proof", &shape)?;
            let start = Instant::now();
            let output = proof.verify(&vk, circuit.steps, &z0)?;
            if !circuit.completed(&z0, &output) {
                return Err("incomplete final state".into());
            }
            println!(
                "verified: true; verify: {:.6} s",
                start.elapsed().as_secs_f64()
            );
        }
        _ => {
            return Err("usage:
  valis-nova-demo diff <old.txt> <new.txt> <public.json>
  valis-nova-demo setup <public.json> <pk.bin> <vk.bin>
  valis-nova-demo prove <old.txt> <public.json> <pk.bin> <proof.bin>
  valis-nova-demo verify <public.json> <vk.bin> <proof.bin>"
                .into())
        }
    }
    Ok(())
}
