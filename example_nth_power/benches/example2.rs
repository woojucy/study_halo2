use halo2::plonk::*;
use halo2::{
    halo2curves,
    poly::commitment::Params,
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::{ProverIPA, VerifierIPA},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2curves::pasta::{EqAffine, Fp};
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    marker::PhantomData,
    path::Path,
};
// bench-mark tool
use criterion::{criterion_group, criterion_main, Criterion};
use example::example2::TestCircuit;
use rand::rngs::OsRng;

// K is the dimension for the poly commit
fn bench_example<const K: u32>(name: &str, c: &mut Criterion) {
    // Set the polynomial commitment parameters
    let params_path = Path::new("./benches/data/params_example2");
    if File::open(params_path).is_err() {
        let params: ParamsIPA<EqAffine> = ParamsIPA::new(K);
        let mut buf = Vec::new();

        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(params_path).expect("Failed to create params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }
    let params_fs = File::open(params_path).expect("Failed to load params");
    let params: ParamsIPA<EqAffine> =
        ParamsIPA::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    // Define a circuit
    let circuit = TestCircuit(PhantomData);

    // Set the verification and proof generation key
    let vk = keygen_vk(&params, &circuit).expect("vk generation failed");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk generation failed");

    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;

    // Set the instances
    let input = Fp::from(2); // input
    let output = Fp::from(4); // expected result y

    let public_input = [input, output];

    // Create a proof
    let proof_path = Path::new("./benches/data/proof_example2");
    if File::open(proof_path).is_err() {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        c.bench_function(&prover_name, |b| {
            b.iter(|| {
                create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
                    &params,
                    &pk,
                    &[circuit.clone()],
                    &[&[&public_input]],
                    &mut OsRng,
                    &mut transcript,
                )
                .expect("proof generation failed")
            })
        });
        let proof: Vec<u8> = transcript.finalize();
        let mut file = File::create(proof_path).expect("Failed to create proof");
        file.write_all(&proof[..]).expect("Failed to write proof");
    }

    let mut proof_fs = File::open(proof_path).expect("Failed to load proof");
    let mut proof = Vec::<u8>::new();
    proof_fs
        .read_to_end(&mut proof)
        .expect("Couldn't read proof");

    // verify the proof
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            use halo2::poly::VerificationStrategy;
            let strategy = AccumulatorStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            let strategy = verify_proof::<IPACommitmentScheme<_>, VerifierIPA<_>, _, _, _>(
                &params,
                pk.get_vk(),
                strategy,
                &[&[&public_input]],
                &mut transcript,
            )
            .unwrap();
            assert!(strategy.finalize());
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_example::<3>("example2", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
