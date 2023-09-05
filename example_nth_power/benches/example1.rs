use example::example1::TestCircuit;
use halo2_proofs::{
    pasta::{vesta, Fp},
    plonk::*,
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use std::marker::PhantomData;

// Benchmark tool
use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

// K is the dimension for the poly commit
fn bench_example<const K: u32>(name: &str, c: &mut Criterion) {
    // Set the polynomial commitment parameters
    let mut rng = OsRng;
    let params: Params<vesta::Affine> = Params::new(K);

    // Define a circuit
    let circuit = TestCircuit(PhantomData);

    // Set the verifier and prover key according to the params and circuit
    let vk = keygen_vk(&params, &circuit).expect("vk generation failed");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk generation failed");

    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;

    // Set the instances
    let input = Fp::from(2); // input
    let output = Fp::from(4096); // expected result y
    let public_input = [input, output];

    // Benchmarking proof gereration time
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            create_proof(
                &params,
                &pk,
                &[circuit.clone()],
                &[&[&public_input]],
                &mut rng,
                &mut transcript,
            )
            .expect("proof generation failed")
        })
    });
    let proof = transcript.finalize();

    // Benchmarking verification time
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(
                &params,
                pk.get_vk(),
                strategy,
                &[&[&public_input]],
                &mut transcript
            )
            .is_ok());
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_example::<7>("example1", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
