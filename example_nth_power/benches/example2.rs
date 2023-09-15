use halo2::poly::VerificationStrategy;
use halo2::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::commitment::Params,
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2::{plonk::*, SerdeFormat};
// use halo2curves::pasta::{EqAffine, Fr};
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    marker::PhantomData,
    path::Path,
};
// bench-mark tool
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use example::example2::TestCircuit;
use rand::rngs::OsRng;

// K is the dimension for the poly commit
fn bench_example(k: u32, name: &str, c: &mut Criterion) {
    // Set the polynomial commitment parameters
    let params_path = Path::new("./benches/data/params_example2");
    if File::open(params_path).is_err() {
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        let mut buf = Vec::new();

        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(params_path).expect("Failed to create params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }
    let params_fs = File::open(params_path).expect("Failed to load params");
    let params: ParamsKZG<Bn256> =
        ParamsKZG::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    // Define a circuit
    let circuit = TestCircuit(PhantomData);

    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;

    // Set the instances
    let input = Fr::from(2); // input
    let output = Fr::from(4); // expected result y

    let public_input = [input, output];

    // write verifying key
    let vk_path = "./benches/data/vk_example2";
    if File::open(&vk_path).is_err() {
        let vk = keygen_vk(&params, &circuit.clone()).expect("keygen_vk failed");
        let mut buf = Vec::new();
        let _ = vk.write(&mut buf, SerdeFormat::RawBytes);
        let mut file = File::create(&vk_path).expect("Failed to create vk");
        file.write_all(&buf[..])
            .expect("Failed to write vk to file");
    }
    let vk_fs = File::open(vk_path).expect("Failed to load vk");
    let vk = VerifyingKey::<G1Affine>::read::<BufReader<File>, TestCircuit<Fr>>(
        &mut BufReader::new(vk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read vk");

    // write proving key
    let pk_path = "./benches/data/pk_example2";
    if File::open(&pk_path).is_err() {
        let pk = keygen_pk(&params, vk, &circuit.clone()).expect("keygen_pk failed");
        let mut buf = Vec::new();
        let _ = pk.write(&mut buf, SerdeFormat::RawBytes);
        let mut file = File::create(&pk_path).expect("Failed to create pk");
        file.write_all(&buf[..])
            .expect("Failed to write pk to file");
    }
    let pk_fs = File::open(pk_path).expect("Failed to load pk");
    let pk = ProvingKey::<G1Affine>::read::<BufReader<File>, TestCircuit<Fr>>(
        &mut BufReader::new(pk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read pk");

    // Create a proof
    let proof_path = Path::new("./benches/data/proof_example2");
    if File::open(proof_path).is_err() {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        c.bench_function(&prover_name, |b| {
            b.iter(|| {
                create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
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
            let accept = {
                let mut transcript: Blake2bRead<&[u8], _, Challenge255<_>> =
                    TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
                VerificationStrategy::<_, VerifierGWC<_>>::finalize(
                    verify_proof::<_, VerifierGWC<_>, _, _, _>(
                        params.verifier_params(),
                        pk.get_vk(),
                        AccumulatorStrategy::new(params.verifier_params()),
                        &[&[&public_input]],
                        &mut transcript,
                    )
                    .unwrap(),
                )
            };
            assert!(accept);
        });
    });
}

fn main() {
    let mut criterion = Criterion::default();
    // .sample_size(100)  // 샘플 크기 설정
    // .nresamples(100);  // 반복 횟수 설정

    let benches: Vec<Box<dyn Fn(&mut Criterion)>> =
        vec![Box::new(|c| bench_example(3, "example1", c))];

    for bench in benches {
        bench(&mut criterion);
    }
}
