use halo2::{circuit::*, halo2curves::ff::PrimeField, plonk::*, poly::Rotation};
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
use rand::rngs::OsRng;

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PowerByNumConfig {
    pub col_a: Column<Advice>,
    pub col_b: Column<Advice>,
    pub col_c: Column<Advice>,
    pub selector: Selector,
    pub instance: Column<Instance>,
    pub constant: Column<Fixed>,
}

#[derive(Debug, Clone)]
struct PowerByNumChip<F: PrimeField> {
    config: PowerByNumConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> PowerByNumChip<F> {
    pub fn construct(config: PowerByNumConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> PowerByNumConfig {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let selector = meta.selector();
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(instance);
        meta.enable_constant(constant);

        meta.create_gate("mul", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * (a * b - c)]
        });

        PowerByNumConfig {
            col_a,
            col_b,
            col_c,
            selector,
            instance,
            constant,
        }
    }

    pub fn intial_assign(
        &self,
        mut layouter: impl Layouter<F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        layouter.assign_region(
            || "first region",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let init_a = region.assign_advice_from_constant(
                    || "constant",
                    self.config.col_a,
                    0,
                    F::from(1),
                )?;

                let init_b = region.assign_advice_from_instance(
                    || "instance",
                    self.config.instance,
                    0,
                    self.config.col_b,
                    0,
                )?;

                let init_c = region.assign_advice(
                    || "init_a * init_b",
                    self.config.col_c,
                    0,
                    || init_a.value().copied() * init_b.value(),
                )?;

                Ok((init_a, init_b, init_c))
            },
        )
    }

    pub fn subsequent_assign(
        &self,
        mut layouter: impl Layouter<F>,
        prev_b: &AssignedCell<F, F>,
        prev_c: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "subsequent row",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                // copy the value from previous region
                prev_c.copy_advice(|| "a", &mut region, self.config.col_a, 0)?;

                prev_b.copy_advice(|| "b", &mut region, self.config.col_b, 0)?;

                let res_c = region.assign_advice(
                    || "c",
                    self.config.col_c,
                    0,
                    || prev_b.value().copied() * prev_c.value(),
                )?;

                Ok(res_c)
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}

#[derive(Default, Clone, Copy)]
struct TestCircuit<F>(PhantomData<F>);

impl<F: PrimeField> Circuit<F> for TestCircuit<F> {
    type Config = PowerByNumConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        PowerByNumChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = PowerByNumChip::construct(config);

        let (_, prev_b, mut prev_c) = chip.intial_assign(layouter.namespace(|| "first region"))?;

        for _i in 1..12 {
            let tmp_c = chip.subsequent_assign(
                layouter.namespace(|| "subsequent region"),
                &prev_b,
                &prev_c,
            )?;

            prev_c = tmp_c;
        }

        chip.expose_public(layouter.namespace(|| "out"), &prev_c, 1)?;

        Ok(())
    }
}

const K: u32 = 7;

fn bench_example(name: &str, c: &mut Criterion) {
    // Initialize the polynomial commitment parameters
    let params_path = Path::new("./benches/params/example2_params");
    if File::open(params_path).is_err() {
        // let params: ParamsIPA<EqAffine> = ParamsIPA::new(k);
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

    let empty_circuit = TestCircuit(PhantomData);
    let vk = keygen_vk(&params, &empty_circuit).expect("vk generation failed");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("pk generation failed");

    let mut prover_name = "Measure prover time in ".to_string();
    let mut verifier_name = "Measure verifier time in ".to_string();
    prover_name += name;
    verifier_name += name;

    let input = Fp::from(2); // input
    let output = Fp::from(4096); // expected result y

    let public_input = [input, output];

    let circuit = TestCircuit(PhantomData);

    // Benchmark proof creation
    // c.bench_function(&prover_name, |b| {
    //     b.iter(|| {
    //         let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    //         create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
    //             &params,
    //             &pk,
    //             &[circuit],
    //             &[&[&public_input]],
    //             OsRng,
    //             &mut transcript,
    //         )
    //         .expect("proof generation failed");
    //     });
    // });

    // Create a proof
    let proof_path = Path::new("./benches/proofs/example2_proof");
    if File::open(proof_path).is_err() {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[&[&public_input]],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation failed");
        let proof: Vec<u8> = transcript.finalize();
        let mut file = File::create(proof_path).expect("Failed to create proof");
        file.write_all(&proof[..]).expect("Failed to write proof");
    }

    let mut proof_fs = File::open(proof_path).expect("Failed to load proof");
    let mut proof = Vec::<u8>::new();
    proof_fs
        .read_to_end(&mut proof)
        .expect("Couldn't read proof");

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

    // c.bench_function(&prover_name, |b| {
    //     b.iter(|| {
    //         let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    //         create_proof(
    //             &params,
    //             &pk,
    //             &[circuit],
    //             &[&[&public_input]],
    //             &mut rng,
    //             &mut transcript,
    //         )
    //         .expect("proof generation failed")
    //     })
    // });

    // let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // create_proof(
    //     &params,
    //     &pk,
    //     &[circuit],
    //     &[&[&public_input]],
    //     &mut rng,
    //     &mut transcript,
    // )
    // .expect("proof generation failed");
    // let proof = transcript.finalize();

    // c.bench_function(&verifier_name, |b| {
    //     b.iter(|| {
    //         let strategy = SingleVerifier::new(&params);
    //         let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    //         assert!(verify_proof(
    //             &params,
    //             pk.get_vk(),
    //             strategy,
    //             &[&[&public_input]],
    //             &mut transcript
    //         )
    //         .is_ok());
    //     });
    // });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_example("example2", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
