use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::*,
    pasta::{vesta, Fp},
    plonk::*,
    poly::commitment::Params,
    poly::Rotation,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use std::marker::PhantomData;

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
struct PowerByNumChip<F: FieldExt> {
    config: PowerByNumConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> PowerByNumChip<F> {
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

impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
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
    let mut rng = OsRng;
    let params: Params<vesta::Affine> = Params::new(K);

    let empty_circuit = TestCircuit(PhantomData);
    let vk = keygen_vk(&params, &empty_circuit).expect("vk generation failed");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("pk generation failed");

    let mut prover_name = "Measure prover time in ".to_string();
    let mut verifier_name = "Measure verifier time in".to_string();
    prover_name += name;
    verifier_name += name;

    let input = Fp::from(2); // input
    let output = Fp::from(4096); // expected result y

    let public_input = [input, output];

    let circuit = TestCircuit(PhantomData);

    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof(
                &params,
                &pk,
                &[circuit],
                &[&[&public_input]],
                &mut rng,
                &mut transcript,
            )
            .expect("proof generation failed")
        })
    });

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[&public_input]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation failed");
    let proof = transcript.finalize();

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
    bench_example("example1", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
