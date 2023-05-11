use std::marker::PhantomData;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

// Generate halo2 zkp proof for n-th power of an integer.
// More formally, it prove the relation R = { ( x, y; exp): x^exp = y } where public input x,y and private input exp.
// The public/private input setting can be chaged easily.
#[derive(Debug, Clone)]
struct PowerByNumConfig {
    pub col_a: Column<Advice>,
    pub col_b: Column<Advice>,
    pub col_c: Column<Advice>,
    pub selector: Selector,
    pub instance: Column<Instance>,
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

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

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

                let init_a = region.assign_advice_from_instance(
                    || "ins1",
                    self.config.instance,
                    0,
                    self.config.col_a,
                    0)?;

                let init_b = region.assign_advice_from_instance(
                    || "ins2",
                    self.config.instance,
                    1,
                    self.config.col_b,
                    0)?;

                let init_c = region.assign_advice(
                    || "ins1 * ins2",
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
                prev_c.copy_advice(
                    || "a",
                    &mut region,
                    self.config.col_a,
                    0,
                )?;

                prev_b.copy_advice(
                    || "b",
                    &mut region,
                    self.config.col_b,
                    0,
                )?;

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

#[derive(Default)]
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

        let (mut prev_a, 
            prev_b, 
            mut prev_c) =
            chip.intial_assign(layouter.namespace(|| "first region"))?;

        for _i in 0..3 {

            // to check the assigned values
            println!("{}", format!("{:=<95}", ""));
            println!("a[{}]: {:?}", _i, prev_a.value().copied());
            println!("b[{}]: {:?}", _i, prev_b.value().copied());
            println!("c[{}]: {:?}", _i, prev_c.value().copied());

            // store the intended value to a region
            let tmp_c = chip.subsequent_assign(
                layouter.namespace(|| "subsequent region"), 
                &prev_b, 
                &prev_c)?;
            
            prev_a = prev_c;
            prev_c = tmp_c;
        }
        println!("{}", format!("{:=<95}", ""));

        chip.expose_public(layouter.namespace(|| "out"), &prev_c, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::TestCircuit;
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    #[test]
    fn example_test() {
        let k = 4;

        let a = Fp::from(1); // ins1
        let b = Fp::from(2); // ins2
        let out = Fp::from(16); // expected result

        let circuit = TestCircuit(PhantomData);

        let public_input = vec![a, b, out];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();

    }
}
