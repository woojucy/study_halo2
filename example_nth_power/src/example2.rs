// Same with example1 but uses different library which is from PSE team
use halo2::{circuit::*, halo2curves::ff::PrimeField, plonk::*, poly::Rotation};
use std::marker::PhantomData;

// Generate halo2 zkp proof for n-th power of an integer.
// More formally, it prove the relation R = { ( x, y; exp): x^exp = y } where public input x,y and private input exp.
// The public/private input setting can be chaged.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PowerByNumConfig {
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

#[derive(Default, Clone)]
pub struct TestCircuit<F>(pub PhantomData<F>);

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

        /* to check the initially assigned values */
        // println!("{}", format!("{:=<95}", ""));
        //println!("col_a[0]: {:?}", prev_a.value().copied());
        // println!("col_b[0]: {:?}", prev_b.value().copied());
        // println!("col_c[0]: {:?}", prev_c.value().copied());

        for _i in 1..2 {
            // store the intended value to a region
            let tmp_c = chip.subsequent_assign(
                layouter.namespace(|| "subsequent region"),
                &prev_b,
                &prev_c,
            )?;

            /* to check the assigned values */
            // println!("{}", format!("{:=<95}", ""));
            // println!("col_a[{}]: {:?}", _i, prev_c.value().copied());
            // println!("col_b[{}]: {:?}", _i, prev_b.value().copied());
            // println!("col_c[{}]: {:?}", _i, tmp_c.value().copied());

            prev_c = tmp_c;
        }

        // println!("{}", format!("{:=<95}", ""));

        chip.expose_public(layouter.namespace(|| "out"), &prev_c, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::TestCircuit;
    use halo2::{dev::MockProver, halo2curves::bn256::Fr};

    #[test]
    fn example_test2() {
        let k = 3;

        let input = Fr::from(2); // input x
        let output = Fr::from(4); // expected result y

        let circuit = TestCircuit(PhantomData);

        let public_input = vec![input, output];

        // runs a synthetic keygen-and-prove operation on the given circuit
        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        // println!("{:?}", prover);
        prover.assert_satisfied();
    }
}
