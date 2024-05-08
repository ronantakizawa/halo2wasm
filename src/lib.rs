use wasm_bindgen::prelude::*;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    pasta::Fp,
    dev::MockProver,
};

#[cfg(feature = "console_error_panic_hook")]
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct IPCheckCircuit {
    ip_string: String,
}

#[wasm_bindgen]
impl IPCheckCircuit {
    #[wasm_bindgen(constructor)]
    pub fn new(ip_string: String) -> IPCheckCircuit {
        set_panic_hook();
        Self { ip_string }
    }

    #[wasm_bindgen]
    pub fn verify(&self) -> bool {
        let k = 5;
        let prover = MockProver::run(k, self, vec![]).unwrap();
        prover.verify().is_ok()
    }
}

struct CharCircuit {
    value: AssignedCell<Fp, Fp>,
}

impl CharCircuit {
    fn new(value: AssignedCell<Fp, Fp>) -> Self {
        Self { value }
    }

    fn constrain(&self, region: &mut Region<'_, Fp>, expected: u8, selector: Selector) -> Result<(), Error> {
        let _ = selector.enable(region, 0);
        let expected_val = Fp::from(expected as u64);
        region.constrain_constant(self.value.cell(), expected_val)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct IPCheckConfig {
    chars: Vec<Column<Advice>>,
    selector: Selector,
}

impl Circuit<Fp> for IPCheckCircuit {
    type Config = IPCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { ip_string: "".to_string() }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let selector = meta.selector();
        let constant = meta.fixed_column();
        meta.enable_constant(constant);

        let mut chars = Vec::new();
        for _ in 0..15 {
            chars.push(meta.advice_column());
            meta.enable_equality(*chars.last().unwrap());
        }

        IPCheckConfig { chars, selector }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_region(|| "Check IP", |mut region| {
            let mut char_cells = Vec::new();
            let ip_bytes = self.ip_string.as_bytes();

            for (i, &byte) in ip_bytes.iter().enumerate() {
                let cell = region.assign_advice(|| format!("char {}", i), config.chars[i], 0, || Value::known(Fp::from(byte as u64)))?;
                char_cells.push(CharCircuit::new(cell));
            }

            let expected_chars: Vec<u8> = "127.0.0.1".bytes().collect();

            for (i, char_circuit) in char_cells.iter().enumerate() {
                if i < expected_chars.len() {
                    char_circuit.constrain(&mut region, expected_chars[i], config.selector)?;
                }
            }

            Ok(())
        })
    }
}
