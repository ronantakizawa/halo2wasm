use std::io;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    pasta::Fp,
    dev::MockProver,
};

#[derive(Clone)]
struct CharCircuit {
    value: AssignedCell<Fp, Fp>,
}

impl CharCircuit {
    fn new(value: AssignedCell<Fp, Fp>) -> Self {
        Self { value }
    }

    fn constrain(&self, region: &mut Region<'_, Fp>, expected: u8, selector: Selector) -> Result<(), Error> {
        selector.enable(region, 0)?;

        let expected_val = Fp::from(expected as u64);
        region.constrain_constant(self.value.cell(), expected_val)?;

        Ok(())
    }
}

struct IPCheckCircuit {
    ip_string: String,
}

#[derive(Clone)]
struct IPCheckConfig {
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

fn main() {
    println!("Please enter an IP address:");
    let mut ip_string = String::new();
    io::stdin().read_line(&mut ip_string).expect("Failed to read line");
    let ip_string = ip_string.trim().to_string();  // Trim the newline character

    let circuit = IPCheckCircuit {
        ip_string,
    };
    let k = 5;

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    match prover.verify() {
        Ok(_) => println!("Circuit verified successfully!"),
        Err(e) => println!("Verification failed: {:?}", e),
    }
}
