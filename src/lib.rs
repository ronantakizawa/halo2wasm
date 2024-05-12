use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    pasta::Fq,
    plonk::{create_proof, keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error},
    poly::commitment::Params,
    transcript::Blake2bWrite,
};
use halo2_proofs::pasta::pallas::Affine as EqAffine; // Correct curve type import
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

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
    pub fn new(ip_string: String) -> Result<IPCheckCircuit, JsValue> {
        if !ip_string.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Err(JsValue::from_str("Invalid IP format"));
        }
        set_panic_hook();
        Ok(Self { ip_string })
    }

    #[wasm_bindgen]
    pub fn verify(&self) -> Result<bool, JsValue> {
        let k = 5;
        let prover = MockProver::<Fq>::run(k, self, vec![]).map_err(|e| {
            JsValue::from_str(&format!("Error running prover: {}", e))
        })?;
        Ok(prover.verify().is_ok())
    }

    #[wasm_bindgen]
pub fn get_proof(&self) -> Result<Vec<u8>, JsValue> {
    let k = 5;
    let params = Params::<EqAffine>::new(k);
    let rng = OsRng;

    let vk = keygen_vk(&params, self)
        .map_err(|e| JsValue::from_str(&format!("Error generating verifying key: {:?}", e)))?;

    let pk = keygen_pk(&params, vk, self)
        .map_err(|e| JsValue::from_str(&format!("Error generating proving key: {:?}", e)))?;

    let mut transcript = Blake2bWrite::init(Vec::new());

    let circuit_instance = IPCheckCircuit { ip_string: self.ip_string.clone() };
    let circuits: &[IPCheckCircuit] = &[circuit_instance];
    // Note: No external instances are passed here; adjust accordingly if your scenario differs
    let proof_result = create_proof(&params, &pk, circuits, &[], rng, &mut transcript);
    if let Err(e) = proof_result {
        return Err(JsValue::from_str(&format!("Error creating proof: {:?}", e)));
    }

    let proof = transcript.finalize();
    Ok(proof)
}
}



#[derive(Clone)]
pub struct IPCheckConfig {
    chars: Vec<Column<Advice>>,
    fixed: Column<halo2_proofs::plonk::Fixed>,
}

impl Circuit<Fq> for IPCheckCircuit {
    type Config = IPCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let chars = (0..15).map(|_| {
            let col = meta.advice_column();
            meta.enable_equality(col);  
            col
        }).collect::<Vec<_>>();
        let fixed = meta.fixed_column();
        meta.enable_constant(fixed);

        IPCheckConfig {
            chars,
            fixed,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), Error> {
        layouter.assign_region(|| "Check IP", |mut region| {
            let ip_bytes = self.ip_string.split('.').collect::<Vec<_>>();
            if ip_bytes.len() != 4 {
                return Err(Error::Synthesis); // Ensure there are exactly four parts
            }
    
            let expected = [127, 0, 0, 1]; // The expected bytes for "127.0.0.1"
            let mut cells = Vec::new();
    
            for (i, &part) in ip_bytes.iter().enumerate() {
                let byte = part.parse::<u8>().map_err(|_| Error::Synthesis)?; // Parse each part as byte
                let cell = region.assign_advice(
                    || format!("IP byte {}", i),
                    config.chars[i],
                    0,
                    || Value::known(Fq::from(byte as u64))
                )?;
                let expected_cell = region.assign_fixed(
                    || format!("Expected byte {}", i),
                    config.fixed,
                    i,
                    || Value::known(Fq::from(expected[i] as u64))
                )?;
                region.constrain_equal(cell.cell(), expected_cell.cell())?;
                cells.push(cell);
            }
    
            Ok(())
        })
    }

    fn without_witnesses(&self) -> Self {
        Self { ip_string: "".to_string() }  // Return an instance with an empty IP string
    }
}
