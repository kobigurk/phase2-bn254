#![allow(unused_imports)]

extern crate bellman_ce;

use std::str;
use std::fs;
use std::fs::OpenOptions;
use std::collections::BTreeMap;
use std::io::{
    Read,
    Write,
};

use bellman_ce::pairing::{
    Engine,
    ff::{
        PrimeField,
    },
};

use bellman_ce::{
    Circuit,
    SynthesisError,
    Variable,
    Index,
    ConstraintSystem,
    LinearCombination,
};


#[derive(Serialize, Deserialize)]
struct CircuitJson {
    pub constraints: Vec<Vec<BTreeMap<String, String>>>,
    #[serde(rename = "nPubInputs")]
    pub num_inputs: usize,
    #[serde(rename = "nOutputs")]
    pub num_outputs: usize,
    #[serde(rename = "nVars")]
    pub num_variables: usize,
}

#[derive(Clone)]
pub struct CircomCircuit<E: Engine> {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_constraints: usize,
    pub inputs: Vec<E::Fr>,
    pub aux: Vec<E::Fr>,
    pub constraints: Vec<(
        Vec<(usize, E::Fr)>,
        Vec<(usize, E::Fr)>,
        Vec<(usize, E::Fr)>,
    )>,
}

impl<'a, E: Engine> CircomCircuit<E> {
    pub fn load_witness_json_file(&mut self, filename: &str) {
        let reader = OpenOptions::new()
            .read(true)
            .open(filename)
            .expect("unable to open.");
        self.load_witness_json(reader);
    }

    pub fn load_witness_json<R: Read>(&mut self, reader: R) {
        let witness: Vec<String> = serde_json::from_reader(reader).unwrap();
        let witness = witness.into_iter().map(|x| E::Fr::from_str(&x).unwrap()).collect::<Vec<E::Fr>>();
        self.inputs = witness[..self.num_inputs].to_vec();
        self.aux = witness[self.num_inputs..].to_vec();
    }

    pub fn from_json_file(filename: &str) -> CircomCircuit::<E> {
        let reader = OpenOptions::new()
            .read(true)
            .open(filename)
            .expect("unable to open.");
        return CircomCircuit::from_json(reader);
    }

    pub fn from_json<R: Read>(reader: R) -> CircomCircuit::<E> {
        let circuit_json: CircuitJson = serde_json::from_reader(reader).unwrap();

        let num_inputs = circuit_json.num_inputs + circuit_json.num_outputs + 1;
        let num_aux = circuit_json.num_variables - num_inputs;

        fn convert_constraint<EE: Engine>(lc: &BTreeMap<String, String>) -> Vec<(usize, EE::Fr)> {
            let mut coeffs = vec![];
            for (var_index_str, coefficient_str) in lc {
                coeffs.push((var_index_str.parse().unwrap(), EE::Fr::from_str(coefficient_str).unwrap()));
            }
            return coeffs;
        }

        let mut constraints = vec![];
        for constraint in circuit_json.constraints.iter() {
            constraints.push((convert_constraint::<E>(&constraint[0]), convert_constraint::<E>(&constraint[1]), convert_constraint::<E>(&constraint[2])));
        }

        return CircomCircuit {
            num_inputs: num_inputs,
            num_aux: num_aux,
            num_constraints: circuit_json.num_variables,
            inputs: vec![],
            aux: vec![],
            constraints: constraints,
        };
    }
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for CircomCircuit<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        for i in 1..self.num_inputs {
            cs.alloc_input(|| format!("variable {}", i),
                           || {
                Ok(if self.inputs.len() > 0 { self.inputs[i] } else { E::Fr::from_str("1").unwrap() })
            })?;
        }

        for i in 0..self.num_aux {
            cs.alloc(|| format!("aux {}", i),
                           || {
                Ok(if self.aux.len() > 0 { self.aux[i] } else { E::Fr::from_str("1").unwrap() })
            })?;
        }

        fn make_lc<E: Engine>(lc_data: Vec<(usize, E::Fr)>, num_inputs: usize) -> LinearCombination<E> {
            let mut lc = LinearCombination::<E>::zero();
            for (index, coeff) in lc_data {
                let var_index = if index < num_inputs {
                    Index::Input(index)
                } else {
                    Index::Aux(index - num_inputs)
                };
                lc = lc + (coeff, Variable::new_unchecked(var_index))
            }
            return lc;
        }
        for (i, constraint) in self.constraints.iter().enumerate() {
            cs.enforce(|| format!("constraint {}", i),
                       |_| make_lc(constraint.0.clone(), self.num_inputs),
                       |_| make_lc(constraint.1.clone(), self.num_inputs),
                       |_| make_lc(constraint.2.clone(), self.num_inputs),
            );
        }
        Ok(())
    }
}
