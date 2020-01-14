#![allow(unused_imports)]

extern crate bellman_ce;

use std::str;
use std::fs;
use std::collections::BTreeMap;

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

pub struct CircomCircuit<'a> {
    pub file_name: &'a str,
    pub has_witness: bool,
    pub witness_file_name: &'a str,
}

impl CircomCircuit<'_> {
    pub fn parse_witness<E: Engine>(&self) -> (Vec<E::Fr>, Vec<E::Fr>) {
        if self.has_witness {
            let content = fs::read_to_string(self.file_name).unwrap();
            let circuit_json: CircuitJson = serde_json::from_str(&content).unwrap();

            let witness_content = fs::read_to_string(self.witness_file_name).unwrap();
            let witness: Vec<String> = serde_json::from_str(&witness_content).unwrap();
            let witness = witness.into_iter().map(|x| E::Fr::from_str(&x).unwrap()).collect::<Vec<E::Fr>>();
            let num_public_inputs = circuit_json.num_inputs + circuit_json.num_outputs + 1;
            (witness[..num_public_inputs].to_vec(), witness[num_public_inputs..].to_vec())
        } else {
            (vec![], vec![])
        }
    }
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for CircomCircuit<'a> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let content = fs::read_to_string(self.file_name)?;
        let circuit_json: CircuitJson = serde_json::from_str(&content).unwrap();
        let witness_tup = self.parse_witness::<E>();
        let mut witness = witness_tup.0.clone();
        witness.extend_from_slice(&witness_tup.1);

        let num_public_inputs = circuit_json.num_inputs + circuit_json.num_outputs + 1;
        println!("witness: {:?}", witness);
        println!("num public inputs: {}", num_public_inputs);
        for i in 1..circuit_json.num_variables {
            if i < num_public_inputs {
                cs.alloc_input(|| format!("variable {}", i), || {
                        println!("index: {}", i);
                    if self.has_witness {
                        Ok(witness[i])
                    } else {
                        Ok(E::Fr::from_str("1").unwrap())
                    }
                })?;
            } else {
                cs.alloc(|| format!("variable {}", i), || {
                    if self.has_witness {
                        Ok(witness[i])
                    } else {
                        Ok(E::Fr::from_str("1").unwrap())
                    }
                })?;
            }
        }
        let mut constrained: BTreeMap<usize, bool> = BTreeMap::new();
        let mut constraint_num = 0;
        for (i, constraint) in circuit_json.constraints.iter().enumerate() {
            let mut lcs = vec![];
            for lc_description in constraint {
                let mut lc = LinearCombination::<E>::zero();
                for (var_index_str, coefficient_str) in lc_description {
                    let var_index_num: usize = var_index_str.parse().unwrap();
                    let var_index = if var_index_num < num_public_inputs {
                        Index::Input(var_index_num)
                    } else {
                        Index::Aux(var_index_num - num_public_inputs)
                    };
                    constrained.insert(var_index_num, true);
                    if i == 2 {
                        lc = lc + (E::Fr::from_str(coefficient_str).unwrap(), Variable::new_unchecked(var_index));
                    } else {
                        lc = lc + (E::Fr::from_str(coefficient_str).unwrap(), Variable::new_unchecked(var_index));
                    }
                }
                lcs.push(lc);
            }
            cs.enforce(|| format!("constraint {}", constraint_num), |_| lcs[0].clone(), |_| lcs[1].clone(), |_| lcs[2].clone());
            constraint_num += 1;
        }
        println!("constraints: {}", circuit_json.constraints.len());
        let mut unconstrained: BTreeMap<usize, bool> = BTreeMap::new();
        for i in 0..circuit_json.num_variables {
            if !constrained.contains_key(&i) {
                unconstrained.insert(i, true);
            }
        }
        for (i, _) in unconstrained {
            println!("variable {} is unconstrained", i);
        }
        Ok(())
    }
}
