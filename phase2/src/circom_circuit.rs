extern crate bellman_ce;
extern crate rand;

use std::str;
use std::fs;
use std::fs::{OpenOptions, File};
use std::io::{Read, Write, Seek, Error, ErrorKind};
use std::collections::BTreeMap;
use std::iter::repeat;
use std::sync::Arc;
use itertools::Itertools;
use rand::{Rng, OsRng};
use parameters::MPCParameters;
use byteorder::{LittleEndian, ReadBytesExt};
use bellman_ce::pairing::ff::Field;
use bellman_ce::pairing::ff::PrimeFieldRepr;
use bellman_ce::pairing::ff::PrimeFieldDecodingError;

use bellman_ce::{
    Circuit,
    SynthesisError,
    Variable,
    Index,
    ConstraintSystem,
    LinearCombination,
    groth16::{
        Parameters,
        Proof,
        prepare_verifying_key,
        create_random_proof,
        verify_proof,
    },
    pairing::{
        Engine,
        CurveAffine,
        ff::{
            PrimeField,
        },
        bn256::{
            Bn256,
        }
    }
};

use crate::utils::{
    repr_to_big,
    p1_to_vec,
    p2_to_vec,
    pairing_to_vec,
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

#[derive(Serialize, Deserialize)]
struct ProofJson {
    pub protocol: String,
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ProvingKeyJson {
    #[serde(rename = "A")]
    pub a: Vec<Vec<String>>,
    #[serde(rename = "B1")]
    pub b1: Vec<Vec<String>>,
    #[serde(rename = "B2")]
    pub b2: Vec<Vec<Vec<String>>>,
    #[serde(rename = "C")]
    pub c: Vec<Option<Vec<String>>>,
    pub vk_alfa_1: Vec<String>,
    pub vk_beta_1: Vec<String>,
    pub vk_delta_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "hExps")]
    pub h: Vec<Vec<String>>,
    // Todo: add json fields: nPublic, nVars, polsA, polsB, polsC, protocol: groth
}

#[derive(Serialize, Deserialize)]
struct VerifyingKeyJson {
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
    pub vk_alfa_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    pub vk_alfabeta_12: Vec<Vec<Vec<String>>>,
    pub protocol: String,
    #[serde(rename = "nPublic")]
    pub inputs_count: usize,
}

#[derive(Clone)]
pub struct CircomCircuit<E: Engine> {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_constraints: usize,
    pub witness: Option<Vec<E::Fr>>,
    pub constraints: Vec<(
        Vec<(usize, E::Fr)>,
        Vec<(usize, E::Fr)>,
        Vec<(usize, E::Fr)>,
    )>,
}

impl<'a, E: Engine> CircomCircuit<E> {
    pub fn get_public_inputs(&self) -> Option<Vec<E::Fr>> {
        return match self.witness.clone() {
            None => None,
            Some(w) => Some(w[1..self.num_inputs].to_vec()),
        }
    }

    pub fn get_public_inputs_json(&self) -> String {
        let inputs = self.get_public_inputs();
        let inputs = match inputs {
            None => return String::from("[]"),
            Some(inp) => inp.iter().map(|x| repr_to_big(x.into_repr())).collect_vec()
        };
        return serde_json::to_string(&inputs).unwrap();
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
        let witness = &self.witness.clone();
        for i in 1..self.num_inputs {
            cs.alloc_input(|| format!("variable {}", i),
                           || {
                Ok(match witness {
                    None => E::Fr::from_str("1").unwrap(),
                    Some(w) => w[i],
                })
            })?;
        }

        for i in 0..self.num_aux {
            cs.alloc(|| format!("aux {}", i),
                           || {
                Ok(match witness {
                    None => E::Fr::from_str("1").unwrap(),
                    Some(w) => w[i + self.num_inputs],
                })
            })?;
        }

        let make_index = |index|
            if index < self.num_inputs {
                Index::Input(index)
            } else {
                Index::Aux(index - self.num_inputs)
            };
        let make_lc = |lc_data: Vec<(usize, E::Fr)>|
            lc_data.iter().fold(
                LinearCombination::<E>::zero(),
                |lc: LinearCombination<E>, (index, coeff)| lc + (*coeff, Variable::new_unchecked(make_index(*index)))
            );
        for (i, constraint) in self.constraints.iter().enumerate() {
            cs.enforce(|| format!("constraint {}", i),
                       |_| make_lc(constraint.0.clone()),
                       |_| make_lc(constraint.1.clone()),
                       |_| make_lc(constraint.2.clone()),
            );
        }
        Ok(())
    }
}

pub fn prove<E: Engine, R: Rng>(circuit: CircomCircuit<E>, params: &Parameters<E>, mut rng: R) -> Result<Proof<E>, SynthesisError> {
    let mut params2 = params.clone();
    filter_params(&mut params2);
    return create_random_proof(circuit, &params2, &mut rng);
}

pub fn verify<E: Engine>(circuit: &CircomCircuit<E>, params: &Parameters<E>, proof: &Proof<E>) -> Result<bool, SynthesisError> {
    let inputs = match circuit.get_public_inputs() {
        None => return Err(SynthesisError::AssignmentMissing),
        Some(inp) => inp,
    };
    return verify_proof(
        &prepare_verifying_key(&params.vk),
        proof,
        &inputs
    );
}

pub fn create_verifier_sol(params: &Parameters<Bn256>) -> String {
    // TODO: use a simple template engine
    let bytes = include_bytes!("verifier_groth.sol");
    let template = String::from_utf8_lossy(bytes);

    let p1_to_str = |p: &<Bn256 as Engine>::G1Affine| {
        let x = repr_to_big(p.get_x().into_repr());
        let y = repr_to_big(p.get_y().into_repr());
        return format!("uint256({}), uint256({})", x, y)
    };
    let p2_to_str = |p: &<Bn256 as Engine>::G2Affine| {
        let x = p.get_x();
        let y = p.get_y();
        let x_c0 = repr_to_big(x.c0.into_repr());
        let x_c1 = repr_to_big(x.c1.into_repr());
        let y_c0 = repr_to_big(y.c0.into_repr());
        let y_c1 = repr_to_big(y.c1.into_repr());
        format!("[uint256({}), uint256({})], [uint256({}), uint256({})]", x_c1, x_c0, y_c1, y_c0)
    };

    let template = template.replace("<%vk_alfa1%>", &*p1_to_str(&params.vk.alpha_g1));
    let template = template.replace("<%vk_beta2%>", &*p2_to_str(&params.vk.beta_g2));
    let template = template.replace("<%vk_gamma2%>", &*p2_to_str(&params.vk.gamma_g2));
    let template = template.replace("<%vk_delta2%>", &*p2_to_str(&params.vk.delta_g2));

    let template = template.replace("<%vk_ic_length%>", &*params.vk.ic.len().to_string());
    let template = template.replace("<%vk_input_length%>", &*(params.vk.ic.len() - 1).to_string());

    let mut vi = String::from("");
    for i in 0..params.vk.ic.len() {
        vi = format!("{}{}vk.IC[{}] = Pairing.G1Point({});\n", vi, if vi.len() == 0 { "" } else { "        " }, i, &*p1_to_str(&params.vk.ic[i]));
    }
    let template = template.replace("<%vk_ic_pts%>", &*vi);

    return template;
}

pub fn create_verifier_sol_file(params: &Parameters<Bn256>, filename: &str) -> std::io::Result<()> {
    return fs::write(filename, create_verifier_sol(params).as_bytes());
}

pub fn proof_to_json(proof: &Proof<Bn256>) -> Result<String, serde_json::error::Error> {
    return serde_json::to_string(&ProofJson {
        protocol: "groth".to_string(),
        pi_a: p1_to_vec(&proof.a),
        pi_b: p2_to_vec(&proof.b),
        pi_c: p1_to_vec(&proof.c),
    });
}

pub fn proof_to_json_file(proof: &Proof<Bn256>, filename: &str) -> std::io::Result<()> {
    let str = proof_to_json(proof).unwrap(); // TODO: proper error handling
    return fs::write(filename, str.as_bytes());
}

pub fn load_params_file(filename: &str) -> Parameters<Bn256> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    return load_params(reader);
}

pub fn load_params<R: Read>(reader: R) -> Parameters<Bn256> {
    let should_filter_points_at_infinity = false;
    let params = MPCParameters::read(reader, should_filter_points_at_infinity, true).expect("unable to read params");
    return params.get_params().clone();
}

pub fn filter_params<E: Engine>(params: &mut Parameters<E>) {
    params.vk.ic = params.vk.ic.clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>();
    params.h = Arc::new((*params.h).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
    params.a = Arc::new((*params.a).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
    params.b_g1 = Arc::new((*params.b_g1).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
    params.b_g2 = Arc::new((*params.b_g2).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
}

pub fn proving_key_json(params: &Parameters<Bn256>) -> Result<String, serde_json::error::Error> {
    let proving_key = ProvingKeyJson {
        a: params.a.iter().map(|e| p1_to_vec(e)).collect_vec(),
        b1: params.b_g1.iter().map(|e| p1_to_vec(e)).collect_vec(),
        b2: params.b_g2.iter().map(|e| p2_to_vec(e)).collect_vec(),
        c: repeat(None).take(params.vk.ic.len()).chain(params.l.iter().map(|e| Some(p1_to_vec(e)))).collect_vec(),
        vk_alfa_1: p1_to_vec(&params.vk.alpha_g1),
        vk_beta_1: p1_to_vec(&params.vk.beta_g1),
        vk_delta_1: p1_to_vec(&params.vk.delta_g1),
        vk_beta_2: p2_to_vec(&params.vk.beta_g2),
        vk_delta_2: p2_to_vec(&params.vk.delta_g2),
        h: params.h.iter().map(|e| p1_to_vec(e)).collect_vec(),
    };
    return serde_json::to_string(&proving_key);
}

pub fn proving_key_json_file(params: &Parameters<Bn256>, filename: &str) -> std::io::Result<()> {
    let str = proving_key_json(params).unwrap(); // TODO: proper error handling
    return fs::write(filename, str.as_bytes());
}

pub fn verification_key_json(params: &Parameters<Bn256>) -> Result<String, serde_json::error::Error> {
    let verification_key = VerifyingKeyJson {
        ic: params.vk.ic.iter().map(|e| p1_to_vec(e)).collect_vec(),
        vk_alfa_1: p1_to_vec(&params.vk.alpha_g1),
        vk_beta_2: p2_to_vec(&params.vk.beta_g2),
        vk_gamma_2: p2_to_vec(&params.vk.gamma_g2),
        vk_delta_2: p2_to_vec(&params.vk.delta_g2),
        vk_alfabeta_12: pairing_to_vec(&Bn256::pairing(params.vk.alpha_g1, params.vk.beta_g2)),
        inputs_count: params.vk.ic.len() - 1,
        protocol: String::from("groth"),
    };
    return serde_json::to_string(&verification_key);
}

pub fn verification_key_json_file(params: &Parameters<Bn256>, filename: &str) -> std::io::Result<()> {
    let str = verification_key_json(params).unwrap(); // TODO: proper error handling
    return fs::write(filename, str.as_bytes());
}

pub fn witness_from_json_file<E: Engine>(filename: &str) -> Vec<E::Fr> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    return witness_from_json::<E, File>(reader);
}

pub fn witness_from_json<E: Engine, R: Read>(reader: R) -> Vec<E::Fr>{
    let witness: Vec<String> = serde_json::from_reader(reader).unwrap();
    return witness.into_iter().map(|x| E::Fr::from_str(&x).unwrap()).collect::<Vec<E::Fr>>();
}

pub fn witness_from_wtns_file<E: Engine>(filename: &str) -> Vec<E::Fr> {
    let mut reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    return witness_from_wtns::<E, File>(&mut reader).unwrap();
}

pub fn witness_from_wtns<E: Engine, R: Read>(mut reader: &mut R) -> std::io::Result<Vec<E::Fr>> {
    
    let mut magic = [0;4];

    reader.read(&mut magic)?;
    if magic != [b'w',b't',b'n',b's'] {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid file type"));
    }

    let version = reader.read_u32::<LittleEndian>()?;
    if version > 1 {
        return Err(Error::new(ErrorKind::InvalidData, "Version not supported"));
    }

    let n8 = reader.read_u32::<LittleEndian>()?;
    if n8 != 32 {
        return Err(Error::new(ErrorKind::InvalidData, "Field size is not 256 bits."));
    }

    let mut q: [u64;4] = [0;4];
    for i in 0..4 {
        q[i] = reader.read_u64::<LittleEndian>()?;
    }
    if q != [ 
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029   
      ] 
    {
        return Err(Error::new(ErrorKind::InvalidData, "Circuit not in the bn256 curve field."));
    }

    let n = reader.read_u32::<LittleEndian>()?;
    
    let mut res : Vec<E::Fr> = Vec::new();
    let mut v = E::Fr::zero().into_repr();
    for _i in 0..n {
        v.read_le(&mut reader)?;
        match E::Fr::from_repr(v) {
            Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            Ok(v) => res.push(v),
        }
    }

    Ok(res)
}

pub fn circuit_from_json_file<E: Engine>(filename: &str) -> CircomCircuit::<E> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    return circuit_from_json(reader);
}

pub fn circuit_from_json<E: Engine, R: Read>(reader: R) -> CircomCircuit::<E> {
    let circuit_json: CircuitJson = serde_json::from_reader(reader).unwrap();

    let num_inputs = circuit_json.num_inputs + circuit_json.num_outputs + 1;
    let num_aux = circuit_json.num_variables - num_inputs;

    let convert_constraint = |lc: &BTreeMap<String, String>| {
        lc.iter().map(|(index, coeff)| (index.parse().unwrap(), E::Fr::from_str(coeff).unwrap())).collect_vec()
    };

    let constraints = circuit_json.constraints.iter().map(
        |c| (convert_constraint(&c[0]), convert_constraint(&c[1]), convert_constraint(&c[2]))
    ).collect_vec();

    return CircomCircuit {
        num_inputs: num_inputs,
        num_aux: num_aux,
        num_constraints: circuit_json.num_variables,
        witness: None,
        constraints: constraints,
    };
}

pub fn create_rng() -> Box<dyn Rng> {
    return Box::new(OsRng::new().unwrap())
}




fn circuit_from_r1cs_read_header<E: Engine, R:Read>(circuit : &mut CircomCircuit<E>, reader: &mut R) -> std::io::Result<()> {

    let n8 = reader.read_u32::<LittleEndian>()?;
    if n8 != 32 {
        return Err(Error::new(ErrorKind::InvalidData, "Field size is not 256 bits."));
    }

    let mut q: [u64;4] = [0;4];
    for i in 0..4 {
        q[i] = reader.read_u64::<LittleEndian>()?;
    }

    if q != [ 
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029   
      ] 
    {
        return Err(Error::new(ErrorKind::InvalidData, "Circuit not in the bn256 curve field."));
    }


    let n_vars = (reader.read_u32::<LittleEndian>()?) as usize;
    let n_outputs = (reader.read_u32::<LittleEndian>()?) as usize;
    let n_pub_inputs = (reader.read_u32::<LittleEndian>()?) as usize;
    let _n_prv_inputs = (reader.read_u32::<LittleEndian>()?) as usize;
    let _n_labels = (reader.read_u64::<LittleEndian>()?) as usize;
    let n_constraints = (reader.read_u32::<LittleEndian>()?) as usize;

    circuit.num_inputs = n_pub_inputs + n_outputs + 1;
    circuit.num_aux = n_vars-circuit.num_inputs;
    circuit.num_constraints = n_constraints;

    Ok(())
}

fn circuit_from_r1cs_read_lc<E: Engine, R:Read>(mut reader: &mut R) -> std::io::Result< Vec<(usize, E::Fr)> > {
    let mut lc : Vec<(usize, E::Fr)> = Vec::new();
    let n_coefs = reader.read_u32::<LittleEndian>()?;
    for _i in 0..n_coefs {
        let coef_id = (reader.read_u32::<LittleEndian>()?) as usize;
        let mut coef_val = E::Fr::zero().into_repr();
        coef_val.read_le(&mut reader)?;
        match E::Fr::from_repr(coef_val) {
            Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            Ok(v) => lc.push((coef_id, v)),
        }
    }
    
    Ok(lc)
}

fn circuit_from_r1cs_read_constraint<E: Engine, R:Read>(circuit : &mut CircomCircuit<E>, mut reader: &mut R) -> std::io::Result<()> {
    let lc_a = circuit_from_r1cs_read_lc::<E,R>(&mut reader)?;
    let lc_b = circuit_from_r1cs_read_lc::<E,R>(&mut reader)?;
    let lc_c = circuit_from_r1cs_read_lc::<E,R>(&mut reader)?;

    circuit.constraints.push((lc_a, lc_b, lc_c));

    Ok(())
}

fn circuit_from_r1cs_read_constraints<E: Engine, R:Read>(mut circuit : &mut CircomCircuit<E>, mut reader: &mut R) -> std::io::Result<()> {
    for _i in 0..circuit.num_constraints {
        circuit_from_r1cs_read_constraint::<E,R>(&mut circuit, &mut reader)?;
    }
    Ok(())
}



pub fn circuit_from_r1cs<E: Engine, R:Read + Seek>(mut reader: R) -> std::io::Result<CircomCircuit::<E>> {
    let mut magic = [0;4];
    let mut circuit= CircomCircuit {
        num_inputs: 0,
        num_aux: 0,
        num_constraints: 0,
        witness: None,
        constraints: Vec::new()
    };
    let mut pos :i64 = 0;

    reader.read(&mut magic)?;
    pos +=4;

    if magic != [b'r',b'1',b'c',b's'] {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid file type"));
    }


    let version = reader.read_u32::<LittleEndian>()?;
    pos += 4;
    if version > 1 {
        return Err(Error::new(ErrorKind::InvalidData, "Version not supported"));
    }

    let mut header_pos: Option<i64> = None;
    let mut constraints_pos: Option<i64> = None;

    let n_sections = reader.read_u32::<LittleEndian>()?;
    pos += 4;
    for _i in 0..n_sections {
        let section_type = reader.read_u32::<LittleEndian>()?;
        pos += 4;
        let section_len = (reader.read_u64::<LittleEndian>()?) as i64;
        pos += 8;
        match section_type {
            1 => match  header_pos {
                None => header_pos = Some(pos),
                Some(_) => return Err(Error::new(ErrorKind::InvalidData, "2 Headers sections in the file"))
            },
            2 => match  constraints_pos {
                None => constraints_pos = Some(pos),
                Some(_) => return Err(Error::new(ErrorKind::InvalidData, "2 Constraints sections in the file"))
            },
            _ => ()
        }
        reader.seek(std::io::SeekFrom::Current(section_len))?;
        pos = pos + section_len;
    }

    match header_pos {
        Some(p) => {
            reader.seek(std::io::SeekFrom::Start(p as u64))?;
            circuit_from_r1cs_read_header(&mut circuit, &mut reader)?;
        },
        None => return Err(Error::new(ErrorKind::InvalidData, "No header section")) 
    }

    match constraints_pos {
        Some(p) => {
            reader.seek(std::io::SeekFrom::Start(p as u64))?;
            circuit_from_r1cs_read_constraints(&mut circuit, &mut reader)?;
        },
        None => return Err(Error::new(ErrorKind::InvalidData, "No constraints section")) 
    }

    Ok(circuit)
}

pub fn circuit_from_r1cs_file<E: Engine>(filename: &str) -> CircomCircuit::<E> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    return circuit_from_r1cs(reader).unwrap();
}