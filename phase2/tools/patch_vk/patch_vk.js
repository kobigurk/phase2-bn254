const fs = require('fs');
const {stringifyBigInts, unstringifyBigInts} = require('snarkjs/src/stringifybigint.js');
const BN128 =  require('snarkjs/src/bn128');

const bn128 = new BN128();

const json = unstringifyBigInts(JSON.parse(fs.readFileSync('transformed_vk.json')));
json.vk_alfabeta_12 = bn128.F12.affine(bn128.pairing( json.vk_alfa_1 , json.vk_beta_2 ));
fs.writeFileSync('patched_transformed_vk.json', JSON.stringify(stringifyBigInts(json)));
