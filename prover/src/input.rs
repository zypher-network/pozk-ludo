use anyhow::anyhow;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ethabi::decode;
use ethabi::encode;
use ethabi::ethereum_types::U256;
use ethabi::ParamType;
use ethabi::Token;
use ludo_ai_game::build_cs::LudoGame;
use ludo_ai_game::build_cs::ROUND_LEN;
use ludo_ai_game::circuits::operation::Operation;
use ludo_ai_game::circuits::piece::LudoPiece;
use ludo_ai_game::circuits::Mode;
use ludo_ai_game::NUM_PIECES;
use num_bigint::BigInt;
use num_bigint::Sign;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::ops::AddAssign;
use std::ops::Mul;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Input {
    pub operations: Vec<Vec<u8>>, // 3*2*16=96bit
    pub pieces: Vec<u8>,
    pub nonce: String,
}

impl TryInto<LudoGame> for Input {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<LudoGame, Self::Error> {
        let operations = self
            .operations
            .iter()
            .map(|x| x.iter().map(|y| Operation::new(*y)).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        let pieces = self
            .pieces
            .iter()
            .map(|x| LudoPiece::new(*x))
            .collect::<Vec<_>>();

        Ok(LudoGame {
            operations,
            pieces,
            nonce: self.nonce,
            mode: Mode::NORMAL,
        })
    }
}

pub fn pack(val: &[u8], base: BigInt) -> BigInt {
    let mut factor = vec![BigInt::one()];
    for _ in 0..val.len() {
        factor.push(factor.last().unwrap().mul(base.clone()));
    }

    let mut packed_board = BigInt::zero();
    for (f, v) in factor.into_iter().zip(val.iter()) {
        packed_board.add_assign(BigInt::from(*v).mul(f));
    }

    packed_board
}

pub fn unpack(val: BigInt, bit: usize, len: usize) -> Vec<u8> {
    let bits = val.to_radix_le(2).1;

    let mut res = vec![];
    for b in bits.chunks(bit) {
        let mut result: u8 = 0;

        for (i, b) in b.iter().enumerate() {
            if *b == 1 {
                result |= 1 << i;
            }
        }

        res.push(result);
    }

    res.extend_from_slice(&[0].repeat(len - res.len()));

    res
}

pub fn encode_prove_inputs(inputs: &[Input]) -> String {
    let mut encode_inputs = vec![];
    for input in inputs {
        let operations = input
            .operations
            .clone()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        assert_eq!(operations.len(), ROUND_LEN * 3);
        assert_eq!(input.pieces.len(), NUM_PIECES);

        let packed_operations = pack(&operations, BigInt::from(4));
        let packed_pieces = pack(&input.pieces, BigInt::from(64));

        let operations = Token::Uint(U256::from_little_endian(&packed_operations.to_bytes_le().1));
        let pieces = Token::Uint(U256::from_little_endian(&packed_pieces.to_bytes_le().1));
        let nonce = Token::Uint(U256::from_dec_str(&input.nonce).unwrap());

        encode_inputs.push(Token::FixedArray(vec![operations, pieces, nonce]));
    }

    let bytes = encode(&[Token::Array(encode_inputs)]);
    format!("0x{}", hex::encode(&bytes))
}

pub fn decode_prove_inputs(bytes: &[u8]) -> Result<Vec<Input>, anyhow::Error> {
    let mut input_tokens = decode(
        &[ParamType::Array(Box::new(ParamType::Tuple(vec![
            ParamType::Uint(256), // packed_operations
            ParamType::Uint(256), // packed_peces
            ParamType::Uint(256), // nonce
        ])))],
        bytes,
    )?;

    let tokens = input_tokens.pop().unwrap().into_array().unwrap();

    let f_uint = |token: Token| -> BigInt {
        let mut bytes = [0u8; 32];
        token.into_uint().unwrap().to_big_endian(&mut bytes);
        BigInt::from_bytes_be(Sign::Plus, &bytes)
    };

    let mut circuits = vec![];

    for t_token in tokens {
        let token = t_token.into_tuple().unwrap();

        let packed_operations = f_uint(token[0].clone());
        let unpacked_operations = unpack(packed_operations, 2, 48);
        let t_operations = unpacked_operations
            .chunks_exact(3)
            .map(|x| x.to_vec())
            .collect::<Vec<_>>();

        let packed_pieces = f_uint(token[1].clone());
        let unpacked_pieces = unpack(packed_pieces, 6, 16);

        let nonce = f_uint(token[2].clone());

        let circuit = Input {
            operations: t_operations,
            pieces: unpacked_pieces,
            nonce: nonce.to_string(),
        };
        circuits.push(circuit);
    }

    Ok(circuits)
}

pub fn decode_multiple_prove_publics(
    bytes: &[u8],
    size: usize,
) -> Result<Vec<Vec<Fr>>, anyhow::Error> {
    let mut input_tokens = decode(
        &[ParamType::Array(Box::new(ParamType::FixedArray(
            Box::new(ParamType::Uint(256)),
            size,
        )))],
        bytes,
    )?;
    let tokens = input_tokens
        .pop()
        .ok_or_else(|| anyhow!("Infallible point"))?
        .into_array()
        .ok_or_else(|| anyhow!("Infallible point"))?;
    let mut publics = vec![];
    for token in tokens {
        let ffs = token
            .into_fixed_array()
            .ok_or_else(|| anyhow!("Infallible point"))?;
        let mut public = vec![];
        for fs in ffs {
            let mut bytes = [0u8; 32];
            fs.into_uint().unwrap().to_big_endian(&mut bytes);
            let f = Fr::from_be_bytes_mod_order(&bytes);
            public.push(f);
        }

        publics.push(public);
    }

    Ok(publics)
}

#[cfg(test)]
mod test {
    use num_bigint::BigInt;

    use crate::input::{pack, unpack};

    use super::{decode_prove_inputs, encode_prove_inputs, Input};

    #[test]
    fn test_pack() {
        let x = vec![
            0, 3, 2, 1, 0, 0, 1, 2, 3, 3, 2, 1, 2, 3, 1, 2, 3, 3, 0, 0, 1, 1, 2, 2, 3, 3, 0,
        ];
        let y = unpack(pack(&x, BigInt::from(4)), 2, x.len());
        assert_eq!(x, y);

        let x = vec![0, 12, 13, 15, 20, 1, 2, 3, 57, 58, 59, 20, 20, 0];
        let y = unpack(pack(&x, BigInt::from(64)), 6, x.len());
        assert_eq!(x, y);
    }

    #[test]
    fn test_serialize() {
        {
            let input = r##"
        {
            "operations": [[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0],[0,0,0]],
            "pieces": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "nonce": "1"
        }
        "##;

            let input: Input = serde_json::from_str(input).unwrap();
            let inputs = vec![input.clone(), input];

            let hex = encode_prove_inputs(&inputs);
            println!("input:{}", hex);

            let inputs_hex = hex.trim_start_matches("0x");
            let inputs_bytes = hex::decode(inputs_hex).unwrap();
            let decode = decode_prove_inputs(&inputs_bytes).unwrap();
            assert_eq!(decode, inputs)
        }

        {
            let input = r##"
        {
            "operations": [[1,2,3],[0,0,0],[1,1,1],[2,2,2],[3,3,3],[1,2,3],[2,2,2],[3,3,3],[0,0,0],[0,0,0],[0,0,3],[2,0,0],[2,1,0],[1,2,0],[1,2,0],[1,2,0]],
            "pieces": [1,2,3,4,5,6,7,8,9,10,50,51,52,53,54,0],
            "nonce": "123456789987654321"
        }
        "##;

            let input: Input = serde_json::from_str(input).unwrap();
            let inputs = vec![input.clone(), input];

            let hex = encode_prove_inputs(&inputs);

            let inputs_hex = hex.trim_start_matches("0x");
            let inputs_bytes = hex::decode(inputs_hex).unwrap();
            let decode = decode_prove_inputs(&inputs_bytes).unwrap();
            assert_eq!(decode, inputs)
        }
    }
}
