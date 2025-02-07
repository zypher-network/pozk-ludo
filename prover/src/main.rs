use anyhow::anyhow;
use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ethabi::{encode, ethereum_types::U256, Token};
use input::{decode_multiple_prove_publics, decode_prove_inputs};
use ludo_ai_game::build_cs::LudoGame;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

mod input;

const PK_BYTES: &[u8] = include_bytes!("../../../materials/prover_key.bin");
// const PK_BYTES: &[u8] = include_bytes!("../../materials/prover_key.bin");

#[tokio::main]
async fn main() {
    let input_path = std::env::var("INPUT").expect("env INPUT missing");
    let bytes = reqwest::get(&input_path)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();

    // parse inputs and publics
    let mut input_len_bytes = [0u8; 4];
    input_len_bytes.copy_from_slice(&bytes[0..4]);
    let input_len = u32::from_be_bytes(input_len_bytes) as usize;

    let input_bytes = &bytes[4..input_len + 4];
    let publics_bytes = &bytes[input_len + 4..];

    let inputs = decode_prove_inputs(input_bytes).expect("Unable to decode inputs");
    let inputs = inputs
        .iter()
        .map(|x| x.clone().try_into().unwrap())
        .collect::<Vec<LudoGame>>();
    let publics =
        decode_multiple_prove_publics(publics_bytes, 2).expect("Unable to decode publics");
    assert_eq!(inputs.len(), publics.len());

    let mut rng = ChaChaRng::from_entropy();
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(PK_BYTES).unwrap();
    let mut proofs = vec![];
    for (input, pi) in inputs.into_iter().zip(publics.iter()) {
        let proof = Groth16::<Bn254>::prove(&pk, input, &mut rng).unwrap();

        {
            let pvk = Groth16::<Bn254>::process_vk(&pk.vk).unwrap();
            assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, pi, &proof).unwrap());
        }

        proofs.push(proof);
    }

    let bytes = multiple_proofs_to_abi_bytes(&proofs).unwrap();
    let client = reqwest::Client::new();
    client.post(&input_path).body(bytes).send().await.unwrap();
}

pub fn multiple_proofs_to_abi_bytes(proofs: &[Proof<Bn254>]) -> Result<Vec<u8>, anyhow::Error> {
    let mut m_pr_token = vec![];
    for proof in proofs {
        let mut proof_token = vec![];
        let (ax, ay) = proof.a.xy().ok_or_else(|| anyhow!("Infallible point"))?;
        proof_token.push(parse_filed_to_token(&ax));
        proof_token.push(parse_filed_to_token(&ay));

        let (bx, by) = proof.b.xy().ok_or_else(|| anyhow!("Infallible point"))?;
        proof_token.push(parse_filed_to_token(&bx.c1));
        proof_token.push(parse_filed_to_token(&bx.c0));
        proof_token.push(parse_filed_to_token(&by.c1));
        proof_token.push(parse_filed_to_token(&by.c0));

        let (cx, cy) = proof.c.xy().ok_or_else(|| anyhow!("Infallible point"))?;
        proof_token.push(parse_filed_to_token(&cx));
        proof_token.push(parse_filed_to_token(&cy));

        m_pr_token.push(Token::FixedArray(proof_token));
    }
    let l_pr_token = Token::Array(m_pr_token);
    let proof_bytes = encode(&[l_pr_token]);

    Ok(proof_bytes)
}

#[inline]
fn parse_filed_to_token<F: PrimeField>(f: &F) -> Token {
    let bytes = f.into_bigint().to_bytes_be();
    Token::Uint(U256::from_big_endian(&bytes))
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Bn254, Fr};
    use ark_ff::{BigInteger, Field, PrimeField};
    use ark_groth16::{Groth16, ProvingKey};
    use ark_serialize::CanonicalDeserialize;
    use ark_snark::SNARK;
    use ethabi::{ethereum_types::U256, Token};
    use ludo_ai_game::build_cs::LudoGame;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use std::{str::FromStr, time::Instant};

    use crate::{
        input::{decode_multiple_prove_publics, decode_prove_inputs},
        PK_BYTES,
    };

    #[tokio::test]
    async fn test() {
        let input_bytes = hex::decode("00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let mut pi_token = vec![];
        pi_token.push(Token::Uint(U256::from_big_endian(
            &Fr::ONE.into_bigint().to_bytes_be(),
        )));
        pi_token.push(Token::Uint(U256::from_big_endian(
            &Fr::from_str("1092739377885103454644040430160177557655257088")
                .unwrap()
                .into_bigint()
                .to_bytes_be(),
        )));
        let pi_bytes = ethabi::encode(&[Token::Array(vec![
            Token::FixedArray(pi_token.clone()),
            Token::FixedArray(pi_token),
        ])]);

        let inputs = decode_prove_inputs(&input_bytes).expect("Unable to decode inputs");
        let inputs = inputs
            .iter()
            .map(|x| x.clone().try_into().unwrap())
            .collect::<Vec<LudoGame>>();
        let publics =
            decode_multiple_prove_publics(&pi_bytes, 2).expect("Unable to decode publics");

        let mut rng = ChaChaRng::from_entropy();
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(PK_BYTES).unwrap();

        for (input, pi) in inputs.into_iter().zip(publics.iter()) {
            let start_time = Instant::now();
            let proof = Groth16::<Bn254>::prove(&pk, input, &mut rng).unwrap();
            let end_time = Instant::now();
            println!("prove time:{:.2?}", end_time - start_time);

            let pvk = Groth16::<Bn254>::process_vk(&pk.vk).unwrap();
            assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, pi, &proof).unwrap());
        }
    }
}
