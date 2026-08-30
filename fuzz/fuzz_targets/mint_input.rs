#![no_main]

use lexicon_core::linter::{LintEngine, NameCandidate};
use lexicon_core::pool::{AgencyAlloc, Pool, PoolSet};
use lexicon_core::types::{indices_from_beta, mint_alpha, NameType};
use lexicon_core::vrf;
use lexicon_core::Authority;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 45 {
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let seq = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let nonce = u32::from_le_bytes(data[40..44].try_into().unwrap());
    let tag = data[44] % 5 + 1;
    let Some(ty) = NameType::from_tag(tag) else {
        return;
    };

    let auth = Authority::from_seed("DIA", seed);
    let alpha = mint_alpha("DIA", ty, "fuzz", seq, nonce);
    let Ok((pi, beta)) = auth.vrf_prove(&alpha) else {
        return;
    };
    let pk = auth.public_key();
    let Ok(out) = vrf::verify(&pk, &alpha, &pi) else {
        panic!("self-proof failed to verify");
    };
    assert_eq!(out.as_bytes(), beta.as_bytes());

    let pools = tiny();
    if let Ok(sizes) = pools.pool_sizes(ty, "DIA") {
        let idx = indices_from_beta(beta.as_bytes(), &sizes);
        if let Ok(name) = pools.compose(ty, "DIA", &idx) {
            if let Ok(words) = pools.lookup_words(ty, "DIA", &idx) {
                let _ = LintEngine::core().check(&NameCandidate {
                    name,
                    name_type: ty,
                    words,
                });
            }
        }
    }
});

fn tiny() -> PoolSet {
    PoolSet {
        id: "fuzz".into(),
        nickname_first: Pool::from_lines("nf", "AMBER\nCOPPER\nGRANITE\nTIMBER\n"),
        nickname_second: Pool::from_lines("ns", "LEDGER\nSPIRE\nRIDGE\nORBIT\n"),
        codeword: Pool::from_lines("cw", "OXIDE\nPEBBLE\nQUARRY\nWALNUT\n"),
        cryptonym_word: Pool::from_lines("cr", "FLOOR\nLANTERN\nORCHID\nTINDER\n"),
        exercise_first: Pool::from_lines("ef", "AMBER\nCOPPER\nGRANITE\nTIMBER\n"),
        exercise_second: Pool::from_lines("es", "DRILL\nRELAY\nSIGNAL\nVECTOR\n"),
        agencies: vec![AgencyAlloc {
            id: "DIA".into(),
            first_letters: "ACGT".into(),
            digraphs: vec!["DI".into()],
            sap_designators: vec!["TK".into(), "SI".into()],
        }],
    }
}
