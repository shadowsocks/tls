// The TLS Protocol Version 1.0
// 5. HMAC and the pseudorandom function
// https://datatracker.ietf.org/doc/html/rfc2246#section-5
// 
// The Transport Layer Security (TLS) Protocol Version 1.1
// 5. HMAC and the Pseudorandom Function
// https://datatracker.ietf.org/doc/html/rfc4346#section-5
use crypto2::hash::{Md5, Sha1};
use crypto2::mac::{HmacMd5, HmacSha1};


pub fn prf(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    // L_S1 = L_S2 = ceil(L_S / 2);
    let len_s1 = (secret.len() + 1) / 2;
    let len_s2 = secret.len() / 2;
    let s1 = &secret[..len_s1];
    let s2 = &secret[len_s2..];
    
    // P_MD5(S1, label + seed)
    let hmac = HmacMd5::new(s1);
    // A(1)
    let mut hmac_clone = hmac.clone();
    hmac_clone.update(&label);
    hmac_clone.update(&seed);
    let mut a = hmac_clone.finalize();

    let olen = out.len();
    let mut offset = 0;
    while offset < olen {
        // P_hash[i] = HMAC_hash(secret, A(i) + seed)
        let mut hmac_clone = hmac.clone();
        hmac_clone.update(&a);
        hmac_clone.update(&label);
        hmac_clone.update(&seed);
        let hash = hmac_clone.finalize();

        let end = core::cmp::min(offset + HmacMd5::TAG_LEN, olen);
        let len = end - offset;
        out[offset..end].copy_from_slice(&hash[..len]);
        offset += len;

        // A(i+1) = HMAC_hash(secret, A(i))
        let mut hmac_clone = hmac.clone();
        hmac_clone.update(&a);
        a = hmac_clone.finalize();
    }

    // P_SHA-1(S2, label + seed)
    let hmac = HmacSha1::new(s2);
    // A(1)
    let mut hmac_clone = hmac.clone();
    hmac_clone.update(&label);
    hmac_clone.update(&seed);
    let mut a = hmac_clone.finalize();

    offset = 0;
    while offset < olen {
        // P_hash[i] = HMAC_hash(secret, A(i) + seed)
        let mut hmac_clone = hmac.clone();
        hmac_clone.update(&a);
        hmac_clone.update(&label);
        hmac_clone.update(&seed);
        let hash = hmac_clone.finalize();

        let end = core::cmp::min(offset + HmacSha1::TAG_LEN, olen);
        let len = end - offset;
        // XOR
        for i in 0..len {
            out[offset + i] ^= hash[i];
        }
        // out[offset..end].copy_from_slice(&hash[..len]);
        offset += len;

        // A(i+1) = HMAC_hash(secret, A(i))
        let mut hmac_clone = hmac.clone();
        hmac_clone.update(&a);
        a = hmac_clone.finalize();
    }
}


#[test]
fn test_tls_v10_prf() {
    // https://github.com/randombit/botan/blob/master/src/tests/data/kdf/tls_prf.vec
    let secret = hex::decode("6C81AF87ABD86BE83C37CE981F6BFE11BD53A8").unwrap();
    let salt = hex::decode("A6D455CB1B2929E43D63CCE55CE89D66F252549729C19C1511").unwrap();
    let output = hex::decode("A8").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);

    let secret = hex::decode("6BB61D34AF2BCCF45A850850BCDE35E55A92BA").unwrap();
    let salt = hex::decode("510194C9C9F90D98452FB914F636D5E5297C").unwrap();
    let output = hex::decode("5E75").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);

    let secret = hex::decode("3CC54F5F3EF82C93CE60EB62DC9DF005280DD1").unwrap();
    let salt = hex::decode("7FC24D382379A9CD54D53458947CB28E298A1DCC5EB2556F71ACAC1B").unwrap();
    let output = hex::decode("706F52").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);

    let secret = hex::decode("BD3462DC587DFA992AE48BD7643B62A9971928").unwrap();
    let salt = hex::decode("9F6FAFED1F241A1E40ADEAF2AD80").unwrap();
    let output = hex::decode("841D7339").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);

    let secret = hex::decode("1235A061FA3867B8E51511D1E672CE141E2FA6").unwrap();
    let salt = hex::decode("1026B9224FC59706BEADAE58EBD161FD2EAC").unwrap();
    let output = hex::decode("D856787D41").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);

    let secret = hex::decode("63A22C3C7C5651103648F5CFC9764A7BDE821F").unwrap();
    let salt = hex::decode("512FBF47D9DA2915").unwrap();
    let output = hex::decode("F13096FEED6E").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("AA15082F10F25EC4F96DFFE9DC3D80BBA6361B").unwrap();
    let salt = hex::decode("519B87DB85FBE92FB4070F3BEF6E3D97DF69B66061EB83B4A334E8EEDC0F8E").unwrap();
    let output = hex::decode("B637FCADE57896").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("775B727CE679B8696171C7BE60FC2E3F4DE516").unwrap();
    let salt = hex::decode("453C2549058B063C83E8B85E5CEF3570DF51B7D79B486F4F33").unwrap();
    let output = hex::decode("3431016193616501").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("AB299AD69DC581F13D86562AE2BE8B08015FF8").unwrap();
    let salt = hex::decode("5569FC").unwrap();
    let output = hex::decode("A624CC363499B1EA64").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("AE4947624D877916E5B01EDDAB8E4CDC817630").unwrap();
    let salt = hex::decode("7FDE51EFB4044017C95E3608F8FB6F").unwrap();
    let output = hex::decode("5B908EB5B2A7F115CF57").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("4F13EB6FBE1FA2FCD7B5B21C9F20980D1986A4").unwrap();
    let salt = hex::decode("514DBCE520AB34").unwrap();
    let output = hex::decode("EE73EEE90E35AF2BC3575D").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("41BC094049008CBAE99CAC0BA901D0B2DD15DF").unwrap();
    let salt = hex::decode("CB6C0544FF8CF74C71E910F2220D54C509DC442CB3").unwrap();
    let output = hex::decode("BD859DAE2729A348774146B5").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("95751B37945DD9DE515B45927A229AAB40F7D0").unwrap();
    let salt = hex::decode("75318F49A11F42A24AF48267411FDD0831").unwrap();
    let output = hex::decode("FE310AF0913149D53718AC53E5").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("FC250F36E5C1365C3EAD122E63F90612DBBDA7").unwrap();
    let salt = hex::decode("8A4B5AEA3AC0B2FF777D77B5EFB6E7D8AF").unwrap();
    let output = hex::decode("C0107D144E53227EDE5E677A35BE").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("F6A8A67ACA60F25080100F3F5C928038936E57").unwrap();
    let salt = hex::decode("F8B663768421BA77861F1EBEBF4C8341DC01ED1F7D4B054B7C").unwrap();
    let output = hex::decode("A1FCD686295E3DE32C438A8FFD63CE").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("77BF131D53997B1FB2ACE2137E26992B36BF3E").unwrap();
    let salt = hex::decode("859D1EE9A694865ECC1830C361D24485AC1026").unwrap();
    let output = hex::decode("60D0A09FCFDE24AB73F62A7C9F594766").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("39CF412177DD47B8E97A4D92D104138CD4E41C").unwrap();
    let salt = hex::decode("9CD35F26E8A89C25410B3394A957B781BBD0D190DA").unwrap();
    let output = hex::decode("F7D49D2C112F3EE64411F50B264AE15BB4").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("5C40AF252D0A4F445E638D954993BCB0673281").unwrap();
    let salt = hex::decode("2DFB810DC9ED5B291754144937E6052666D476D1F5F94C").unwrap();
    let output = hex::decode("FDA100D44E2F839C21199A56ACAF57454C21").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("2A8B07B082F2A4C95611B20685A4410E90B8D2").unwrap();
    let salt = hex::decode("320ADFA586F7EBF346646DE9").unwrap();
    let output = hex::decode("A5CCE186AFDB9C0EB664C719DD1A69C1BA6059").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("BCBD1EFDA490B9D541BA9DF50FE9A451DD0313").unwrap();
    let salt = hex::decode("255230A341E671BC31B1").unwrap();
    let output = hex::decode("2291E19459725562F106F63FE2F81E73BA23F04A").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("B361B123993602D0BA62567BF9B81992DB108EAE").unwrap();
    let salt = hex::decode("20878A3A703785DE37846086C097619E9823F7FCD2B7B3A9466FA6").unwrap();
    let output = hex::decode("A71CB3E9C58E83414D69775CF7127E9C95AF10B7E2").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("8E7CC0EED8BFF691B370C08FE0DB32D06700B088").unwrap();
    let salt = hex::decode("02F3B9155F5CFF08B9F47A2FDC701BA3F08BCDDF21292911D06FC0A5A99B").unwrap();
    let output = hex::decode("25DA6B3027CBBCA4352EFB85D3FCB9060285BC39ECB8").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("041CC7ED27C01A701A0F15269DA6CA6D806B10C3").unwrap();
    let salt = hex::decode("8E5F4FADE80AF92D495AF5A50C8E").unwrap();
    let output = hex::decode("E3B7F0D721C05663166B43A75F2997F9F029886FC069D0").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("A7421C0D96D2455E57408C2BF02E86DCEE71B060").unwrap();
    let salt = hex::decode("BD2623716653B538C885FA2ED4B0A2").unwrap();
    let output = hex::decode("46948B1DD4C7977AA7241ABD74A88E7838E575DD34AA9B75").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("56DAD2D1AF95F938E073D10A1A779F80BB0F76FE").unwrap();
    let salt = hex::decode("D1DA1DEF7BD5C327894B7A992AA7A694664470F642").unwrap();
    let output = hex::decode("53B1169FA52AABC427D1C41501B612DF6D726F55DAD9D246E9").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("4F2E4F77820A686894B90A0AFD0ABA772D0CC6B0").unwrap();
    let salt = hex::decode("062577E22854BAF0E68A51A27644FFB0").unwrap();
    let output = hex::decode("30ED285AE596143BE7998901C2F35530D81CA4DD14E03D17DF2C").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("86173BD0F3C5E7052482B53BD8604E197112F3D8").unwrap();
    let salt = hex::decode("12B4E5F24ADC8A").unwrap();
    let output = hex::decode("BB3BD1CBFA7889441E930C4B5E8EC7AB00D9612E9D762D42427AD9").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("2B9CE8B0AB3041D6A1803BDD342E6537E40BE305").unwrap();
    let salt = hex::decode("517D3D00850F48912B713E653CB4F38703B6A6").unwrap();
    let output = hex::decode("88F8AFCB8109C7B359B18CCED73A1B09404CC9EABB23695BF353ED9E").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("819CB722AA4475D8301A8E24DCD9D82DF2B081F4").unwrap();
    let salt = hex::decode("56872A31A10E8C").unwrap();
    let output = hex::decode("83FD6F33AD11819019E086F0683E26D59D57C9E5AF26C81738E44D47A3").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("80F1F9B0D05F41C448E5306E41833918B9E688ED").unwrap();
    let salt = hex::decode("6175CDE230DF6691F4E8A36B265C53CAD736AD6F34F895D5C6633D66B5").unwrap();
    let output = hex::decode("0C00B5F50565FDD5345C63773D5FCC8B3C8E412DFFF23B95490EFB4E53FA").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("0AE876A7BB96C24CEFA6ED53CEE7B0A41B8FF7B3").unwrap();
    let salt = hex::decode("").unwrap();
    let output = hex::decode("881B99C3E43B1A42F096CF556D3143D5C5DBC4E984D26C5F3075BCB08B73DA").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);


    let secret = hex::decode("2212169D33FADC6FF94A3E5E0020587953CF1964").unwrap();
    let salt = hex::decode("FCD5C9637A21E43F3CFF6ECF65B6E2F97933779F101AD6").unwrap();
    let output = hex::decode("1E1C646C2BFBDC62FA4C81F1D0781F5F269D3F45E5C33CAC8A2640226C8C5D16").unwrap();
    let label: &[u8] = b"";
    let mut out = vec![0u8; output.len()];
    prf(&secret, label, &salt, &mut out);
    assert_eq!(&out, &output);
}