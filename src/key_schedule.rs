// 7.1.  Key Schedule
// https://tools.ietf.org/html/rfc8446#section-7.1
// 
//     HKDF-Expand-Label(Secret, Label, Context, Length) =
//         HKDF-Expand(Secret, HkdfLabel, Length)
// 
//     Where HkdfLabel is specified as:
// 
//     struct {
//        uint16 length = Length;
//        opaque label<7..255> = "tls13 " + Label;
//        opaque context<0..255> = Context;
//     } HkdfLabel;
// 
//     Derive-Secret(Secret, Label, Messages) =
//         HKDF-Expand-Label(Secret, Label,
//                           Transcript-Hash(Messages), Hash.length)
// 
// 
//     (EC)DHE -> HKDF-Extract = Handshake Secret
//              |
//              +-----> Derive-Secret(., "c hs traffic",
//              |                     ClientHello...ServerHello)
//              |                     = client_handshake_traffic_secret
//              |
//              +-----> Derive-Secret(., "s hs traffic",
//              |                     ClientHello...ServerHello)
//              |                     = server_handshake_traffic_secret
//              v
//        Derive-Secret(., "derived", "")
// 
// 
// 7.5.  Exporters
// https://datatracker.ietf.org/doc/html/rfc8446#section-7.5
//    TLS-Exporter(label, context_value, key_length) = 
//          HKDF-Expand-Label(Derive-Secret(Secret, label, ""), "exporter", Hash(context_value), key_length)
use crypto2::hash::{Sha256, Sha384};
use crypto2::kdf::{HkdfSha256, HkdfSha384};


/// TLSv1.3 Secret Generator
#[derive(Clone)]
pub struct SecretGeneratorSha256 {
    early_secret: HkdfSha256,
    handshake_secret: HkdfSha256,
    master_secret: HkdfSha256,

    server_application_traffic_secret_last: Option<[u8; HkdfSha256::TAG_LEN]>,
    client_application_traffic_secret_last: Option<[u8; HkdfSha256::TAG_LEN]>,
}

impl SecretGeneratorSha256 {
    pub const OUTPUT_LEN: usize = HkdfSha256::TAG_LEN;

    // PSK (a pre-shared key established externally or derived from the
    // resumption_master_secret value from a previous connection)
    pub fn new(psk: &[u8], ecdhe_shared_secret: &[u8]) -> Self {
        let zeros = [0u8; HkdfSha256::TAG_LEN];
        let salt = &zeros;
        let ikm = psk;

        let early_secret = HkdfSha256::new(salt, ikm);
        
        let salt = Self::derive_secret(&early_secret, b"derived", b"");
        let ikm = ecdhe_shared_secret;
        let handshake_secret = HkdfSha256::new(&salt, ikm);

        let salt = Self::derive_secret(&handshake_secret, b"derived", b"");
        let ikm = &zeros;
        let master_secret = HkdfSha256::new(&salt, ikm);

        let server_application_traffic_secret_last = None;
        let client_application_traffic_secret_last = None;

        Self { 
            early_secret, handshake_secret, master_secret, 
            server_application_traffic_secret_last,
            client_application_traffic_secret_last, 
         }
    }

    pub fn early_secret(&self) -> &[u8; HkdfSha256::TAG_LEN] {
        self.early_secret.prk()
    }

    pub fn hkdf_expand_label(secret: &HkdfSha256, label: &[u8], hash: &[u8], okm: &mut [u8]) {
        // 7.1.  Key Schedule
        // https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
        //     HKDF-Expand-Label(Secret, Label, Context, Length) =
        //         HKDF-Expand(Secret, HkdfLabel, Length)
        // 
        //     Where HkdfLabel is specified as:
        // 
        //     struct {
        //        uint16 length = Length;
        //        opaque label<7..255> = "tls13 " + Label;
        //        opaque context<0..255> = Context;
        //     } HkdfLabel;
        // 
        //     Derive-Secret(Secret, Label, Messages) =
        //         HKDF-Expand-Label(Secret, Label,
        //                           Transcript-Hash(Messages), Hash.length)
        const LABEL_PREFIX: &[u8] = b"tls13";

        let olen = okm.len();
        let hlen = hash.len();
        let label_len = LABEL_PREFIX.len() + label.len();

        assert!(olen <= u16::MAX as usize);
        assert!(hlen <= u8::MAX as usize);
        assert!(label_len >= 7 && label_len <= 255);
        
        // OKM-LEN
        let olen_octets = (olen as u16).to_be_bytes(); // uint16
        // LABEL-LEN
        let llen_octets = (label_len as u8).to_be_bytes();           // u8
        // HASH-LEN
        let hlen_octets = (hlen as u8).to_be_bytes();                // u8

        let multi_info: [&[u8]; 6] = [
            &olen_octets,        // OKM-LEN
            &llen_octets,        // LABEL-LEN
            LABEL_PREFIX, label, // Lable
            &hlen_octets, &hash, // CONTEXT-LEN (Hash-Len), Context (Hash)
        ];

        // HKDF-Expand(Secret, HkdfLabel, Length)
        secret.expand_multi_info(&multi_info, okm);
    }

    pub fn derive_secret(secret: &HkdfSha256, label: &[u8], messages: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        // 4.4.1.  The Transcript Hash
        // https://tools.ietf.org/html/rfc8446#section-4.4.1
        // 
        // Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
        let hash = Sha256::oneshot(messages);

        let mut okm = [0u8; Sha256::DIGEST_LEN];
        Self::hkdf_expand_label(secret, label, &hash, &mut okm);
        okm
    }

    // ==========  Early Secret ============
    pub fn derive_binder_key(&self, label: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        Self::derive_secret(&self.early_secret, label, b"")
    }
    pub fn derive_ext_binder_key(&self) -> [u8; HkdfSha256::TAG_LEN] {
        Self::derive_secret(&self.early_secret, b"ext binder", b"")
    }
    pub fn derive_res_binder_key(&self) -> [u8; HkdfSha256::TAG_LEN] {
        Self::derive_secret(&self.early_secret, b"res binder", b"")
    }

    pub fn derive_client_early_traffic_secret(&self, messages: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        Self::derive_secret(&self.early_secret, b"c e traffic", messages)
    }

    pub fn derive_early_exporter_master_secret(&self, messages: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        Self::derive_secret(&self.early_secret, b"e exp master", messages)
    }

    // ============ Handshake Secret ==============
    pub fn derive_client_handshake_traffic_secret(&self, messages: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        Self::derive_secret(&self.handshake_secret, b"c hs traffic", messages)
    }

    pub fn derive_server_handshake_traffic_secret(&self, messages: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        Self::derive_secret(&self.handshake_secret, b"s hs traffic", messages)
    }

    // ============== Master Secret ==================
    pub fn derive_client_application_traffic_secret_0(&mut self, messages: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        let secret = Self::derive_secret(&self.master_secret, b"c ap traffic", messages);
        self.client_application_traffic_secret_last = Some(secret);
        secret
    }

    pub fn derive_client_application_traffic_secret_next(&mut self) -> [u8; HkdfSha256::TAG_LEN] {
        // application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)

        // NOTE: 需要先调用 derive_client_application_traffic_secret_0 函数后再调用此函数。
        let application_traffic_secret_last = self.client_application_traffic_secret_last.unwrap();
        let hkdf = HkdfSha256::from_prk(&application_traffic_secret_last);

        let mut okm = [0u8; Sha256::DIGEST_LEN];
        Self::hkdf_expand_label(&hkdf, b"traffic upd", b"", &mut okm);
        self.client_application_traffic_secret_last = Some(okm);
        
        okm
    }

    pub fn derive_server_application_traffic_secret_0(&mut self, messages: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        let secret = Self::derive_secret(&self.master_secret, b"s ap traffic", messages);
        self.server_application_traffic_secret_last = Some(secret);
        secret
    }
    pub fn derive_server_application_traffic_secret_next(&mut self) -> [u8; HkdfSha256::TAG_LEN] {
        // application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)

        // NOTE: 需要先调用 derive_client_application_traffic_secret_0 函数后再调用此函数。
        let application_traffic_secret_last = self.server_application_traffic_secret_last.unwrap();
        let hkdf = HkdfSha256::from_prk(&application_traffic_secret_last);
        
        let mut okm = [0u8; Sha256::DIGEST_LEN];
        Self::hkdf_expand_label(&hkdf, b"traffic upd", b"", &mut okm);
        self.server_application_traffic_secret_last = Some(okm);
        
        okm
    }

    pub fn derive_exporter_master_secret(&self, messages: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        Self::derive_secret(&self.master_secret, b"exp master", messages)
    }

    pub fn derive_resumption_master_secret(&self, messages: &[u8]) -> [u8; HkdfSha256::TAG_LEN] {
        Self::derive_secret(&self.master_secret, b"res master", messages)
    }

    // 7.2.  Updating Traffic Secrets
    // https://datatracker.ietf.org/doc/html/rfc8446#section-7.2
    // The next-generation application_traffic_secret is computed as:
    // 
    //    application_traffic_secret_N+1 =
    //        HKDF-Expand-Label(application_traffic_secret_N,
    //                          "traffic upd", "", Hash.length)
    // 
    // Once client_/server_application_traffic_secret_N+1 and its associated
    // traffic keys have been computed, implementations SHOULD delete
    // client_/server_application_traffic_secret_N and its associated
    // traffic keys.
    pub fn derive_application_traffic_secret_next(last_application_traffic_secret: &[u8; HkdfSha256::TAG_LEN]) -> [u8; HkdfSha256::TAG_LEN] {
        let hkdf = HkdfSha256::from_prk(last_application_traffic_secret);
        
        let mut okm = [0u8; Sha256::DIGEST_LEN];
        Self::hkdf_expand_label(&hkdf, b"traffic upd", b"", &mut okm);
        okm
    }

    // 7.3.  Traffic Key Calculation
    // https://datatracker.ietf.org/doc/html/rfc8446#section-7.3
    // 
    // The traffic keying material is generated from an input traffic secret value using:
    // 
    //     [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
    //     [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
    // 
    // [sender] denotes the sending side.  The value of Secret for each
    // record type is shown in the table below.
    // 
    //     +-------------------+---------------------------------------+
    //     | Record Type       | Secret                                |
    //     +-------------------+---------------------------------------+
    //     | 0-RTT Application | client_early_traffic_secret           |
    //     |                   |                                       |
    //     | Handshake         | [sender]_handshake_traffic_secret     |
    //     |                   |                                       |
    //     | Application Data  | [sender]_application_traffic_secret_N |
    //     +-------------------+---------------------------------------+
    pub fn derive_traffic_key(secret: &[u8; HkdfSha256::TAG_LEN], key: &mut [u8]) {
        let hkdf = HkdfSha256::from_prk(secret);
        Self::hkdf_expand_label(&hkdf, b"key", b"", key);
    }

    pub fn derive_traffic_iv(secret: &[u8; HkdfSha256::TAG_LEN], iv: &mut [u8]) {
        let hkdf = HkdfSha256::from_prk(secret);
        Self::hkdf_expand_label(&hkdf, b"iv", b"", iv);
    }
}
