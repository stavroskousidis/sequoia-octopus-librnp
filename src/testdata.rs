//! Data for tests.

/// The sample keys from RFC 9980, Appendix A.
pub mod rfc9980 {
    use sequoia_openpgp as openpgp;
    use openpgp::{
        Cert,
        parse::Parse,
    };

    /// What we expect RNP's interface to report for a key.
    pub struct TestKey {
        /// The algorithm ID.
        ///
        /// From RFC 9580, Section 9.1, and RFC 9980, Section 2.1.
        pub algo: u8,

        /// The name of the algorithm in RNP's interface.
        pub name: &'static str,

        /// The size of the algorithm-specific part of the public key
        /// in bits.
        ///
        /// From RFC 9580, Section 5.5.5.9, and RFC 9980, Tables 3, 4,
        /// 6, 7, and 8.
        pub bits: u32,

        /// The fingerprint as given in Appendix A.
        pub fingerprint: &'static str,

        /// The SHA-1 digest of the algorithm-specific part of the
        /// public key.
        ///
        /// These values have been computed without the help of
        /// Sequoia: they are the output of `sha1sum` over the
        /// corresponding octets of the key packets.
        pub grip: &'static str,
    }

    /// A Transferable Secret Key, and what we expect for its keys.
    pub struct TestVector {
        /// The section of RFC 9980 containing the key.
        pub section: &'static str,
        /// The Transferable Secret Key.
        pub tsk: &'static [u8],
        /// The version of the keys.
        pub version: u32,
        /// The primary key.
        pub primary: TestKey,
        /// The subkey.
        pub subkey: TestKey,
    }

    impl TestVector {
        /// Returns the certificate without secret key material.
        pub fn cert(&self) -> Cert {
            Cert::from_bytes(self.tsk).expect("valid test vector")
                .strip_secret_key_material()
        }

        /// Returns the primary key followed by the subkey.
        pub fn keys(&self) -> [&TestKey; 2] {
            [&self.primary, &self.subkey]
        }
    }

    /// The Transferable Secret Keys of Appendix A.
    pub const VECTORS: &[TestVector] = &[
        TestVector {
            section: "A.1.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.1.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 27,
                name: "ED25519",
                bits: 256,
                fingerprint: "C789E17D9DBDCA7B3C833A3C063FEB03\
                              53F80AD911FE27868FB0645DF803E947",
                grip: "FBF78E7446713336F95ABBEE206BF9D8DAD17C9A",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "DAFE0EEBB2675ECFCDC20A23FE89CA5D\
                              12E83F527DFA354B6DCF662131A48B9D",
                grip: "E0DEC15C542EFCB5C9E41728196E6EA9F13C0C22",
            },
        },
        TestVector {
            section: "A.2.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.2.1.asc"),
            version: 4,
            primary: TestKey {
                algo: 27,
                name: "ED25519",
                bits: 256,
                fingerprint: "342E5DB2DE345215CB2C944F7102FFED3B9CF12D",
                grip: "901EA858C5B0F3593051942DB3CC8B697AAD5CE7",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "E51DBFEA51936988B5428FFFA4F95F985ED61A51",
                grip: "C41E084A34816E4D5D8022B26B78407D0F1D94AE",
            },
        },
        TestVector {
            section: "A.3.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.3.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 30,
                name: "ML-DSA-65+ED25519",
                bits: (32 + 1952) * 8,
                fingerprint: "A3E2E14B6A493FF930FB27321F125E9A\
                              6880338BE9FB7DA3AE065EA65793242F",
                grip: "77AD1BA119493C82C9EA3C72B0B56F40048483CF",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "7DAE8FBCE23022607167AF72A002E774\
                              E0CA379A2D7AE072384E1E8FDE3265E4",
                grip: "7E5AD0CBF8569101AD2287FC62053123E06FCACE",
            },
        },
        TestVector {
            section: "A.4.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.4.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 31,
                name: "ML-DSA-87+ED448",
                bits: (57 + 2592) * 8,
                fingerprint: "0D7A8BE1410CD68EED4845AB487B4B4C\
                              FAECD8EBAD1A1166A84230499200EE20",
                grip: "04CC18DD1A9AA42D842B2CE9C33C769C0D23C32D",
            },
            subkey: TestKey {
                algo: 36,
                name: "ML-KEM-1024+X448",
                bits: (56 + 1568) * 8,
                fingerprint: "65090E147A8116AB7F62AB4EC7AAE59D\
                              9E6532FEB2AF230C73CDC869FBC60C8F",
                grip: "40F5F050AC42DFEB08FC083D6A59AD45F05DD2FF",
            },
        },
        TestVector {
            section: "A.5.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.5.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 32,
                name: "SLH-DSA-SHAKE-128s",
                bits: 32 * 8,
                fingerprint: "EED4D13FC36C78E48276A93233339C4D\
                              D230FD5F6F5C5B82C63D5C0B5E361D92",
                grip: "33511300AD3923446F14C483BC1A360C8BD97831",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "3E8745A4BB488779E0F32480FA23F8D0\
                              BFD8C2F49D7F74E957E1C2FFC2EF4BFC",
                grip: "F3F98BBBFF5A2B960D5508F877447E4911C6DB5B",
            },
        },
        TestVector {
            section: "A.6.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.6.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 33,
                name: "SLH-DSA-SHAKE-128f",
                bits: 32 * 8,
                fingerprint: "D54E0307021169F7B88BEB2B76E3AAD0\
                              E114BE1A8F982D74DBA9CA51D03537F4",
                grip: "EA1629EEB728D33110C63DA5AC60BBF968FCFAC2",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "D8875664256C382DD7F3A5CE05021088\
                              922811F5D0B1A1F8C7769944A51B7002",
                grip: "296B6CF2E09FF7613294EB88A55465C693832D1F",
            },
        },
        TestVector {
            section: "A.7.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.7.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 34,
                name: "SLH-DSA-SHAKE-256s",
                bits: 64 * 8,
                fingerprint: "72FFF84863AEBA67F0D1D7691173247D\
                              D427533B9D7EE76011C6F77F2CE9FA7A",
                grip: "5A2C7C9051B24D017F38AFFDB8E0171175C5187A",
            },
            subkey: TestKey {
                algo: 36,
                name: "ML-KEM-1024+X448",
                bits: (56 + 1568) * 8,
                fingerprint: "570A5BBAB93169876A8240DA35A1ADA7\
                              BA8A640AABE3AB467C797214844DF15F",
                grip: "52637724D06BEBF5AC767116409CD3FD8ACF19D6",
            },
        },
    ];
}
