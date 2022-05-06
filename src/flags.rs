// Key export flags.
pub type RnpKeyExportFlags = u32;
pub const RNP_KEY_EXPORT_ARMORED: RnpKeyExportFlags = 1 << 0;
pub const RNP_KEY_EXPORT_PUBLIC:  RnpKeyExportFlags = 1 << 1;
pub const RNP_KEY_EXPORT_SECRET:  RnpKeyExportFlags = 1 << 2;
pub const RNP_KEY_EXPORT_SUBKEYS: RnpKeyExportFlags = 1 << 3;

// Key remove flags.
pub type RnpKeyRemoveFlags = u32;
pub const RNP_KEY_REMOVE_PUBLIC:  RnpKeyRemoveFlags = 1 << 0;
pub const RNP_KEY_REMOVE_SECRET:  RnpKeyRemoveFlags = 1 << 1;
pub const RNP_KEY_REMOVE_SUBKEYS: RnpKeyRemoveFlags = 1 << 2;

// Key unload flags.
pub type RnpKeyUnloadFlags = u32;
pub const RNP_KEY_UNLOAD_PUBLIC: RnpKeyUnloadFlags = 1 << 0;
pub const RNP_KEY_UNLOAD_SECRET: RnpKeyUnloadFlags = 1 << 1;

// Flags for optional details to include in JSON.
pub type RnpJsonFlags = u32;
pub const RNP_JSON_PUBLIC_MPIS:    RnpJsonFlags = 1 << 0;
pub const RNP_JSON_SECRET_MPIS:    RnpJsonFlags = 1 << 1;
pub const RNP_JSON_SIGNATURES:     RnpJsonFlags = 1 << 2;
pub const RNP_JSON_SIGNATURE_MPIS: RnpJsonFlags = 1 << 3;

// Flags to include additional data in packet dumping.
pub type RnpJsonDumpFlags = u32;
pub const RNP_JSON_DUMP_MPI:  RnpJsonDumpFlags = 1 << 0;
pub const RNP_JSON_DUMP_RAW:  RnpJsonDumpFlags = 1 << 1;
pub const RNP_JSON_DUMP_GRIP: RnpJsonDumpFlags = 1 << 2;

pub type RnpDumpFlags = u32;
pub const RNP_DUMP_MPI:  RnpDumpFlags = 1 << 0;
pub const RNP_DUMP_RAW:  RnpDumpFlags = 1 << 1;
pub const RNP_DUMP_GRIP: RnpDumpFlags = 1 << 2;

// Flags for the key loading/saving functions.
pub type RnpLoadSaveFlags = u32;
pub const RNP_LOAD_SAVE_PUBLIC_KEYS: RnpLoadSaveFlags = 1 << 0;
pub const RNP_LOAD_SAVE_SECRET_KEYS: RnpLoadSaveFlags = 1 << 1;
pub const RNP_LOAD_SAVE_PERMISSIVE:  RnpLoadSaveFlags = 1 << 8;
pub const RNP_LOAD_SAVE_SINGLE:      RnpLoadSaveFlags = 1 << 9;

// Flags for output structure creation.
pub type RnpOutputFlags = u32;
pub const RNP_OUTPUT_FILE_OVERWRITE: RnpOutputFlags = 1 << 0;
pub const RNP_OUTPUT_FILE_RANDOM:    RnpOutputFlags = 1 << 1;

// User id type.
pub type RnpUserIDType = u32;
pub const RNP_USER_ID:   RnpUserIDType = 1;
pub const RNP_USER_ATTR: RnpUserIDType = 2;

// Flags for rnp_key_remove_signatures.
pub type RnpKeyRemoveSignatureFlags = u32;
pub const RNP_KEY_SIGNATURE_INVALID:   RnpKeyRemoveSignatureFlags = 1;
pub const RNP_KEY_SIGNATURE_UNKNOWN_KEY: RnpKeyRemoveSignatureFlags = 2;
pub const RNP_KEY_SIGNATURE_NON_SELF_SIG: RnpKeyRemoveSignatureFlags = 4;

pub type RnpKeyRemoveSignatureAction = u32;
pub const RNP_KEY_SIGNATURE_KEEP:   RnpKeyRemoveSignatureAction = 0;
pub const RNP_KEY_SIGNATURE_REMOVE: RnpKeyRemoveSignatureAction = 1;

// Flags for rnp_op_encrypt_set_flags.
pub type RnpEncryptFlags = u32;
pub const RNP_ENCRYPT_NOWRAP: RnpEncryptFlags = 1 << 0;

// Flags for rnp_*_security_rule
pub type RnpSecurityFlags = u32;
pub const RNP_SECURITY_OVERRIDE: RnpSecurityFlags = 1 << 0;
pub const RNP_SECURITY_REMOVE_ALL: RnpSecurityFlags = 1 << 16;

pub type RnpSecurityLevel = u32;
pub const RNP_SECURITY_PROHIBITED: RnpSecurityLevel = 0;
pub const RNP_SECURITY_INSECURE: RnpSecurityLevel = 1;
pub const RNP_SECURITY_DEFAULT: RnpSecurityLevel = 2;
