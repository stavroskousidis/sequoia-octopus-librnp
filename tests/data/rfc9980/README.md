Test vectors from RFC 9980, "Post-Quantum Cryptography in OpenPGP",
Appendix A.

`A.N.1.asc` is the Transferable Secret Key of Appendix A.N.1, copied
from the text of the RFC (https://www.rfc-editor.org/rfc/rfc9980.txt)
without the indentation.  The keys are sample keys that are published
in the RFC.  Do not use them for anything but tests.

| File      | Primary key        | Subkey            | Version |
|-----------|--------------------|-------------------|---------|
| A.1.1.asc | Ed25519            | ML-KEM-768+X25519 | 6       |
| A.2.1.asc | Ed25519            | ML-KEM-768+X25519 | 4       |
| A.3.1.asc | ML-DSA-65+Ed25519  | ML-KEM-768+X25519 | 6       |
| A.4.1.asc | ML-DSA-87+Ed448    | ML-KEM-1024+X448  | 6       |
| A.5.1.asc | SLH-DSA-SHAKE-128s | ML-KEM-768+X25519 | 6       |
| A.6.1.asc | SLH-DSA-SHAKE-128f | ML-KEM-768+X25519 | 6       |
| A.7.1.asc | SLH-DSA-SHAKE-256s | ML-KEM-1024+X448  | 6       |

`A.N.M.asc` with M = 3 or 4 is the detached signature of Appendix
A.N.M, copied the same way.  Each is a v6 signature over the text
document "Testing\n", made by the primary key of the Transferable
Secret Key of the same appendix.

| File      | Made by   | Algorithm          | Hash algorithm |
|-----------|-----------|--------------------|----------------|
| A.3.4.asc | A.3.1.asc | ML-DSA-65+Ed25519  | SHA2-256       |
| A.4.4.asc | A.4.1.asc | ML-DSA-87+Ed448    | SHA3-512       |
| A.5.4.asc | A.5.1.asc | SLH-DSA-SHAKE-128s | SHA2-256       |
| A.6.3.asc | A.6.1.asc | SLH-DSA-SHAKE-128f | SHA2-256       |
| A.7.3.asc | A.7.1.asc | SLH-DSA-SHAKE-256s | SHA2-512       |
