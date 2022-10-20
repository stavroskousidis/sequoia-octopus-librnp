//! This is a stub implementation of parcimonie, which is used when
//! the `net` feature is disabled.

use crate::Keystore;
use crate::openpgp::policy::Policy;

pub struct Parcimonie {
}

impl Parcimonie {
    pub fn new<P>(_policy: P, ks: &Keystore) -> Self
        where P: Policy
    {
        // The real parcimonie uses this.  Use it here to avoid an
        // unused warning.
        if false {
            let _ = ks.create_ref();
        }

        Parcimonie {
        }
    }
}
