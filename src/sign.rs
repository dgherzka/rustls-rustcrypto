#[cfg(feature = "alloc")]
use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

#[cfg(feature = "p256")]
use self::ecdsa::EcdsaSigningKeyP256;
#[cfg(feature = "p384")]
use self::ecdsa::EcdsaSigningKeyP384;
#[cfg(feature = "x25519")]
use self::eddsa::Ed25519SigningKey;
use self::rsa::RsaSigningKey;

use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureScheme};
use signature::{RandomizedSigner, SignatureEncoding};

#[derive(Debug)]
pub struct GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding,
    T: RandomizedSigner<S>,
{
    _marker: PhantomData<S>,
    key: Arc<T>,
    scheme: SignatureScheme,
}

impl<T, S> Signer for GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding + Send + Sync + core::fmt::Debug,
    T: RandomizedSigner<S> + Send + Sync + core::fmt::Debug,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .try_sign_with_rng(&mut rand_core::OsRng, message)
            .map_err(|_| rustls::Error::General("signing failed".into()))
            .map(|sig: S| sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
pub struct GenericSigner<S, T>
where
    S: SignatureEncoding,
    T: signature::Signer<S>,
{
    _marker: PhantomData<S>,
    key: Arc<T>,
    scheme: SignatureScheme,
}

impl<S, T> Signer for GenericSigner<S, T>
where
    S: SignatureEncoding + Send + Sync + core::fmt::Debug,
    T: signature::Signer<S> + Send + Sync + core::fmt::Debug,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .try_sign(message)
            .map_err(|_| rustls::Error::General("signing failed".into()))
            .map(|sig: S| sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Extract any supported key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    RsaSigningKey::try_from(der)
        .map(|x| Arc::new(x) as _)
        .or_else(|_| any_ecdsa_type(der))
        .or_else(|_| any_eddsa_type(der))
}

/// Extract any supported ECDSA key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
pub fn any_ecdsa_type(
    #[allow(unused)] der: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    #[allow(unused_mut)]
    let mut result = Err(Error::General("not supported".into()));

    #[cfg(feature = "p256")]
    {
        result = result.or_else(|_| EcdsaSigningKeyP256::try_from(der).map(|x| Arc::new(x) as _));
    }

    #[cfg(feature = "p384")]
    {
        result = result.or_else(|_| EcdsaSigningKeyP384::try_from(der).map(|x| Arc::new(x) as _));
    }

    result
}

/// Extract any supported EDDSA key from the given DER input.
///
/// # Errors
///
/// Returns an error if the key couldn't be decoded.
pub fn any_eddsa_type(
    #[allow(unused)] der: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    // TODO: Add support for Ed448

    #[allow(unused_mut)]
    let mut result = Err(Error::General("not supported".into()));

    #[cfg(feature = "x25519")]
    {
        result = result.or_else(|_| Ed25519SigningKey::try_from(der).map(|x| Arc::new(x) as _));
    }

    result
}

pub mod ecdsa;
pub mod eddsa;
pub mod rsa;
