//! This is a fork of the [secrets](https://github.com/stouset/secrets) crate.
//! This crate adds `mlock` and `mprotect` to lock the secret's page in memory
//! and read only when exposed

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs, rust_2018_idioms, unused_qualifications)]

use core::{
    any,
    fmt::{self, Debug},
};
use libc::{mprotect, PROT_NONE, PROT_READ, PROT_WRITE};
use memsec::{mlock, munlock};
use std::mem;

use zeroize::{Zeroize, ZeroizeOnDrop};

pub use zeroize;

/// Wrapper for the inner secret. Can be exposed by [`ExposeSecret`]
pub struct SecretBox<S: Zeroize> {
    inner_secret: Box<S>,
}

impl<S: Zeroize> Zeroize for SecretBox<S> {
    fn zeroize(&mut self) {
        let secret_ptr = self.inner_secret.as_ref() as *const S;

        let len = mem::size_of::<S>();

        unsafe {
            if !munlock(secret_ptr as *mut u8, len) {
                panic!("Unable to munlock variable");
            }

            if mprotect(secret_ptr as *mut libc::c_void, len, PROT_READ | PROT_WRITE) != 0 {
                panic!("Unable to unprotect variable")
            }
        }

        self.inner_secret.as_mut().zeroize()
    }
}

impl<S: Zeroize> Drop for SecretBox<S> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<S: Zeroize> ZeroizeOnDrop for SecretBox<S> {}

impl<S: Zeroize> From<Box<S>> for SecretBox<S> {
    fn from(source: Box<S>) -> Self {
        Self::new(source)
    }
}

impl<S: Zeroize> SecretBox<S> {
    /// Create a secret value using a pre-boxed value.
    pub fn new(boxed_secret: Box<S>) -> Self {
        let secret_ptr = Box::into_raw(boxed_secret);

        let len = mem::size_of::<S>();

        unsafe {
            if !mlock(secret_ptr as *mut u8, len) {
                panic!(
                    "Unable to lock memory page:{}\n",
                    std::io::Error::last_os_error()
                )
            }

            if mprotect(secret_ptr as *mut libc::c_void, len, PROT_NONE) != 0 {
                munlock(secret_ptr as *mut u8, len); // Clean up mlock
                let _ = Box::from_raw(secret_ptr);
                panic!("Unable to protect memory");
            }
        }

        let inner_secret = unsafe { Box::from_raw(secret_ptr) };

        Self { inner_secret }
    }
}

impl<S: Zeroize + Default> SecretBox<S> {
    /// Create a secret value using a function that can initialize the vale in-place.
    pub fn new_with_mut(ctr: impl FnOnce(&mut S)) -> Self {
        let mut secret = Self::default();
        ctr(secret.expose_secret_mut().inner_secret_mut());
        secret
    }
}

impl<S: Zeroize + Clone> SecretBox<S> {
    /// Create a secret value using the provided function as a constructor.
    ///
    /// The implementation makes an effort to zeroize the locally constructed value
    /// before it is copied to the heap, and constructing it inside the closure minimizes
    /// the possibility of it being accidentally copied by other code.
    ///
    /// **Note:** using [`Self::new`] or [`Self::new_with_mut`] is preferable when possible,
    /// since this method's safety relies on empyric evidence and may be violated on some targets.
    pub fn new_with_ctr(ctr: impl FnOnce() -> S) -> Self {
        let mut data = ctr();
        let secret = Self {
            inner_secret: Box::new(data.clone()),
        };
        data.zeroize();
        secret
    }

    /// Same as [`Self::new_with_ctr`], but the constructor can be fallible.
    ///
    ///
    /// **Note:** using [`Self::new`] or [`Self::new_with_mut`] is preferable when possible,
    /// since this method's safety relies on empyric evidence and may be violated on some targets.
    pub fn try_new_with_ctr<E>(ctr: impl FnOnce() -> Result<S, E>) -> Result<Self, E> {
        let mut data = ctr()?;
        let secret = Self {
            inner_secret: Box::new(data.clone()),
        };
        data.zeroize();
        Ok(secret)
    }
}

impl<S: Zeroize + Default> Default for SecretBox<S> {
    fn default() -> Self {
        Self {
            inner_secret: Box::<S>::default(),
        }
    }
}

impl<S: Zeroize> Debug for SecretBox<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBox<{}>([REDACTED])", any::type_name::<S>())
    }
}

impl<S> Clone for SecretBox<S>
where
    S: CloneableSecret,
{
    fn clone(&self) -> Self {
        SecretBox {
            inner_secret: self.inner_secret.clone(),
        }
    }
}

impl<S: Zeroize> ExposeSecret<S> for SecretBox<S> {
    fn expose_secret(&mut self) -> SecretGuard<'_, S> {
        SecretGuard::new(self.inner_secret.as_mut())
    }
}

impl<S: Zeroize> ExposeSecretMut<S> for SecretBox<S> {
    fn expose_secret_mut(&mut self) -> SecretGuard<'_, S> {
        SecretGuard::new(self.inner_secret.as_mut())
    }
}

/// Marker trait for secrets which are allowed to be cloned
pub trait CloneableSecret: Clone + Zeroize {}

/// Secret Guard that holds a mutable to reference to the secret
pub struct SecretGuard<'a, S>
where
    S: Zeroize,
{
    data: &'a mut S,
}

impl<'a, S: Zeroize> SecretGuard<'a, S> {
    /// Create a new SecretGuard instance.
    pub fn new(data: &'a mut S) -> Self {
        let len = mem::size_of_val(data);

        let guard = Self { data };

        let secret_ptr = guard.data as *const S;

        unsafe {
            if mprotect(secret_ptr as *mut libc::c_void, len, PROT_NONE) != 0 {
                panic!("Unable to protect memory")
            }
        }

        guard
    }
    /// Get a shared reference to the inner secret
    pub fn inner_secret(&self) -> &S {
        let len = mem::size_of_val(self.data);
        let secret_ptr = self.data as *const S;

        unsafe {
            if mprotect(secret_ptr as *mut libc::c_void, len, PROT_READ) != 0 {
                panic!("Unable to protect memory")
            }
        }
        self.data
    }

    /// Get an exclusive reference to the inner secret
    pub fn inner_secret_mut(&mut self) -> &mut S {
        let len = mem::size_of_val(self.data);
        let secret_ptr = self.data as *const S;

        unsafe {
            if mprotect(secret_ptr as *mut libc::c_void, len, PROT_READ) != 0 {
                panic!("Unable to protect memory")
            }
        }
        self.data
    }
}

impl<'a, S: Zeroize> Drop for SecretGuard<'a, S> {
    fn drop(&mut self) {
        let len = mem::size_of_val(self.data);
        let secret_ptr = self.data as *const S;

        unsafe {
            if mprotect(secret_ptr as *mut libc::c_void, len, PROT_NONE) != 0 {
                panic!("Unable to protect memory")
            }
        }
    }
}
/// Expose a reference to an inner secret
pub trait ExposeSecret<S: Zeroize> {
    /// Expose secret: this is the only method providing access to a secret.
    fn expose_secret(&mut self) -> SecretGuard<'_, S>;
}

/// Expose a mutable reference to an inner secret
pub trait ExposeSecretMut<S: Zeroize> {
    /// Expose secret: this is the only method providing access to a secret.
    fn expose_secret_mut(&mut self) -> SecretGuard<'_, S>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Clone, Default)]
    struct TestSecret {
        data: Vec<u8>,
    }

    impl TestSecret {
        fn new(size: usize) -> Self {
            let mut data = vec![0; size];
            data[0] = 1;
            Self { data }
        }
    }

    impl Zeroize for TestSecret {
        fn zeroize(&mut self) {
            self.data = Vec::new();
        }
    }

    #[test]
    fn test_secret_box_drop_zeroizes() {
        let secret = Box::new(TestSecret::new(10));
        SecretBox::new(secret);
    }
}
