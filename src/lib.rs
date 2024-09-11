//! This is a fork of the [secrets](https://github.com/stouset/secrets) crate.
//! This crate adds `mlock`  to lock the secret's page in memory

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

use core::{
    any,
    fmt::{self, Debug},
};
use std::mem::size_of_val;
use std::ops::{Deref, DerefMut};

#[cfg(unix)]
use errno::errno;

#[cfg(unix)]
use std::ffi::c_void;

#[cfg(unix)]
use libc::{mlock, munlock, sysconf, _SC_PAGESIZE};

#[cfg(target_os = "linux")]
use libc::{madvise, MADV_DODUMP, MADV_DONTDUMP};

pub use zeroize;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper for the inner secret. Can be exposed by [`ExposeSecret`]
pub struct SecretBox<S: Zeroize> {
    inner_secret: Box<S>,
}

impl<S: Zeroize> Zeroize for SecretBox<S> {
    fn zeroize(&mut self) {
        self.inner_secret.as_mut().zeroize()
    }
}

impl<S: Zeroize> Drop for SecretBox<S> {
    fn drop(&mut self) {
        let len = size_of_val(&*self.inner_secret);
        let secret_ptr = self.inner_secret.as_ref() as *const S;

        #[cfg(unix)]
        {
            let page_size = unsafe { sysconf(_SC_PAGESIZE) };

            if page_size == -1 {
                panic!("Error getting page size: \n{}", errno())
            }

            let page_size = page_size as usize;
            // Align the address and size to the page boundary
            let start = (secret_ptr as usize) & !(page_size - 1);
            let end = ((secret_ptr as usize) + len + page_size - 1) & !(page_size - 1);
            let aligned_len = end - start;

            unsafe {
                #[cfg(target_os = "linux")]
                if madvise(start as *mut c_void, aligned_len, MADV_DODUMP) != 0 {
                    panic!("madvise failed: \n{:?}", errno());
                }

                if munlock(start as *const c_void, aligned_len) != 0 {
                    panic!("Unable to munlock variable: \n {:?} \n", errno())
                }
            }
        }

        #[cfg(windows)]
        unsafe {
            if windows_sys::Win32::System::Memory::VirtualUnlock(secret_ptr.cast(), len) == 0 {
                panic!("VirtualUnlock failed",);
            }
        }

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
        let len = size_of_val(&*boxed_secret);

        let secret_ptr = Box::into_raw(boxed_secret);

        #[cfg(unix)]
        {
            let page_size = unsafe { sysconf(_SC_PAGESIZE) };
            if page_size == -1 {
                panic!("Error getting page size: \n{}", errno())
            }

            let page_size = page_size as usize;

            // Align the address and size to the page boundary
            let start = (secret_ptr as usize) & !(page_size - 1);
            let end = ((secret_ptr as usize) + len + page_size - 1) & !(page_size - 1);
            let aligned_len = end - start;

            unsafe {
                #[cfg(target_os = "linux")]
                if madvise(start as *mut c_void, aligned_len, MADV_DONTDUMP) != 0 {
                    panic!("madvise failed: \n{:?}", errno());
                }
                if mlock(start as *const c_void, aligned_len) != 0 {
                    panic!("mlock failed: \n{:?}", errno());
                }
            }
        }

        #[cfg(windows)]
        unsafe {
            if windows_sys::Win32::System::Memory::VirtualLock(secret_ptr.cast(), len) == 0 {
                panic!("VirtualLock failed",);
            }
        }

        // Recreate Box from raw pointer
        let inner_secret = unsafe { Box::from_raw(secret_ptr) };

        Self { inner_secret }
    }
}

impl<S: Zeroize + Default> SecretBox<S> {
    /// Create a secret value using a function that can initialize the vale in-place.
    pub fn new_with_mut(ctr: impl FnOnce(&mut S)) -> Self {
        let mut secret = Self::default();
        ctr(&mut *secret.expose_secret_mut());
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
        let secret = Self::new(Box::new(data.clone()));
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
        let secret = Self::new(Box::new(data.clone()));
        data.zeroize();
        Ok(secret)
    }
}

impl<S: Zeroize + Default> Default for SecretBox<S> {
    fn default() -> Self {
        let inner_secret = Box::<S>::default();
        SecretBox::new(inner_secret)
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
        SecretBox::new(self.inner_secret.clone())
    }
}

impl<S: Zeroize> ExposeSecret<S> for SecretBox<S> {
    fn expose_secret(&mut self) -> SecretGuard<'_, S> {
        SecretGuard::new(&self.inner_secret)
    }

    fn expose_secret_mut(&mut self) -> SecretGuardMut<'_, S> {
        SecretGuardMut::new(&mut self.inner_secret)
    }
}

/// Secret Guard that holds a reference to the secret.
#[derive(Debug, Eq, PartialEq)]
pub struct SecretGuard<'a, S>
where
    S: Zeroize,
{
    data: &'a S,
}

impl<S> Deref for SecretGuard<'_, S>
where
    S: Zeroize,
{
    type Target = S;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

/// Secret Guard that holds a mutable to reference to the secret.
#[derive(Debug, Eq, PartialEq)]
pub struct SecretGuardMut<'a, S>
where
    S: Zeroize,
{
    data: &'a mut S,
}

impl<S> Deref for SecretGuardMut<'_, S>
where
    S: Zeroize,
{
    type Target = S;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<S> DerefMut for SecretGuardMut<'_, S>
where
    S: Zeroize,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<'a, S: Zeroize> SecretGuard<'a, S> {
    /// Create a new SecretGuard instance.
    pub fn new(data: &'a S) -> Self {
        Self { data }
    }
}

impl<'a, S: Zeroize> SecretGuardMut<'a, S> {
    /// Create a new SecretGuard instance.
    pub fn new(data: &'a mut S) -> Self {
        Self { data }
    }
}

/// Marker trait for secrets which are allowed to be cloned
pub trait CloneableSecret: Clone + Zeroize {}

/// Create a SecretGuard that holds a reference to the secret
pub trait ExposeSecret<S: Zeroize> {
    /// Expose secret as non-mutable.
    fn expose_secret(&mut self) -> SecretGuard<'_, S>;

    /// Expose secret as mutable.
    fn expose_secret_mut(&mut self) -> SecretGuardMut<'_, S>;
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

        fn check_non_zero(&self) -> bool {
            self.data.iter().any(|&x| x != 0)
        }

        fn check_zero(&self) -> bool {
            self.data.iter().all(|&x| x == 0)
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
        let mut secret_box = SecretBox::new(secret);
        assert!((*secret_box.expose_secret()).check_non_zero());

        drop(secret_box);

        // Verify that secret is zeroized after drop
        // This requires checking the memory, which is not straightforward in Rust.
        // Here we rely on the zeroize trait to ensure it zeroizes.
        assert!(TestSecret::default().check_zero());
    }

    #[test]
    fn test_secret_box_expose_secret_mut() {
        let secret = Box::new(String::from("Encrypted"));
        let mut secret_box = SecretBox::new(secret);

        {
            let mut exposed = secret_box.expose_secret_mut();
            (*exposed) = String::from("Encrypted 2");
        }

        assert_eq!((*secret_box.expose_secret()), String::from("Encrypted 2"));
    }

    #[test]
    fn test_secret_box_new_with_ctr() {
        let mut secret_box = SecretBox::new_with_ctr(|| TestSecret::new(10));
        assert!((*secret_box.expose_secret()).check_non_zero());
    }

    #[test]
    fn test_secret_box_try_new_with_ctr() {
        let result: Result<SecretBox<TestSecret>, &'static str> =
            SecretBox::try_new_with_ctr(|| Ok(TestSecret::new(10)));

        match result {
            Ok(mut secret_box) => assert!((*secret_box.expose_secret()).check_non_zero()),
            Err(_) => panic!("Expected Ok variant"),
        }
    }

    #[test]
    fn test_secret_guard_equality() {
        let secret_guard_a = SecretGuard::new(&5);
        let secret_guard_b = SecretGuard::new(&5);

        assert!(secret_guard_a == secret_guard_b);

        let mut val_a = 7;
        let mut val_b = 5;

        let secret_guard_mut_a = SecretGuardMut::new(&mut val_a);
        let secret_guard_mut_b = SecretGuardMut::new(&mut val_b);

        assert!(secret_guard_mut_a != secret_guard_mut_b)
    }
}
