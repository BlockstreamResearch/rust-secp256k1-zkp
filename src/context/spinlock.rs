// SPDX-License-Identifier: CC0-1.0

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::context::internal::SelfContainedContext;

const MAX_SPINLOCK_ATTEMPTS: usize = 128;

// Some embedded targets have atomic loads and stores but no atomic compare-and-swap,
// so there is no way to claim the lock. On those targets `try_lock` always fails
// and callers take the fallback contention path described below.
const HAVE_ATOMIC_CAS: bool = cfg!(target_has_atomic = "8");

// Best-Effort Spinlock
//
// To obtain exclusive access, call [`Self::try_lock`], which will spinlock
// for some small number of iterations before giving up. By trying again in
// a loop, you can emulate a "true" spinlock that will only yield once it
// has access. However, this would be very dangerous, especially in a nostd
// environment, because if we are pre-empted by an interrupt handler while
// the lock is held, and that interrupt handler attempts to take the lock,
// then we deadlock.
//
// Instead, the strategy we take within this module is to simply create a
// new stack-local context object if we are unable to obtain a lock on the
// global one. This is slow and loses the defense-in-depth "rerandomization"
// anti-sidechannel measure, but it is better than deadlocking..
pub struct SpinLock<T> {
    flag: AtomicBool,
    // Invariant: if this is non-None, then the store is valid and can be
    // used with `ffi::secp256k1_context_preallocated_create`.
    data: UnsafeCell<T>,
}

// Required by rustc if we have a static of this type.
// Safety: `data` is accessed only while the `flag` is held.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl SpinLock<SelfContainedContext> {
    pub const fn new() -> Self {
        Self {
            flag: AtomicBool::new(false),
            data: UnsafeCell::new(SelfContainedContext::new_uninitialized()),
        }
    }
}

impl Default for SpinLock<SelfContainedContext> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl SpinLock<u64> {
    pub const fn new(v: u64) -> Self {
        Self {
            flag: AtomicBool::new(false),
            data: UnsafeCell::new(v),
        }
    }
}

impl<T> SpinLock<T> {
    /// Blocks until the lock is acquired, then returns an RAII guard.
    ///
    /// Will spin up to a fixed number of iterations (currently 128); if the
    /// guard is not acquired in that time, return `None`.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        if !HAVE_ATOMIC_CAS {
            return None;
        }

        for _ in 0..MAX_SPINLOCK_ATTEMPTS {
            if self.compare_exchange_flag() {
                return Some(SpinLockGuard {
                    lock: self,
                    _marker: PhantomData,
                });
            }
            spin_loop();
        }
        None
    }

    /// Attempts to claim the lock, returning whether it succeeded.
    ///
    /// Always fails if the target lacks atomic compare-and-swap; see
    /// [`HAVE_ATOMIC_CAS`], which callers should check first.
    #[inline(always)]
    fn compare_exchange_flag(&self) -> bool {
        #[cfg(target_has_atomic = "8")]
        {
            self.flag
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        }
        #[cfg(not(target_has_atomic = "8"))]
        {
            false
        }
    }

    /// Unlocks the data held by the spinlock.
    ///
    /// # Safety
    ///
    /// Once this method is called, no access to the data within the spinlock
    /// should be possible.
    ///
    /// (This method is private so we can enforce this safety condition here.)
    #[inline(always)]
    unsafe fn unlock(&self) {
        self.flag.store(false, Ordering::Release);
    }
}

/// Drops the lock when it goes out of scope.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    _marker: PhantomData<&'a mut T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // SAFETY: we hold the lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: mutable access is unique while the guard lives.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: access to the data within the spinlock is only possible through
        // the `SpinLockGuard` which is being destructed.
        unsafe {
            self.lock.unlock();
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;

    const SPINLOCK_TEST_VAL: u64 = 100;

    macro_rules! assert_not_impl {
        ($type:ty: $trait:path) => {
            const _: fn() = || {
                struct Invalid;
                trait AmbiguousIfImpl<A> {
                    fn marker() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                impl<T: ?Sized + $trait> AmbiguousIfImpl<Invalid> for T {}

                let _ = <$type as AmbiguousIfImpl<_>>::marker;
            };
        };
    }

    // A guard exposes `&T` through `Deref`, so it must only be `Sync` when
    // `T` itself is `Sync`.
    assert_not_impl!(SpinLockGuard<'static, Cell<u64>>: Sync);

    #[test]
    fn basic_lock_unlock() {
        let spinlock = SpinLock::<u64>::new(SPINLOCK_TEST_VAL);

        let guard = spinlock.try_lock().expect("Should be able to acquire lock");
        assert_eq!(*guard, SPINLOCK_TEST_VAL);
        drop(guard);

        let guard2 = spinlock
            .try_lock()
            .expect("Should be able to reacquire lock");
        assert_eq!(*guard2, SPINLOCK_TEST_VAL);
    }

    #[test]
    fn modify_data() {
        let spinlock = SpinLock::<u64>::new(SPINLOCK_TEST_VAL);

        {
            let mut guard = spinlock.try_lock().expect("Should be able to acquire lock");
            *guard = 42;
        }

        let guard = spinlock
            .try_lock()
            .expect("Should be able to reacquire lock");
        assert_eq!(*guard, 42);
    }

    #[test]
    fn contention_single_thread() {
        let spinlock = SpinLock::<u64>::new(SPINLOCK_TEST_VAL);

        let _guard1 = spinlock.try_lock().expect("Should be able to acquire lock");
        let result = spinlock.try_lock();
        assert!(result.is_none(), "Should not be able to acquire lock twice");
    }

    #[test]
    fn guard_deref() {
        let spinlock = SpinLock::<u64>::new(SPINLOCK_TEST_VAL);
        let guard = spinlock.try_lock().expect("Should be able to acquire lock");

        // Test Deref
        assert_eq!(*guard, SPINLOCK_TEST_VAL);

        // Test que nous pouvons utiliser les méthodes de u64
        let value: u64 = *guard;
        assert_eq!(value, SPINLOCK_TEST_VAL);
    }

    #[test]
    fn guard_deref_mut() {
        let spinlock = SpinLock::<u64>::new(SPINLOCK_TEST_VAL);
        let mut guard = spinlock.try_lock().expect("Should be able to acquire lock");

        // Test DerefMut
        *guard += 50;
        assert_eq!(*guard, 150);

        // Modifier via une méthode qui prend &mut self
        *guard = guard.wrapping_add(10);
        assert_eq!(*guard, 160);
    }
}

#[cfg(all(test, feature = "std"))]
mod std_tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use super::*;

    const SPINLOCK_TEST_VAL: u64 = 100;

    #[test]
    fn multiple_threads_no_contention() {
        let spinlock = Arc::new(SpinLock::<u64>::new(SPINLOCK_TEST_VAL));
        let mut handles = vec![];

        for i in 1..=3 {
            let spinlock_clone = Arc::clone(&spinlock);
            let handle = thread::spawn(move || {
                let mut guard = spinlock_clone.try_lock().expect("Should acquire lock");
                let old_value = *guard;
                *guard = old_value + i;
                // (drop guard)
            });
            handles.push(handle);

            // Sleep between spawning threads. In practice this does not seem to be
            // necessary, at least on Andrew's system.
            thread::sleep(Duration::from_millis(10));
        }

        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let guard = spinlock.try_lock().expect("Should be able to acquire lock");
        assert_eq!(*guard, 106);
    }

    #[test]
    fn multiple_threads_contention() {
        let spinlock = Arc::new(SpinLock::<u64>::new(SPINLOCK_TEST_VAL));
        let mut handles = vec![];

        for i in 1..=3 {
            let spinlock_clone = Arc::clone(&spinlock);
            let handle = thread::spawn(move || {
                loop {
                    if let Some(mut guard) = spinlock_clone.try_lock() {
                        let old_value = *guard;
                        *guard = old_value + i;
                        // Sleep while holding lock.
                        thread::sleep(Duration::from_millis(10));
                        break;
                    }
                    //panic!("uncomment me to check that sometimes contention happens");
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let guard = spinlock.try_lock().expect("Should be able to acquire lock");
        assert_eq!(*guard, 106);
    }
}
