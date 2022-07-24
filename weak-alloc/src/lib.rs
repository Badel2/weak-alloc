use once_cell::sync::Lazy;
use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt;
use std::fmt::Write;
use std::ops::Deref;
use std::sync::Mutex;
use weak_list::AllocHashSet;
use weak_list::AllocMem;
use weak_list::WeakList;
use weak_list::WeakListHashSet;

// TODO: interesting crates:
// https://crates.io/crates/refbox
// https://crates.io/crates/weak-table
// https://crates.io/crates/provenant
// https://crates.io/crates/rcgc
// https://crates.io/crates/weak_list

// Missing API:
// * Manual or automatic garbage collection in case the Weak pointer is dropped
// * Weak<T> will keep memory allocated for T even after dropping T, we must use Weak<Box<T>>

/// A custom allocator that can be given ownership of data, returning a `WeakRef`.
#[derive(Clone)]
pub struct WeakAlloc<A> {
    alloc: A,
}

/// List of values owned by the allocator
static WEAK_LIST: Lazy<Mutex<WeakList<WeakListHashSet>>> =
    Lazy::new(|| Mutex::new(WeakList::new()));
// HashSet used as part of a manual realloc API, because the allocator cannot allocate memory while
// the WEAK_LIST lock is held.
static BIGGER_HASHSET: Lazy<Mutex<AllocHashSet>> =
    Lazy::new(|| Mutex::new(AllocHashSet::with_capacity(1)));

impl<A> WeakAlloc<A> {
    pub const fn new(alloc: A) -> Self {
        Self { alloc }
    }
}

pub struct WeakRef<T: ?Sized, A: 'static + Clone + GlobalAlloc = System> {
    weak: weak_list::WeakRef<T>,
    alloc: WeakAlloc<A>,
}

impl<T, A: GlobalAlloc + Clone> Clone for WeakRef<T, A> {
    fn clone(&self) -> Self {
        Self {
            weak: self.weak.clone(),
            alloc: self.alloc.clone(),
        }
    }
}

impl<T: ?Sized + fmt::Debug, A: 'static + Clone + GlobalAlloc> fmt::Debug for WeakRef<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(Weak)")
    }
}

impl<T: Send + Sync + 'static, A: 'static + Clone + GlobalAlloc> WeakRef<T, A> {
    pub fn upgrade(&self) -> Option<ArcRef<T, A>> {
        self.alloc.upgrade(self)
    }
}

pub struct ArcRef<T: ?Sized, A: 'static + Clone + GlobalAlloc = System> {
    arc: weak_list::ArcRef<T>,
    alloc: WeakAlloc<A>,
}

impl<T, A: GlobalAlloc + Clone> Clone for ArcRef<T, A> {
    fn clone(&self) -> Self {
        Self {
            arc: self.arc.clone(),
            alloc: self.alloc.clone(),
        }
    }
}

impl<T: ?Sized, A: GlobalAlloc + Clone> AsRef<T> for ArcRef<T, A> {
    fn as_ref(&self) -> &T {
        &**self
    }
}

impl<T: ?Sized, A: GlobalAlloc + Clone> Deref for ArcRef<T, A> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.arc
    }
}

impl<T, A: GlobalAlloc + Clone> ArcRef<T, A> {
    pub fn get_mut(this: &mut Self) -> Option<&mut T> {
        weak_list::ArcRef::get_mut(&mut this.arc)
    }

    pub fn downgrade(this: &Self) -> WeakRef<T, A> {
        WeakRef {
            weak: weak_list::ArcRef::downgrade(&this.arc),
            alloc: this.alloc.clone(),
        }
    }
}

impl<A> WeakAlloc<A>
where
    A: GlobalAlloc + Clone,
{
    /// Give ownership of a value to the allocator. The value may be deallocated at any time if no
    /// other strong references to it exist.
    ///
    /// Returns a WeakRef that can be used to get back an Arc in the future using the upgrade
    /// method, if the value still exists.
    ///
    /// Because of the way Arc is implemented, prefer giving T where the size of T is small.
    /// Otherwise the backing allocation will not be deallocated when dropping the Arc, it will
    /// only be deallocated after all the weak references go out of scope. So [u8; 1000] is
    /// bad, but Box<[u8; 1000]> and Vec<[u8; 1000]> are good.
    pub fn give<T: Send + Sync + 'static>(&self, element: T) -> WeakRef<T, A> {
        let alloc_mem = AllocMem::default();
        let mut big_hs = BIGGER_HASHSET.lock().unwrap();
        let big_hs_cap = big_hs.capacity();
        let big_hs_opt = Some(&mut *big_hs);
        let mut lock = WEAK_LIST.lock().unwrap();
        // Before pushing node to hashset, ensure the hashset has enough free memory
        lock.realloc_hashset_if_needed_no_alloc(big_hs_opt);
        let weak = lock.push_front_no_alloc(element, alloc_mem);
        drop(lock);
        let new_hs_cap = big_hs.capacity();

        if new_hs_cap < big_hs_cap {
            // Allocate more memory
            big_hs.allocate_capacity(big_hs_cap * 2);
        }

        WeakRef {
            weak,
            alloc: self.clone(),
        }
    }

    // TODO: instead of give and give_and_upgrade, make give always return an ArcRef and document
    // give(x).downgrade() as the way to get a WeakRef?
    /// Alternative to `A.give(x).upgrade().unwrap()` that never fails. There is a race condition
    /// in that snippet if another thread fills the memory causing the allocator to call
    /// `WEAK_LIST.pop_lru()` after the call to `give` but before the call to `upgrade`.
    /// That race condition is avoided in this method by holding the lock slightly longer, so that
    /// no other thread can modify the list before we upgrade to an ArcRef.
    pub fn give_and_upgrade<T: Send + Sync + 'static>(&self, element: T) -> ArcRef<T, A> {
        let alloc_mem = AllocMem::default();
        let mut big_hs = BIGGER_HASHSET.lock().unwrap();
        let big_hs_cap = big_hs.capacity();
        let big_hs_opt = Some(&mut *big_hs);
        let mut lock = WEAK_LIST.lock().unwrap();
        // Before pushing node to hashset, ensure the hashset has enough free memory
        lock.realloc_hashset_if_needed_no_alloc(big_hs_opt);
        let weak = lock.push_front_no_alloc(element, alloc_mem);
        // upgrade cannot fail because we hold a &mut WeakList, and we just pushed this item there.
        // upgrade_quietly to avoid moving the element to the front of the list, because it already
        // is at the front since the call to push_front_no_alloc.
        let arc = weak.upgrade_quietly().unwrap();
        drop(lock);
        let new_hs_cap = big_hs.capacity();

        if new_hs_cap < big_hs_cap {
            // Allocate more memory
            big_hs.allocate_capacity(big_hs_cap * 2);
        }

        ArcRef {
            arc,
            alloc: self.clone(),
        }
    }

    pub fn upgrade<T: Send + Sync + 'static>(&self, w: &WeakRef<T, A>) -> Option<ArcRef<T, A>> {
        let mut wl = WEAK_LIST.lock().unwrap();

        w.weak.upgrade(&mut wl).map(|arc| ArcRef {
            arc,
            alloc: self.clone(),
        })
    }

    /// Remove all the weak references from the WeakAlloc. This will deallocate all the WeakRefs
    /// that do not have an active ArcRef.
    pub fn clear(&self) {
        let mut wl = WEAK_LIST.lock().unwrap();

        wl.clear();
    }

    /// Try to allocate some memory without freeing any existing weak allocations. This can be used
    /// to implement the equivalent to `try_give`: try to allocate a box with some contents but
    /// only if there is enough memory. If there isn't enough memory this method will return a null
    /// pointer and the code needed to initialize the box can be skipped (using `give` forces you
    /// to initialize the value).
    ///
    /// # Safety
    ///
    /// The same restrictions as `GlobalAlloc::alloc`.
    pub unsafe fn weak_alloc(&self, layout: Layout) -> *mut u8 {
        self.alloc.alloc(layout)
    }

    /// Returns a reference to the inner allocator.
    pub fn inner(&self) -> &A {
        &self.alloc
    }
}

unsafe impl<A> GlobalAlloc for WeakAlloc<A>
where
    A: GlobalAlloc,
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut ret = self.alloc.alloc(layout);
        loop {
            if !ret.is_null() {
                break;
            }

            // Malloc returned null pointer!

            // Mitigation in case the inner alloc returns a null pointers even though it has enough
            // memory (bad align parameter?). Since this does not seem to be needed, it is
            // commented out for now.
            /*
            // Before trying to free any weak allocations, try to allocate the same amount of
            // memory using alignment of 1, to ensure that the null pointer is because of lack of
            // memory and not because of an invalid alignment.
            let align_1_layout = Layout::from_size_align(layout.size(), 1).unwrap();
            let ptr_align_1 = self.alloc.alloc(align_1_layout);
            if !ptr_align_1.is_null() {
                // The returned pointer was not null. There are two possibilities:
                // * The layout was indeed invalid
                // * The system did not have enough memory at t0 but now it has enough memory at
                // t1. In this case the expected behaviour would be to try to free a weak
                // reference, because when the layout is valid we only want to return a null
                // pointer after removing all the other weak allocations.
                self.alloc.dealloc(ptr_align_1, align_1_layout);
                // Return null pointer
                return ret;
            }
            */

            //log::error!("malloc returned null pointer");
            // Free some weak allocation and try again
            //WEAK_LIST.lock().unwrap().remove_all_unreachable();
            let some_arc = WEAK_LIST.lock().unwrap().pop_lru();
            if let Some(arc) = some_arc {
                drop(arc);
            } else {
                // No more weak allocations to free, give up and return null pointer
                // TODO: what if the inner alloc always returns a null pointer because of a wrong
                // layout? We would delete all the weak allocations by mistake.
                // Instrument layout to detect faulty layouts.
                instrument::increase_null_ptr_layout_counter(layout);
                return ret;
            }

            ret = self.alloc.alloc(layout);
        }

        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.alloc.dealloc(ptr, layout);
    }
}

/// Instrument failed allocations to detect applications that call malloc with an invalid argument.
/// This is important because such calls to malloc will empty the WeakList (because the condition
/// is to remove elements until malloc returns not null, and in that case malloc will always return
/// null).
pub mod instrument {
    use super::*;

    /// Histogram of `Layout`s that failed to allocate using the inner allocator.
    struct SmallHist {
        v: Vec<(Layout, u32)>,
        other: u32,
    }

    const NUM_NULL_PTR_LAYOUT: usize = 4;
    static NULL_PTR_LAYOUT_COUNTER: Lazy<Mutex<SmallHist>> = Lazy::new(|| {
        Mutex::new(SmallHist {
            v: Vec::with_capacity(NUM_NULL_PTR_LAYOUT),
            other: 0,
        })
    });

    pub fn increase_null_ptr_layout_counter(layout: Layout) {
        let mut guard = NULL_PTR_LAYOUT_COUNTER.lock().unwrap();
        let v = &mut guard.v;

        let mut found = false;

        // Increment layout counter if present.
        for (l, ctr) in v.iter_mut() {
            if *l == layout {
                *ctr += 1;
                found = true;
                break;
            }
        }

        // If the layout is not present yet, add it to the histogram with count=1.
        // Unless the histogram is full, then add 1 to the "other" counter.
        if !found {
            if v.len() == NUM_NULL_PTR_LAYOUT {
                let other = &mut guard.other;
                *other += 1;
            } else {
                v.push((layout, 1));
            }
        }
    }

    pub fn dump_null_ptr_layout_counters() -> String {
        let guard = NULL_PTR_LAYOUT_COUNTER.lock().unwrap();

        if guard.v.is_empty() {
            // Fast path: return empty string
            return String::new();
        }

        // Need to drop guard to be able to allocate memory
        drop(guard);

        // Create a string with enough capacity to ensure that we do not allocate while the guard
        // is held.
        let mut buf = String::with_capacity(1024);
        write!(
            buf,
            "Warn: the following layouts caused allocator to return null pointer: "
        )
        .unwrap();
        let guard = NULL_PTR_LAYOUT_COUNTER.lock().unwrap();

        writeln!(buf, "null_ptr layouts: {:?}", guard.v).unwrap();
        if guard.other != 0 {
            writeln!(buf, "number of other null_ptrs: {}", guard.other).unwrap();
        }

        drop(guard);

        buf
    }
}
