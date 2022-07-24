#![no_main]
use weak_alloc::WeakAlloc;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::mem;
use std::ptr;
use std::sync::Mutex;

// Fuzzing target inspired by
// https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html#example-2-fuzzing-allocator-api-calls
#[derive(Arbitrary, Debug)]
enum AllocatorMethod {
    Malloc {
        // The size of allocation to make.
        size: usize,
        align_log2: u8,
    },
    Free {
        // Free the index^th allocation we've made.
        index: usize,
    },
}

struct FakeAlloc {
    inner: Mutex<LinkedListAllocator>,
}

// LinkedListAllocator code from
// https://os.phil-opp.com/allocator-designs/
// Modified a bit so that memory is never actually allocated
/// Linked list allocator used for testing. It does not actually allocate any memory, it just
/// returns the memory address.
struct LinkedListAllocator {
    head: ListNode,
}

struct ListNode {
    start: usize,
    size: usize,
    next: Option<Box<ListNode>>,
}

impl ListNode {
    fn new(start: usize, size: usize) -> Self {
        ListNode {
            start,
            size,
            next: None,
        }
    }

    fn start_addr(&self) -> usize {
        self.start
    }

    fn end_addr(&self) -> usize {
        self.start_addr() + self.size
    }
}

impl LinkedListAllocator {
    /// Creates an empty LinkedListAllocator.
    pub fn new() -> Self {
        Self {
            head: ListNode::new(0, 0),
        }
    }

    /// Initialize the allocator with the given heap bounds.
    ///
    /// This function is unsafe because the caller must guarantee that the given
    /// heap bounds are valid and that the heap is unused. This method must be
    /// called only once.
    pub unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        self.add_free_region(heap_start, heap_size);
    }

    /// Adds the given memory region to the front of the list.
    unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        // ensure that the freed region is capable of holding ListNode
        assert_eq!(align_up(addr, mem::align_of::<ListNode>()), addr);
        assert!(size >= mem::size_of::<ListNode>());

        // create a new list node and append it at the start of the list
        let mut node = ListNode::new(addr, size);
        node.next = self.head.next.take();
        self.head.next = Some(Box::new(node));
    }

    /// Looks for a free region with the given size and alignment and removes
    /// it from the list.
    ///
    /// Returns a tuple of the list node and the start address of the allocation.
    fn find_region(&mut self, size: usize, align: usize) -> Option<(Box<ListNode>, usize)> {
        // reference to current list node, updated for each iteration
        let mut current = &mut self.head;
        // look for a large enough memory region in linked list
        while let Some(ref mut region) = current.next {
            if let Ok(alloc_start) = Self::alloc_from_region(region, size, align) {
                // region suitable for allocation -> remove node from list
                let next = region.next.take();
                let ret = Some((current.next.take().unwrap(), alloc_start));
                current.next = next;
                return ret;
            } else {
                // region not suitable -> continue with next region
                current = current.next.as_mut().unwrap();
            }
        }

        // no suitable region found
        None
    }

    /// Try to use the given region for an allocation with given size and
    /// alignment.
    ///
    /// Returns the allocation start address on success.
    fn alloc_from_region(region: &ListNode, size: usize, align: usize) -> Result<usize, ()> {
        let alloc_start = align_up(region.start_addr(), align);
        let alloc_end = alloc_start.checked_add(size).ok_or(())?;

        if alloc_end > region.end_addr() {
            // region too small
            return Err(());
        }

        let excess_size = region.end_addr() - alloc_end;
        if excess_size > 0 && excess_size < mem::size_of::<ListNode>() {
            // rest of region too small to hold a ListNode (required because the
            // allocation splits the region in a used and a free part)
            return Err(());
        }

        // region suitable for allocation
        Ok(alloc_start)
    }

    /// Adjust the given layout so that the resulting allocated memory
    /// region is also capable of storing a `ListNode`.
    ///
    /// Returns the adjusted size and alignment as a (size, align) tuple.
    fn size_align(layout: Layout) -> (usize, usize) {
        let layout = layout
            .align_to(mem::align_of::<ListNode>())
            .expect("adjusting alignment failed")
            .pad_to_align();
        let size = layout.size().max(mem::size_of::<ListNode>());
        (size, layout.align())
    }
}

/// Align the given address `addr` upwards to alignment `align`.
fn align_up(addr: usize, align: usize) -> usize {
    let remainder = addr % align;
    if remainder == 0 {
        addr // addr already aligned
    } else {
        addr - remainder + align
    }
}

unsafe impl GlobalAlloc for FakeAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // perform layout adjustments
        let (size, align) = LinkedListAllocator::size_align(layout);
        let mut allocator = self.inner.lock().unwrap();

        if let Some((region, alloc_start)) = allocator.find_region(size, align) {
            let alloc_end = alloc_start.checked_add(size).expect("overflow");
            let excess_size = region.end_addr() - alloc_end;
            if excess_size > 0 {
                allocator.add_free_region(alloc_end, excess_size);
            }
            alloc_start as *mut u8
        } else {
            ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // perform layout adjustments
        let (size, _) = LinkedListAllocator::size_align(layout);

        self.inner
            .lock()
            .unwrap()
            .add_free_region(ptr as usize, size)
    }
}

fuzz_target!(|methods: Vec<AllocatorMethod>| {
    let mut a = LinkedListAllocator::new();
    // Initialize 4GB heap in address range 0-4G
    unsafe { a.init(0, u32::MAX as usize + 1) };
    let a = FakeAlloc {
        inner: Mutex::new(a),
    };
    let a = WeakAlloc::new(a);
    let mut allocs = vec![];
    let mut total_size_so_far: u64 = 0;
    // Only allow to allocate up to 100GB
    let size_limit = 100_000_000_000;
    // Max size of one allocation is 100GB
    let max_size = 100_000_000_000;

    // Interpret the fuzzer-provided methods and make the
    // corresponding allocator API calls.
    for method in methods {
        match method {
            AllocatorMethod::Malloc { size, align_log2 } => {
                if size == 0 {
                    continue;
                }
                if size >= max_size {
                    continue;
                }
                if align_log2 >= 64 {
                    continue;
                }
                if total_size_so_far > size_limit {
                    continue;
                }
                let layout = Layout::from_size_align(size, 1 << align_log2);
                if layout.is_err() {
                    continue;
                }
                let layout = layout.unwrap();
                let ptr = unsafe { a.alloc(layout) };
                allocs.push((ptr, layout));
                total_size_so_far += size as u64;
            }
            AllocatorMethod::Free { index } => match allocs.get(index) {
                Some((ptr, layout)) if !ptr.is_null() => {
                    total_size_so_far -= layout.size() as u64;
                    unsafe { a.dealloc(*ptr, *layout) };
                    allocs[index].0 = std::ptr::null_mut();
                }
                _ => {}
            },
        }
        //println!("{:?}", allocs);
    }

    // Free any remaining allocations.
    for (ptr, layout) in allocs {
        if !ptr.is_null() {
            unsafe { a.dealloc(ptr, layout) };
        }
    }
});
