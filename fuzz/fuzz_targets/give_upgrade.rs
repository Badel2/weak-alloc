#![no_main]
use weak_alloc::WeakAlloc;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use limit_alloc::ConstLimit;
use std::alloc::System;
use std::collections::VecDeque;

// Fuzzing target inspired by
// https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html#example-2-fuzzing-allocator-api-calls
#[derive(Arbitrary, Debug)]
enum AllocatorMethod {
    Give {
        // The size of allocation to make.
        size: usize,
    },
    Upgrade,
    CloneArc,
    DropArc,
    RotateArc,
    CloneWeak,
    DropWeak,
    RotateWeak,
    // Remove all elements from allocator
    Clear,
}

#[global_allocator]
static A: WeakAlloc<ConstLimit<System, 200_000>> = WeakAlloc::new(ConstLimit::new(System));

fuzz_target!(|fuzz_data: (Option<usize>, Vec<AllocatorMethod>)| {
    A.clear();
    let (prefill, methods) = fuzz_data;
    let mut weaks = VecDeque::new();
    let mut upgrades = VecDeque::new();
    let mut total_size_so_far: u64 = 0;
    /*
    // Max size of one allocation is 8KB
    let max_size = 8 * 1024;
    // Max total size is 16*max_size = 128KB
    let max_total_size = 16 * max_size;
    */
    let max_size = 8 * 1024;
    let max_total_size = 1_000_000_000;

    // Prefill allocator with weak allocations
    // This is very useful to detect deadlocks when the allocator tries to allocate something,
    // unfortunately the fuzzer does not detect deadlocks as a timeout because the process never
    // finishes.
    let mut prefilled_weaks = vec![];
    // 200K
    if let Some(size) = prefill {
        if size != 0 && size > 1 {
            let size = std::cmp::min(size, 100_000);
            let pieces = 200_000 / size;
            // More than 5000 pieces, the overhead will be greater than 200_000, so the memory will
            // be full because of the weakrefs alone
            let pieces = std::cmp::min(pieces, 100);

            for _ in 0..pieces {
                prefilled_weaks.push(A.give(Vec::<u8>::with_capacity(size)));
            }
        }
    }

    //let uninit_size = max_size * 3 / 2;
    //let mut uninit_vec: Vec<u8> = Vec::with_capacity(uninit_size);

    //println!("{:?}", methods);

    // Interpret the fuzzer-provided methods and make the
    // corresponding allocator API calls.
    for method in methods {
        //println!("Remaining bytes in Limit: {}", ConstLimit::<_, 200_000>::new(System).remaining());
        match method {
            AllocatorMethod::Give { size } => {
                if size >= max_size {
                    continue;
                }
                if total_size_so_far >= max_total_size as u64 {
                    continue;
                }
                total_size_so_far += size as u64;
                let v: Vec<u8> = Vec::with_capacity(size);
                weaks.push_back(A.give(v));
            }
            AllocatorMethod::Upgrade => {
                if let Some(x) = weaks.iter().next_back() {
                    upgrades.push_back(x.upgrade());
                }
            }
            AllocatorMethod::CloneArc => {
                if let Some(Some(x)) = upgrades.iter().next_back() {
                    upgrades.push_back(Some(x.clone()));
                }
            }
            AllocatorMethod::DropArc => {
                upgrades.pop_back();
            }
            AllocatorMethod::RotateArc => {
                if !upgrades.is_empty() {
                    upgrades.rotate_right(1);
                }
            }
            AllocatorMethod::CloneWeak => {
                if let Some(x) = weaks.iter().next_back() {
                    weaks.push_back(x.clone());
                }
            }
            AllocatorMethod::DropWeak => {
                weaks.pop_back();
            }
            AllocatorMethod::RotateWeak => {
                if !weaks.is_empty() {
                    weaks.rotate_right(1);
                }
            }
            AllocatorMethod::Clear => {
                A.clear();
            }
        }
    }

    //let sentinel2 = b'B';
    //uninit_vec.resize(uninit_size, sentinel2);

    print!("{}", weak_alloc::instrument::dump_null_ptr_layout_counters());
});
