#![no_main]
use weak_alloc::WeakAlloc;
use weak_alloc::WeakRef;
use weak_alloc::ArcRef;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::ptr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;

// Fuzzing target inspired by
// https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html#example-2-fuzzing-allocator-api-calls
#[derive(Arbitrary, Debug)]
enum AllocatorMethod {
    Give {
        // The size of allocation to make.
        size: usize,
        //initialize: bool,
    },
    Upgrade {
        // Upgrade WeakRef to ArcRef of the index^th allocation we've made.
        index: usize,
    },
    CloneArc {
        // Clone ArcRef of the index^th allocation we've made.
        index: usize,
    },
    DropArc {
        // Drop ArcRef of the index^th allocation we've made.
        index: usize,
    },
    CloneWeak {
        // Clone WeakRef of the index^th allocation we've made.
        index: usize,
    },
    DropWeak {
        // Drop WeakRef of the index^th allocation we've made.
        index: usize,
    },
    // Remove all elements from allocator
    Clear,
    // Send next command to the next thread
    NextThread,
    SendArcToMainThread {
        index: usize,
    },
    SendWeakToMainThread {
        index: usize,
    },
    SendArcToThread,
    SendWeakToThread,
    // Synchronize all threads: any commands before this one must complete before any commands
    // after this one
    // TODO: this is useless because the minimizer can remove it and the code may still reproduce
    // the crash
    //Fence,
}

enum Msg {
    Cmd(AllocatorMethod),
    Arc(ArcRef<Vec<u8>, Limit<System>>),
    Weak(WeakRef<Vec<u8>, Limit<System>>),
}

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
struct Limit<A> {
    limit: usize,
    alloc: A,
}

impl<A> Limit<A> {
    const fn new(limit: usize, alloc: A) -> Self {
        Self { limit, alloc }
    }
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for Limit<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match ALLOCATED.fetch_update(SeqCst, SeqCst, |old| {
            let new = old.checked_add(layout.size())?;
            if new > self.limit {
                None
            } else {
                Some(new)
            }
        }) {
            Ok(_size) => {}
            Err(_e) => return ptr::null_mut(),
        }
        let ret = self.alloc.alloc(layout);
        if ret.is_null() {
            // Nothing was actually allocated, so subtract the size
            ALLOCATED.fetch_sub(layout.size(), SeqCst);
        }

        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.alloc.dealloc(ptr, layout);
        ALLOCATED.fetch_sub(layout.size(), SeqCst);
    }
}

#[global_allocator]
static A: WeakAlloc<Limit<System>> = WeakAlloc::new(Limit::new(400_000, System));

fuzz_target!(|methods: Vec<AllocatorMethod>| {
    A.clear();
    // Max size of one allocation is 8KB
    let max_size = 8 * 1024;
    // Max total size is 16*max_size = 128KB
    let max_total_size = 1_000_000_000;

    //let uninit_size = max_size * 3 / 2;
    //let mut uninit_vec: Vec<u8> = Vec::with_capacity(uninit_size);

    // Prefill allocator with weak allocations
    // This is very useful to detect deadlocks when the allocator tries to allocate something,
    // unfortunately the fuzzer does not detect this as a timeout because the process never
    // finishes.
    let mut prefilled_weaks = vec![];
    // 400K
    for _ in 0..400 {
        prefilled_weaks.push(A.give(Vec::<u8>::with_capacity(1000)));
    }

    let (tx1, rx) = std::sync::mpsc::sync_channel(1000);
    let (main, rx1) = std::sync::mpsc::sync_channel(1000);
    //println!("{:?}", methods);
    let t1 = std::thread::spawn(move || {
        let mut weaks = vec![];
        let mut upgrades = vec![];
        let mut total_size_so_far: u64 = 0;

        while let Ok(msg) = rx.recv() {
            match msg {
                Msg::Arc(a) => upgrades.push(Some(a)),
                Msg::Weak(w) => weaks.push(Some(w)),
                Msg::Cmd(method) => 
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
                    /*
                    if initialize {
                        let sentinel = b'A';
                        v.resize(size, sentinel);
                    }
                    */
                    weaks.push(Some(A.give(v)));
                }
                AllocatorMethod::Upgrade { index } => {
                    if let Some(Some(x)) = weaks.get(index) {
                        upgrades.push(x.upgrade());
                    }
                }
                AllocatorMethod::CloneArc { index } => {
                    if let Some(Some(x)) = upgrades.get(index) {
                        upgrades.push(Some(x.clone()));
                    }
                }
                AllocatorMethod::DropArc { index } => {
                    if let Some(x) = upgrades.get_mut(index) {
                        *x = None;
                    }
                }
                AllocatorMethod::CloneWeak { index } => {
                    if let Some(Some(x)) = weaks.get(index) {
                        weaks.push(Some(x.clone()));
                    }
                }
                AllocatorMethod::DropWeak { index } => {
                    if let Some(x) = weaks.get_mut(index) {
                        *x = None;
                    }
                }
                AllocatorMethod::Clear => {
                    A.clear();
                }
                AllocatorMethod::SendArcToMainThread { index } => {
                    if let Some(x) = upgrades.get_mut(index) {
                        if let Some(x) = x.take() {
                            main.send(Msg::Arc(x)).unwrap();
                        }
                    }
                }
                AllocatorMethod::SendWeakToMainThread { index } => {
                    if let Some(x) = weaks.get_mut(index) {
                        if let Some(x) = x.take() {
                            main.send(Msg::Weak(x)).unwrap();
                        }
                    }
                }
                AllocatorMethod::NextThread | AllocatorMethod::SendArcToThread | AllocatorMethod::SendWeakToThread => {
                    unreachable!();
                }
            }
            }
        }
    });
    let (tx2, rx) = std::sync::mpsc::sync_channel(1000);
    let (main, rx2) = std::sync::mpsc::sync_channel(1000);
    let t2 = std::thread::spawn(move || {
        let mut weaks = vec![];
        let mut upgrades = vec![];
        let mut total_size_so_far: u64 = 0;

        while let Ok(msg) = rx.recv() {
            match msg {
                Msg::Arc(a) => upgrades.push(Some(a)),
                Msg::Weak(w) => weaks.push(Some(w)),
                Msg::Cmd(method) => 
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
                    /*
                    if initialize {
                        let sentinel = b'A';
                        v.resize(size, sentinel);
                    }
                    */
                    weaks.push(Some(A.give(v)));
                }
                AllocatorMethod::Upgrade { index } => {
                    if let Some(Some(x)) = weaks.get(index) {
                        upgrades.push(x.upgrade());
                    }
                }
                AllocatorMethod::CloneArc { index } => {
                    if let Some(Some(x)) = upgrades.get(index) {
                        upgrades.push(Some(x.clone()));
                    }
                }
                AllocatorMethod::DropArc { index } => {
                    if let Some(x) = upgrades.get_mut(index) {
                        *x = None;
                    }
                }
                AllocatorMethod::CloneWeak { index } => {
                    if let Some(Some(x)) = weaks.get(index) {
                        weaks.push(Some(x.clone()));
                    }
                }
                AllocatorMethod::DropWeak { index } => {
                    if let Some(x) = weaks.get_mut(index) {
                        *x = None;
                    }
                }
                AllocatorMethod::Clear => {
                    A.clear();
                }
                AllocatorMethod::SendArcToMainThread { index } => {
                    if let Some(x) = upgrades.get_mut(index) {
                        if let Some(x) = x.take() {
                            main.send(Msg::Arc(x)).unwrap();
                        }
                    }
                }
                AllocatorMethod::SendWeakToMainThread { index } => {
                    if let Some(x) = weaks.get_mut(index) {
                        if let Some(x) = x.take() {
                            main.send(Msg::Weak(x)).unwrap();
                        }
                    }
                }
                AllocatorMethod::NextThread | AllocatorMethod::SendArcToThread | AllocatorMethod::SendWeakToThread => {
                    unreachable!();
                }
            }
            }
        }
    });

    // Interpret the fuzzer-provided methods and make the
    // corresponding allocator API calls.
    let mut weaks = vec![];
    let mut upgrades = vec![];
    let mut current = 1;
    for method in methods {
        //println!("Remaining bytes in Limit: {}", ALLOCATED.load(SeqCst));
        if let Ok(msg) = rx1.try_recv() {
            match msg {
                Msg::Arc(a) => upgrades.push(a),
                Msg::Weak(w) => weaks.push(w),
                _ => unreachable!(),
            }
        }
        if let Ok(msg) = rx2.try_recv() {
            match msg {
                Msg::Arc(a) => upgrades.push(a),
                Msg::Weak(w) => weaks.push(w),
                _ => unreachable!(),
            }
        }
        if let AllocatorMethod::NextThread = &method {
            if current == 1 {
                current = 2;
            } else if current == 2 {
                current = 1;
            }
        } else if let AllocatorMethod::SendArcToThread = &method {
            if upgrades.is_empty() {
                continue;
            }
            if current == 1 {
                tx1.send(Msg::Arc(upgrades.pop().unwrap())).unwrap();
            } else if current == 2 {
                tx2.send(Msg::Arc(upgrades.pop().unwrap())).unwrap();
            }
        } else if let AllocatorMethod::SendWeakToThread = &method {
            if weaks.is_empty() {
                continue;
            }
            if current == 1 {
                tx1.send(Msg::Weak(weaks.pop().unwrap())).unwrap();
            } else if current == 2 {
                tx2.send(Msg::Weak(weaks.pop().unwrap())).unwrap();
            }
        } else if current == 1 {
            tx1.send(Msg::Cmd(method)).unwrap();
        } else if current == 2 {
            tx2.send(Msg::Cmd(method)).unwrap();
        }
    }

    //let sentinel2 = b'B';
    //uninit_vec.resize(uninit_size, sentinel2);

    print!("{}", weak_alloc::instrument::dump_null_ptr_layout_counters());

    drop(tx1);
    drop(tx2);
    t1.join().unwrap();
    t2.join().unwrap();
});
