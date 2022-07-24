//! It is not possible to cause undefined behavior using the safe API of WeakList
#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use std::collections::VecDeque;
use weak_list::WeakList;
use weak_list::AllocHashSet;
use weak_list::AllocMem;
use weak_list::ArcRef;

// Fuzzing target inspired by
// https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html#example-2-fuzzing-allocator-api-calls
#[derive(Arbitrary, Debug)]
enum Method {
    // WeakList
    New,
    Default,
    Clear,
    Drop,
    PushFront,
    PushFrontNoAlloc {
        hashset: u8,
    },
    PopBack,
    PopLru,
    RemoveAllUnreachable {
        buf: u8,
    },
    Remove,

    // WeakRef
    WeakRefClone,
    WeakRefUpgrade {
        quietly: bool,
    },
    WeakRefDrop,

    // ArcRef
    ArcRefClone,
    ArcRefDeref,
    ArcRefGetMut,
    ArcRefDowngrade,
    ArcRefDrop,

    // Arc<dyn Any>
    ArcDynAnyToArcRefT { valid: bool },
    ArcDynAnyDrop,

    // Stack manipulation
    RotateLists,
    RotateWeaks,
    RotateArcs,
    RotateArcDyns,
}

fuzz_target!(|methods: Vec<Method>| {
    let mut lists = VecDeque::new();
    let mut weaks = VecDeque::new();
    let mut arcs = VecDeque::new();
    let mut arc_dyns = VecDeque::new();

    for method in methods {
        match method {
            Method::New => {
                lists.push_back(WeakList::new());
            }
            Method::Default => {
                lists.push_back(WeakList::default());
            }
            Method::Clear => {
                if let Some(mut l) = lists.iter_mut().next_back() {
                    l.clear();
                }
            }
            Method::Drop => {
                lists.pop_back();
            }
            Method::PushFront => {
                if let Some(mut l) = lists.iter_mut().next_back() {
                    let t = vec![1u8];
                    let w = l.push_front(t);
                    weaks.push_back(w);
                }
            }
            Method::PushFrontNoAlloc { hashset } => {
                if let Some(mut l) = lists.iter_mut().next_back() {
                    let t = vec![1u8];
                    let mut hh = AllocHashSet::with_capacity(hashset as usize);
                    let hs = if hashset == u8::MAX { None } else {
                        if hh.capacity() <= l.hashset_capacity() {
                            hh.allocate_capacity(l.hashset_capacity() + 1);
                        }

                        Some(&mut hh)
                    };
                    let w = l.push_front_no_alloc(t, AllocMem::default(), hs);
                    weaks.push_back(w);
                }
            }
            Method::PopBack => {
                if let Some(mut l) = lists.iter_mut().next_back() {
                    if let Some(arc_dyn) = l.pop_back() {
                        arc_dyns.push_back(arc_dyn);
                    }
                }
            }
            Method::PopLru => {
                if let Some(mut l) = lists.iter_mut().next_back() {
                    if let Some(arc_dyn) = l.pop_lru() {
                        arc_dyns.push_back(arc_dyn);
                    }
                }
            }
            Method::RemoveAllUnreachable { buf } => {
                if let Some(mut l) = lists.iter_mut().next_back() {
                    let mut hh = vec![None; buf as usize];
                    let hs = if buf == u8::MAX { None } else {
                        Some(hh.as_mut())
                    };

                    l.remove_all_unreachable_into_buf(hs);
                }
            }
            Method::Remove => {
                if let Some(mut l) = lists.iter_mut().next_back() {
                    if let Some(mut w) = weaks.iter_mut().next_back() {
                        if let Some(a) = l.remove(w) {
                            arcs.push_back(a);
                        }
                    }
                }
            }

            Method::WeakRefClone => {
                if let Some(mut w) = weaks.pop_back() {
                    weaks.push_back(w.clone());
                    weaks.push_back(w);
                }
            }
            Method::WeakRefUpgrade { quietly } => {
                if quietly {
                    if let Some(mut w) = weaks.iter_mut().next_back() {
                        if let Some(a) = w.upgrade_quietly() {
                            arcs.push_back(a);
                        }
                    }
                } else {
                    if let Some(mut l) = lists.iter_mut().next_back() {
                        if let Some(mut w) = weaks.iter_mut().next_back() {
                            if let Some(a) = w.upgrade(l) {
                                arcs.push_back(a);
                            }
                        }
                    }
                }
            }
            Method::WeakRefDrop => {
                weaks.pop_back();
            }

            Method::ArcRefClone => {
                if let Some(mut a) = arcs.pop_back() {
                    arcs.push_back(a.clone());
                    arcs.push_back(a);
                }
            }
            Method::ArcRefDeref => {
                if let Some(mut a) = arcs.iter_mut().next_back() {
                    let _ = &*a;
                }
            }
            Method::ArcRefGetMut => {
                if let Some(mut a) = arcs.iter_mut().next_back() {
                    let _ = ArcRef::get_mut(a);
                }
            }
            Method::ArcRefDowngrade => {
                if let Some(mut a) = arcs.iter_mut().next_back() {
                    let w = ArcRef::downgrade(a);
                    weaks.push_back(w);
                }
            }
            Method::ArcRefDrop => {
                arcs.pop_back();
            }

            Method::ArcDynAnyToArcRefT { valid } => {
                if let Some(mut a) = arc_dyns.iter_mut().next_back() {
                    if valid {
                        if let Some(a2) = weak_list::arc_dyn_any_to_arc_ref_t(a) {
                            arcs.push_back(a2);
                        }
                    } else {
                        if let Some(a2) = weak_list::arc_dyn_any_to_arc_ref_t(a) {
                            let _: ArcRef<String> = a2;
                            unreachable!();
                        }
                    }
                }
            }
            Method::ArcDynAnyDrop => {
                arc_dyns.pop_back();
            }

            Method::RotateLists => {
                if !lists.is_empty() {
                    lists.rotate_right(1);
                }
            }
            Method::RotateWeaks => {
                if !weaks.is_empty() {
                    weaks.rotate_right(1);
                }
            }
            Method::RotateArcs => {
                if !arcs.is_empty() {
                    arcs.rotate_right(1);
                }
            }
            Method::RotateArcDyns => {
                if !arc_dyns.is_empty() {
                    arc_dyns.rotate_right(1);
                }
            }
        }
    }
});
