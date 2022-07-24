#![warn(unsafe_op_in_unsafe_fn)]
use once_cell::sync::Lazy;
use std::any::Any;
use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::ops::ControlFlow;
use std::ops::Deref;
use std::ptr;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use std::sync::Weak;

/// Doubly linked, heterogeneous, list of `Arc`-like nodes that functions as a least recently used cache.
// The idea is simple: make a linked list using Arc<Node<T>>.
// A Weak<T> is just a pointer to the allocation of an ArcInner<T>. An Arc<T> is the same pointer.
// So the WeakRef is also just a pointer, but instead of pointing to T it points to Node<T>.
// This allows to very cheaply move the node to the front of the list when used, implementing a
// LRU cache.
//
// Requirements:
// * Must be able to push new element as recently used.
// * Pushing new element returns a WeakRef (equivalent to Weak<T>), which can be upgraded to an ArcRef (equivalent to Arc<T>).
// * Upgrading a WeakRef to an ArcRef can fail if the element was removed from the list.
// * upgrade() should return an Option<ArcRef<T>>.
// * Upgrading a WeakRef to an ArcRef must mark the element as recently used.
// * Must be able to remove least recently used element that is not being currently used by an
// ArcRef.
// * Must be able to remove all elements that no longer have any WeakRefs or ArcRefs that could
// use them.
// * Must be able to push heterogenous types: one WeakList can contain an Arc<String> and an
// Arc<Vec<u32>>, even an Arc<[u8]>.
// * The WeakList must provide an API that does not perform allocations, but allocations can be used in user code.
pub struct WeakList<S: WeakListNodeSet> {
    head: *const RawArcNode,
    tail: *const RawArcNode,
    // Storage used to keep track of all the nodes that belong to this list. This is used to allow
    // safe and fast remove and upgrade functions, because otherwise these functions would need to
    // check if the node belongs to the list by iterating over all the elements, or trust the
    // caller that the node belongs to the list, making almost all the functions unsafe.
    node_set: S,
}

/// `WeakList` storage, needs to be able to tell whether a node belongs to this list.
///
/// Implementations can assume that:
/// * insert will only be called for nodes that do not already belong to the list
/// * remove will only be called for nodes that do already belong to the list
///
/// # Safety
///
/// This trait is unsafe because if an implementation returns true for a pointer that is not in the
/// list, many invariants will be broken. Therefore, contains must always return the correct value.
pub unsafe trait WeakListNodeSet {
    fn insert_ns(&mut self, ptr: usize);
    fn contains_ns(&self, list: &WeakList<Self>, ptr: usize) -> bool
    where
        Self: Sized;
    fn remove_ns(&mut self, ptr: usize);
}

/// Default `WeakList` storage: a hashset of pointer values.
/// O(n) space but O(1) time.
// This is Lazy because HashSet::new is not a const fn.
pub type WeakListHashSet = Lazy<HashSet<usize>>;

unsafe impl WeakListNodeSet for Lazy<HashSet<usize>> {
    fn insert_ns(&mut self, ptr: usize) {
        self.insert(ptr);
    }
    fn contains_ns(&self, _list: &WeakList<Self>, ptr: usize) -> bool {
        self.contains(&ptr)
    }
    fn remove_ns(&mut self, ptr: usize) {
        self.remove(&ptr);
    }
}

/// To check if the list contains a node, iterate over all the nodes in the list until we find the
/// target one. O(1) space but O(n) time.
#[derive(Default)]
pub struct LinearSearch;

unsafe impl WeakListNodeSet for LinearSearch {
    fn insert_ns(&mut self, _ptr: usize) {}
    fn contains_ns(&self, list: &WeakList<Self>, ptr: usize) -> bool {
        // Iterate over list, check if any node address matches ptr
        let mut node = list.head;
        while !node.is_null() {
            if node as usize == ptr {
                return true;
            }
            unsafe { node = read_raw_node_next(node) };
        }

        false
    }
    fn remove_ns(&mut self, _ptr: usize) {}
}

unsafe impl<S: Send + WeakListNodeSet> Send for WeakList<S> {}
unsafe impl<S: Sync + WeakListNodeSet> Sync for WeakList<S> {}

impl<S: Default + WeakListNodeSet> Default for WeakList<S> {
    fn default() -> Self {
        Self {
            head: ptr::null(),
            tail: ptr::null(),
            node_set: S::default(),
        }
    }
}

impl<S: WeakListNodeSet> Drop for WeakList<S> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl WeakList<Lazy<HashSet<usize>>> {
    pub const fn new() -> Self {
        Self {
            head: ptr::null(),
            tail: ptr::null(),
            node_set: Lazy::new(HashSet::new),
        }
    }

    pub fn realloc_hashset_if_needed_no_alloc(
        &mut self,
        bigger_hashset: Option<&mut AllocHashSet>,
    ) {
        // Only reallocate if the hashset is full
        if self.node_set.len() != self.node_set.capacity() {
            return;
        }

        match bigger_hashset {
            Some(new_hs) => {
                if new_hs.capacity() <= self.node_set.capacity() {
                    panic!("New AllocHashSet capacity must be greater than the current capacity but {} <= {}", new_hs.capacity(), self.node_set.capacity());
                }
                new_hs.0.extend(self.node_set.drain());
                std::mem::swap(&mut *self.node_set, &mut new_hs.0);
                // Now bigger_hashset contains the smaller hashset
            }
            None => {
                // If the user did not provide a bigger_hashset, assume they don't mind allocating
                // memory, so don't realloc here
            }
        }
    }

    /// Returns the capacity of the hashset used to keep track of the active nodes. This capacity
    /// can be used to ensure that the `AllocHashSet::with_capacity` passed to
    /// `push_front_no_alloc` has a greater capacity.
    pub fn hashset_capacity(&self) -> usize {
        self.node_set.capacity()
    }
}

impl<S: WeakListNodeSet> WeakList<S> {
    /// Push element to the front of the list. This makes this new element the most recently used.
    ///
    /// Returns a `WeakRef<T>` that can be upgraded to an `ArcRef<T>`, similarly to the
    /// `Weak`/`Arc` std types.
    // This asserts that T is Send+Sync because that's the requirement to make Arc<T> Send+Sync.
    pub fn push_front<T: Send + Sync + 'static>(&mut self, elem: T) -> WeakRef<T> {
        self.push_front_no_alloc(elem, AllocMem::default())
    }

    /// Same as `push_front`, but does not allocate. The user is expected to pass
    /// `AllocMem::default()` and `AllocHashSet::with_capacity(cap)` as arguments.
    // This asserts that T is Send+Sync because that's the requirement to make Arc<T> Send+Sync.
    pub fn push_front_no_alloc<T: Send + Sync + 'static>(
        &mut self,
        elem: T,
        memory: AllocMem<T>,
    ) -> WeakRef<T> {
        let f_move_out = arc_from_raw_to_arc_any::<T>;
        let meta = RawArcNode {
            prev: AtomicPtr::new(ptr::null_mut()),
            next: AtomicPtr::new(ptr::null_mut()),
            f_move_out,
        };
        let mut uninit_arc: Arc<MaybeUninit<Node<T>>> = memory.0;
        let node = Node { meta, elem };
        Arc::get_mut(&mut uninit_arc).unwrap().write(node);
        let arc_node: Arc<Node<T>> =
            unsafe { Arc::from_raw(Arc::into_raw(uninit_arc) as *const Node<T>) };
        let weak_ref = WeakRef {
            weak: Arc::downgrade(&arc_node),
        };
        let raw_node_ptr = Arc::into_raw(arc_node) as *const RawArcNode;
        unsafe { self.push_front_node(raw_node_ptr) }

        weak_ref
    }

    // I give up but an unsized push must be possible to implement.
    // But note that it won't be useful for dinamically sized arrays, because a `Node<[u8]>` does
    // not own any heap memory so dropping one of those nodes from the list will not free any new
    // memory. But it may be useful to store a `dyn Trait` for some use cases.
    /*
    pub fn push_front_unsized<T: ?Sized + Send + Sync + 'static, F>(&mut self, f: F) -> WeakRef<T>
    where F: FnOnce(OpaqueMeta) -> Arc<UnsizedNode<T>>
    {
        let meta = RawArcNode {
            prev: AtomicPtr::new(ptr::null_mut()),
            next: AtomicPtr::new(ptr::null_mut()),
            list: self as *const Self,
            f_move_out: |_| todo!(),
        };
        let elem = f(OpaqueMeta(meta));
        let arc_node: Arc<Node<T>> = unsafe { Arc::from_raw(Arc::into_raw(elem) as *const Node<T>) };
        let weak_ref = WeakRef { weak: Arc::downgrade(&arc_node) };
        let raw_node_ptr = Arc::into_raw(arc_node) as *const RawArcNode;
        unsafe { self.push_front_node(raw_node_ptr) };

        weak_ref
    }
    */

    // Push node to the head of the list.
    unsafe fn push_front_node(&mut self, raw_node_ptr: *const RawArcNode) {
        match (self.head.is_null(), self.tail.is_null()) {
            (true, true) => {
                self.head = raw_node_ptr;
                self.tail = self.head;
            }
            (false, false) => {
                unsafe {
                    raw_nodes_link(raw_node_ptr, self.head);
                }
                self.head = raw_node_ptr;
            }
            _ => unreachable!("head and tail must both be null or both be not null"),
        }
        self.node_set.insert_ns(raw_node_ptr as usize);
    }

    fn contains_node(&self, raw_node_ptr: *const RawArcNode) -> bool {
        self.node_set.contains_ns(self, raw_node_ptr as usize)
    }

    // Remove node assuming that it belongs to this list
    unsafe fn remove_node(&mut self, raw_node_ptr: *const RawArcNode) {
        unsafe {
            // First update head and tail pointers
            if self.head == raw_node_ptr {
                self.head = read_raw_node_next(raw_node_ptr);
            }
            if self.tail == raw_node_ptr {
                self.tail = read_raw_node_prev(raw_node_ptr);
            }
            // Then update neighbors of node
            remove_node_from_list(raw_node_ptr);
            self.node_set.remove_ns(raw_node_ptr as usize);
            // Note that this function does not drop the node!
        }
    }

    // Move node to the front of the list assuming that it belongs to this list
    unsafe fn move_node_to_front(&mut self, raw_node_ptr: *const RawArcNode) {
        // Inlined from
        //self.remove_node(raw_node_ptr);
        // If the node is already at the front of the list, we are done
        if self.head == raw_node_ptr {
            return;
        }
        unsafe {
            // Update tail
            if self.tail == raw_node_ptr {
                self.tail = read_raw_node_prev(raw_node_ptr);
            }
            // Update neighbors of node
            remove_node_from_list(raw_node_ptr);
        }

        // Inlined from
        //self.push_front_node(raw_node_ptr);
        unsafe {
            raw_nodes_link(raw_node_ptr, self.head);
        }
        self.head = raw_node_ptr;
    }

    /// Remove the least recently used element. This does not check if that element is being
    /// currently used, so prefer using `pop_lru` instead.
    pub fn pop_back(&mut self) -> Option<Arc<dyn Any + Send + Sync + 'static>> {
        if self.tail.is_null() {
            return None;
        }

        unsafe {
            let tail = self.tail;
            self.remove_node(tail);
            let arc_any = move_out_of_raw_node(tail);

            Some(arc_any)
        }
    }

    /// Remove the least recently used element that is not currently being used: it does not have
    /// any active `ArcRef`s referencing it.
    pub fn pop_lru(&mut self) -> Option<Arc<dyn Any + Send + Sync + 'static>> {
        //println!("{:?}", self.node_set);
        // Find the last element with strong count 1
        let mut node = self.tail;

        while !node.is_null() {
            unsafe {
                let strong_count = read_raw_node_strong_count(node);
                if strong_count == 1 {
                    // When removing the node, move node.next to the head of the list.
                    // This is done because elements with strong_count > 1 can be consider active,
                    // so we can move them to the front of the queue to speed up the next call to
                    // pop_lru. Let's say these are the strong counts of the nodes:
                    // n0 n1 n2 n3 n4
                    //  2  1  1  2  2
                    // If n2 is the removed node, the resulting list should look like:
                    // n3 n4 n0 n1 n2
                    //  2  2  2  1  1
                    // And then n2 can be immediately removed. Then the next call to pop_lru will
                    // check n1 then n0, and then n4 and n3. n4 and n3 used to have a strong count
                    // of 2, so it is unlikely that they will be removed, so it is better to have
                    // them near the front of the list.
                    //
                    // So:
                    // * cut n2-n3
                    // * link n4-n0
                    // * head = n3
                    // * tail = n2
                    // * self.pop_back()
                    let n2 = node;
                    let n3 = read_raw_node_next(n2);
                    if !n3.is_null() {
                        raw_nodes_cut(n2, n3);
                        let n4 = self.tail;
                        let n0 = self.head;
                        raw_nodes_link(n4, n0);
                        self.head = n3;
                        self.tail = n2;
                    }
                    // If n2.next was null then n2 was the last element

                    return self.pop_back();
                }

                // Visit next node
                node = read_raw_node_prev(node);
            }
        }

        None
    }

    /// Remove all the unreachable elements that do not have any `WeakRef` or `ArcRef`, so they
    /// will never be used again. Returns a `Vec` of the removed elements.
    pub fn remove_unreachable(&mut self) -> Vec<Arc<dyn Any + Send + Sync + 'static>> {
        let mut v = vec![];

        self.remove_unreachable_into_f(|arc_any| {
            v.push(arc_any);

            ControlFlow::Continue(())
        });

        v
    }

    /// Same as `remove_all_unreachable`, but insert the removed elements into the provided buffer.
    /// This can be used to manually deallocate the elements later if needed, and also if it is
    /// important to avoid allocations.
    ///
    /// Note: this function returns immediately if the buffer fills up, so if the returned length
    /// is equal to the buffer size it means that there may still be some unreachable elements
    /// left.
    // TODO: this could return a cursor to continue iteration or something
    pub fn remove_unreachable_into_buf(
        &mut self,
        buf: &mut [Option<Arc<dyn Any + Send + Sync + 'static>>],
    ) -> usize {
        if buf.is_empty() {
            return 0;
        }

        let mut count = 0;

        self.remove_unreachable_into_f(|arc_any| {
            buf[count] = Some(arc_any);
            count += 1;

            if count == buf.len() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });

        count
    }

    /// Same as `remove_all_unreachable`, but pass ownership of the removed element to the provided
    /// callback. This can be used to manually deallocate the elements later if needed.
    pub fn remove_unreachable_into_f<F>(&mut self, mut f: F)
    where
        F: FnMut(Arc<dyn Any + Send + Sync + 'static>) -> ControlFlow<()>,
    {
        // Remove all elements with strong count 1 and weak count 0
        // (these can never be upgraded to an ArcRef, so they can be safely removed)
        let mut node = self.tail;

        while !node.is_null() {
            unsafe {
                let next_node = read_raw_node_prev(node);
                if raw_node_arc_is_unique(node) {
                    self.remove_node(node);
                    let arc_any = move_out_of_raw_node(node);
                    if f(arc_any).is_break() {
                        break;
                    }
                }
                // Visit next node
                node = next_node;
            }
        }
    }

    /// Remove an element from the list.
    pub fn remove<T>(&mut self, weak_ref: &WeakRef<T>) -> Option<ArcRef<T>> {
        // Check if weak_ref belongs to this list
        let raw_node_ptr = weak_ref.weak.as_ptr() as *const RawArcNode;
        if !self.contains_node(raw_node_ptr) {
            return None;
        }
        // SAFETY: we just checked that the list contains this node
        unsafe { self.remove_node(raw_node_ptr) };
        // No need to use move_out_of_raw_node function because we know T
        let arc: Arc<Node<T>> = unsafe { Arc::from_raw(raw_node_ptr as *const Node<T>) };

        Some(ArcRef { arc })
    }

    /// Remove all the elements from the list, regardless of if they are being actively used or
    /// not.
    pub fn clear(&mut self) {
        while let Some(arc) = self.pop_back() {
            drop(arc);
        }
    }
}

pub struct AllocMem<T>(Arc<MaybeUninit<Node<T>>>);

impl<T> Default for AllocMem<T> {
    fn default() -> Self {
        Self(Arc::new(MaybeUninit::uninit()))
    }
}

pub struct AllocHashSet(HashSet<usize>);

unsafe impl Send for AllocHashSet {}
unsafe impl Sync for AllocHashSet {}

impl AllocHashSet {
    // We should not provide a default implementation, because users may incorrectly pass
    // AllocHashSet::default to push_front_no_alloc, and that will not work.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashSet::with_capacity(capacity))
    }

    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Reserve capacity such that the new capacity is at least `target_cap`. If `target_cap` is
    /// less than the current capacity, this function may not actually reallocate.
    pub fn allocate_capacity(&mut self, target_cap: usize) {
        self.0.reserve(target_cap.saturating_sub(self.0.len()))
    }
}

/// Recover a `Arc<dyn Any>` back from a `*const RawArcNode`. This is needed to run the destructor
/// of `T` when nodes are removed from the list.
unsafe fn arc_from_raw_to_arc_any<T: Send + Sync + 'static>(
    raw_node_ptr: *const RawArcNode,
) -> Arc<dyn Any + Send + Sync + 'static> {
    // This Arc<dyn Any> cannot be used to recover the Arc<T> because we do not have an Arc<T>, we
    // have an Arc<Node<T>> and users cannot use the Node type. But users can recover a ArcRef<T>
    // using the function `arc_dyn_any_to_arc_ref_t` (that name will probably change). And then use
    // ArcRef::get_mut to get a mutable reference. See test push_pop_back_recover_type_from_pop for
    // an example.
    unsafe { Arc::<Node<T>>::from_raw(raw_node_ptr as *const Node<T>) }
}

unsafe fn read_raw_node_prev(p: *const RawArcNode) -> *const RawArcNode {
    unsafe { &(*p).prev }.load(SeqCst)
}

unsafe fn read_raw_node_next(p: *const RawArcNode) -> *const RawArcNode {
    unsafe { &(*p).next }.load(SeqCst)
}

unsafe fn update_raw_node_prev(p: *const RawArcNode, prev: *const RawArcNode) {
    unsafe { &(*p).prev }.store(prev as *mut RawArcNode, SeqCst);
}

unsafe fn update_raw_node_next(p: *const RawArcNode, next: *const RawArcNode) {
    unsafe { &(*p).next }.store(next as *mut RawArcNode, SeqCst);
}

unsafe fn raw_nodes_cut(p0: *const RawArcNode, p1: *const RawArcNode) {
    unsafe {
        update_raw_node_next(p0, ptr::null());
        update_raw_node_prev(p1, ptr::null());
    }
}

unsafe fn raw_nodes_link(p0: *const RawArcNode, p1: *const RawArcNode) {
    unsafe {
        update_raw_node_next(p0, p1);
        update_raw_node_prev(p1, p0);
    }
}

unsafe fn remove_node_from_list(p: *const RawArcNode) {
    // [n0 n1 n2]
    // [n0 n2]
    // n0 = n1.prev
    // n2 = n1.next
    // n0.next = n2
    // n2.prev = n0

    unsafe {
        let prev = read_raw_node_prev(p);
        let next = read_raw_node_next(p);

        if !prev.is_null() {
            update_raw_node_next(prev, next);
        }
        if !next.is_null() {
            update_raw_node_prev(next, prev);
        }

        update_raw_node_prev(p, ptr::null());
        update_raw_node_next(p, ptr::null());
    }
}

/// Return strong_count == 1 && weak_count == 0
unsafe fn raw_node_arc_is_unique(p: *const RawArcNode) -> bool {
    let mut dummy_arc: Arc<Node<()>> = unsafe { Arc::from_raw(p as *const Node<()>) };

    // This function cannot read strong_count and weak_count directly because of possible race
    // conditions. There is an Arc::is_unique method but it is private. Arc::get_mut is implemented
    // as "if Arc::is_unique { Some } else { None }", so let's use that here.
    let is_unique = Arc::get_mut(&mut dummy_arc).is_some();
    std::mem::forget(dummy_arc);

    // Race conditions are not possible here because if the Arc is unique, the only place where we
    // can add new Arcs or Refs is inside this WeakList. So if `is_unique` is true, it will stay
    // true, but if `is_unique` is false it may become true. That is not a problem because we only
    // remove the node if `is_unique` is true.
    is_unique
}

unsafe fn read_raw_node_strong_count(p: *const RawArcNode) -> usize {
    let dummy_arc: Arc<Node<()>> = unsafe { Arc::from_raw(p as *const Node<()>) };
    let strong_count = Arc::strong_count(&dummy_arc);
    std::mem::forget(dummy_arc);

    strong_count
}

unsafe fn move_out_of_raw_node(node: *const RawArcNode) -> Arc<dyn Any + Send + Sync + 'static> {
    let arc_from_raw_to_arc_any = unsafe { (*node).f_move_out };
    unsafe { arc_from_raw_to_arc_any(node) }
}

/// Arc<Node<T>> is just a pointer to an ArcInner<Node<T>>. This struct represents the Node<T>
/// part. The memory layout of the ArcInner<Node<T>> is:
/// * strong_count: AtomicUsize
/// * weak_count: AtomicUsize
/// * prev
/// * next
/// * f_move_out
/// * T
/// Accessing the inner fields of the Node<T> requires owning a `&mut WeakList`, so it should be
/// safe to just unsafely write it. But to be conservative we use atomic fields to implement
/// mutability.
///
/// The reason this should not be needed is because these fields are private, so user code can only
/// access T through a &T. Technically a reference &T is also a borrow of `&Node<T>` and mutating
/// the other fields requires creating a `&mut Node<T>`, and creating a `&mut` reference while
/// there is another `&` reference is undefined behavior. So just to be sure we avoid ever creating
/// a `&mut Node<T>` or a `&mut RawArcNode`.
#[repr(C)]
struct RawArcNode {
    prev: AtomicPtr<RawArcNode>,
    next: AtomicPtr<RawArcNode>,
    f_move_out: unsafe fn(*const RawArcNode) -> Arc<dyn Any + Send + Sync + 'static>,
}

// repr(C) guarantees that it is safe to cast *const Node to *const RawArcNode
// TODO: but does RawArcNode need repr(C) as well?
#[repr(C)]
struct Node<T: ?Sized> {
    meta: RawArcNode,
    elem: T,
}

// Failed attempt to implement push_unsized
/*
#[repr(C)]
pub struct UnsizedNode<T: ?Sized> {
    pub meta: OpaqueMeta,
    pub elem: T,
}

pub struct OpaqueMeta(RawArcNode);

impl Default for OpaqueMeta {
    fn default() -> Self {
        Self(RawArcNode {
            prev: AtomicPtr::new(ptr::null_mut()),
            next: AtomicPtr::new(ptr::null_mut()),
            list: ptr::null(),
            f_move_out: |_| { unreachable!() },
        })
    }
}

impl OpaqueMeta {
    pub fn set_metadata<T: Send + Sync + 'static>(&mut self, _arc: &Arc<UnsizedNode<T>>) {
        self.0.f_move_out = arc_from_raw_to_arc_any::<T>;
    }
}
*/

// TODO: the destructor of WeakRef could check the strong/weak counts, and if they are 1/1 this
// means that this was the last WeakRef to the value, and the value can be removed from the list.
// But we cannot remove items from the list because we dont have a mutable reference to the list
// inside the drop function. Same applies to ArcRef.
pub struct WeakRef<T: ?Sized> {
    weak: Weak<Node<T>>,
}

impl<T: ?Sized> Clone for WeakRef<T> {
    fn clone(&self) -> Self {
        Self {
            weak: self.weak.clone(),
        }
    }
}

impl<T: ?Sized + Send + Sync + 'static> WeakRef<T> {
    pub fn upgrade<S: WeakListNodeSet>(&self, list: &mut WeakList<S>) -> Option<ArcRef<T>> {
        // First, upgrade to prevent WeakList::pop_lru from removing the element (although that's
        // impossible because we hold a `&mut WeakList`).
        let ret = self.upgrade_quietly()?;

        // If the list does not contain this node we do not need to update element position
        let raw_node_ptr = self.weak.as_ptr() as *const RawArcNode;
        if !list.contains_node(raw_node_ptr) {
            return None;
        }
        // Mark node as recently used by moving it to the front of the list.
        // SAFETY: we just checked that the list contains this node
        unsafe {
            list.move_node_to_front(raw_node_ptr);
        }

        Some(ret)
    }

    /// Upgrade the `WeakRef` to an `ArcRef`, but do not mark it as least recently used in its
    /// parent `WeakList`.
    ///
    /// This can be used to check whether a `WeakRef` can still be upgraded. It can also be used to
    /// upgrade without a reference to the `WeakList`, but that is not recommended because it makes
    /// the `WeakList` less useful.
    pub fn upgrade_quietly(&self) -> Option<ArcRef<T>> {
        self.weak.upgrade().map(|arc| ArcRef { arc })
    }
}

pub struct ArcRef<T: ?Sized> {
    arc: Arc<Node<T>>,
}

impl<T: ?Sized> Clone for ArcRef<T> {
    fn clone(&self) -> Self {
        Self {
            arc: self.arc.clone(),
        }
    }
}

impl<T: ?Sized> Deref for ArcRef<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.arc.elem
    }
}

impl<T: ?Sized> ArcRef<T> {
    pub fn get_mut(this: &mut Self) -> Option<&mut T> {
        Arc::get_mut(&mut this.arc).map(|x| &mut x.elem)
    }

    pub fn downgrade(this: &Self) -> WeakRef<T> {
        WeakRef {
            weak: Arc::downgrade(&this.arc),
        }
    }
}

/// Try to downcast the result of `WeakList::pop_lru` back into an `ArcRef<T>`. Returns the passed
/// `Arc` back in case of error.
pub fn arc_dyn_any_to_arc_ref_t<T: Send + Sync + 'static>(
    aa: Arc<dyn Any + Send + Sync + 'static>,
) -> Result<ArcRef<T>, Arc<dyn Any + Send + Sync + 'static>> {
    // Try to downcast Arc<dyn Any> to Arc<Node<T>>
    aa.downcast::<Node<T>>().map(|node| ArcRef { arc: node })
}

/*
pub trait ArcNodeDowncast {
    fn get_arc_ref<T: ?Sized>(&self) -> Option<ArcRef<T>>;
}

impl<T> ArcNodeDowncast for Arc<dyn ArcNodeDowncast {
    fn get_arc_ref<T: ?Sized>(&self
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_elem() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        let s1 = ws1.upgrade(&mut wl).expect("s1 died");

        assert_eq!(*s1, format!("string1"));
    }

    #[test]
    fn push_pop_back() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        wl.pop_back();

        assert!(ws1.upgrade(&mut wl).is_none());
    }

    #[test]
    fn push_pop_lru() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        assert!(wl.pop_lru().is_some());

        assert!(ws1.upgrade(&mut wl).is_none());
    }

    #[test]
    fn push_pop_lru_while_upgraded() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        let _s1 = ws1.upgrade(&mut wl).unwrap();

        assert!(wl.pop_lru().is_none());
    }

    #[test]
    fn push_pop_lru_moves_upgraded_tail_to_front() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));
        let s1 = ws1.upgrade(&mut wl).unwrap();
        let _ws2 = wl.push_front(format!("string2"));
        let _ws3 = wl.push_front(format!("string3"));

        // ws1 is the least recently used, but we hold an ArcRef so it will not be removed by
        // pop_lru. ws2 will be removed instead, and ws1 will be moved to the front.
        assert!(wl.pop_lru().is_some());

        // Release ArcRef, but ws1 is still at the front so ws2 will be removed first
        drop(s1);

        assert!(wl.pop_lru().is_some());

        // If ws1 was not removed, we can upgrade it again
        let _s1 = ws1.upgrade(&mut wl).unwrap();
    }

    #[test]
    fn push_push_upgrade_pop() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));
        let ws2 = wl.push_front(format!("string2"));

        assert!(ws1.upgrade(&mut wl).is_some());

        wl.pop_lru();

        assert!(ws1.upgrade(&mut wl).is_some());
        assert!(ws2.upgrade(&mut wl).is_none());
    }

    #[test]
    fn remove_unreachable() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));
        let ws2 = wl.push_front(format!("string2"));
        let ws3 = wl.push_front(format!("string3"));

        drop(ws1);
        drop(ws3);

        // Removes ws1 and ws3
        assert_eq!(wl.remove_unreachable().len(), 2);
        assert!(ws2.upgrade(&mut wl).is_some());
        // Removes ws2
        assert!(wl.pop_back().is_some());
        assert!(ws2.upgrade(&mut wl).is_none());
        // List is now empty
        assert!(wl.pop_back().is_none());
    }

    #[test]
    fn remove_unreachable_empty_buf() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        assert_eq!(wl.remove_unreachable_into_buf(&mut []), 0);

        // ws1 was not removed from list
        let _s1 = ws1.upgrade(&mut wl).unwrap();
    }

    #[test]
    fn remove_unreachable_big_buf() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));
        drop(ws1);

        let mut buf = vec![None; 10];

        assert_eq!(wl.remove_unreachable_into_buf(&mut buf), 1);
        // List is now empty
        assert!(wl.pop_back().is_none());
    }

    #[test]
    fn heterogenous_list() {
        let mut wl = WeakList::new();

        let _ws1 = wl.push_front(format!("string1"));
        let _ws2 = wl.push_front(8u32);
        let _ws3 = wl.push_front(vec!["a", "b", "c"]);
    }

    #[test]
    fn weak_list_is_sync_and_send() {
        fn assert_is_sync_and_send<T: Send + Sync>(_x: &T) {}

        assert_is_sync_and_send(&WeakList::new());
    }

    /*
    #[test]
    fn weak_list_of_rc_should_not_compile() {
        let mut wl = WeakList::new();

        let wsrc = wl.push_front(std::rc::Rc::new(1u8));
    }
    */

    #[test]
    fn upgrade_node_with_another_list() {
        let mut wl1 = WeakList::new();
        let _ws1 = wl1.push_front(format!("string1"));
        let mut wl2 = WeakList::new();
        let ws2 = wl2.push_front(format!("string2"));

        assert!(ws2.upgrade(&mut wl1).is_none());
    }

    #[test]
    fn push_pop_back_updates_head() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        wl.pop_back();

        assert!(ws1.upgrade(&mut wl).is_none());

        // If wl.head still points to ws1, this will fail
        let ws2 = wl.push_front(format!("string2"));
        assert!(ws2.upgrade(&mut wl).is_some());
    }

    #[test]
    fn remove_node_twice() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        let _s1 = wl.remove(&ws1).unwrap();
        assert!(wl.remove(&ws1).is_none());
    }

    #[test]
    fn remove_node_after_moving_list() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        let mut wl2 = WeakList::new();
        std::mem::swap(&mut wl, &mut wl2);

        let _s1 = wl2.remove(&ws1).unwrap();
    }

    #[test]
    fn upgrade_node_after_moving_list() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        let mut wl2 = WeakList::new();
        std::mem::swap(&mut wl, &mut wl2);

        let _s1 = ws1.upgrade(&mut wl2).unwrap();
    }

    #[test]
    fn remove_node_from_another_list() {
        let mut wl1 = WeakList::new();
        let ws1 = wl1.push_front(format!("string1"));
        let mut wl2 = WeakList::new();
        let _ws2 = wl2.push_front(format!("string2"));

        assert!(wl2.remove(&ws1).is_none());
    }

    #[test]
    fn list_cleared_on_drop() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        drop(wl);

        assert_eq!(ws1.upgrade_quietly().as_deref(), None);
    }

    /*
    #[test]
    fn unsized_push() {
        let a1: Arc<[u8]> = Arc::new([1]);

        let mut wl = WeakList::new();

        wl.push_front_unsized(|mut meta| {
            let an1 = Arc::new(UnsizedNode { meta, elem: [1] });
            meta.set_metadata(&an1);
            an1
        });
    }
    */

    #[test]
    fn upgrade_node_after_removing_from_list() {
        // This test used to segfault when dropping the WeakList after the upgrade.
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        let _arc_s1 = wl.pop_back().unwrap();

        // This currently returns None, but it would be fine if it also returns Some
        assert!(ws1.upgrade(&mut wl).is_none());
    }

    #[test]
    fn push_pop_back_recover_type_from_pop() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        let arc_dyn_any = wl.pop_back().unwrap();

        drop(ws1);

        let mut as1: ArcRef<String> = arc_dyn_any_to_arc_ref_t(arc_dyn_any).unwrap();

        let s1_ref = ArcRef::get_mut(&mut as1).unwrap();
        let s1 = std::mem::take(s1_ref);

        assert_eq!(s1, format!("string1"));
    }

    #[test]
    fn push_pop_back_recover_type_from_weak_ref() {
        let mut wl = WeakList::new();

        let ws1 = wl.push_front(format!("string1"));

        let _arc_s1 = wl.pop_back().unwrap();

        // It is impossible to recover an ArcRef after the item has been removed from the list
        assert!(ws1.upgrade(&mut wl).is_none());
    }

    #[test]
    fn fuzz_1() {
        // [Give { size: 91 }, Give { size: 72057594037927936 }, Upgrade { index: 0 }, Give { size: 0 }, Clear, Clear, Upgrade { index: 0 }]
        let mut wl = WeakList::new();
        let mut weaks: Vec<Option<WeakRef<Vec<u8>>>> = vec![];
        let mut upgrades = vec![];

        weaks.push(Some(wl.push_front(Vec::with_capacity(91))));
        upgrades.push(weaks[0].as_ref().unwrap().upgrade(&mut wl));
        weaks.push(Some(wl.push_front(Vec::with_capacity(0))));
        wl.clear();
        //wl.clear();
        upgrades.push(weaks[0].as_ref().unwrap().upgrade(&mut wl));
    }

    #[test]
    fn variance_remove() {
        let mut wl = WeakList::new();

        let ws1: WeakRef<&'static str> = wl.push_front("string1");

        fn shorten_lifetime<'a, T: ?Sized>(
            weak_ref: WeakRef<&'a T>,
            _lifetime: &'a T,
        ) -> WeakRef<&'a T> {
            weak_ref
        }

        let stack_str: &str = &format!("hi");
        let shorter_ws1 = shorten_lifetime(ws1, stack_str);
        // Calling remove with a WeakRef<&'a str> instead of a WeakRef<&'static str> is valid and
        // harmless
        let s1: ArcRef<&str> = wl.remove(&shorter_ws1).unwrap();

        assert_eq!(&*s1, &"string1");
    }

    #[test]
    fn default_impl_lazy() {
        // Lazy::default calls HashSet::default, so this works as expected
        let mut wl: WeakList<WeakListHashSet> = WeakList::default();
        let ws1 = wl.push_front(format!("string1"));
        let s1 = ws1.upgrade(&mut wl).expect("s1 died");
        assert_eq!(*s1, format!("string1"));
    }
}
