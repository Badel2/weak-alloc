# weak-alloc 
 
A custom allocator that can be given ownership of data, returning a `WeakRef`. 
The `WeakRef` is equivalent to a `std::sync::Weak`: a smart pointer that can be 
upgraded to an `ArcRef`, but it may have been invalidated. 
 
The `WeakAlloc` will try to deallocate unused `WeakRef`s when a memory
allocation fails. This allows to use the allocator to implement an efficient
least recently used (LRU) cache that will only evict values when the system is
out of memory. 

### Example

Example use case: a least-recently-used cache implemented using a regular hashmap.

```rust
use std::alloc::System;
use weak_alloc::{WeakAlloc, WeakRef, ArcRef};

#[global_allocator]
static A: WeakAlloc<System> = WeakAlloc::new(System);

struct RegionCache {
    // Cache (region_x, region_z) to uncompressed file, so each region file is
    // only uncompressed once
    cache: HashMap<(i32, i32), WeakRef<Vec<u8>>>,
}

fn get_uncompressed_file(&self, region_x: i32, region_z: i32) -> Result<ArcRef<Vec<u8>>, ChunkLoadError> {
    let arc_ref = self
        .cache
        .get(&(region_x, region_z))
        .and_then(|w| w.upgrade());

    if let Some(arc_ref) = arc_ref {
        // Return value from cache
        Ok(arc_ref)
    } else {
        // Not into cache or upgrade failed because the WeakRef was removed from the list, so read file.
        // Uncompress file
        let buf = uncompress_file(region_x, region_z);
        // Give ownership to allocator
        let arc_ref = A.give_and_upgrade(buf);
        // Insert into cache
        self.cache
            .insert((region_x, region_z), ArcRef::downgrade(&arc_ref));

        Ok(arc_ref)
    }
}
```
 
### Caveats 
 
Some operating systems overcommit memory, which means that your program never 
actually runs of out memory, instead the operating system kills the process if 
it uses too much memory. In that case this allocator will not be able to do its 
job, because it is never given a chance. As a simple workaround, you can wrap 
the system allocator with another allocator that limits the total memory, such 
as `limit-alloc`: 
 
<https://github.com/Badel2/limit-alloc>

Then you can initialize the `WeakAlloc` like this:

```rust
use std::alloc::System;
use limit_alloc::ConstLimit;
use weak_alloc::WeakAlloc;

// Limit available memory to 200_000 bytes.
#[global_allocator]
static A: WeakAlloc<ConstLimit<System, 200_000>> = WeakAlloc::new(ConstLimit::new(System));
```
