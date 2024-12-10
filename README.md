# shush-rs

[![crates.io](https://img.shields.io/crates/v/shush-rs.svg)](https://crates.io/crates/shush-rs)
[![Github](https://img.shields.io/badge/github-eyob94/shush-rs)](https://github.com/Eyob94/shush-rs)

A Rust crate designed to manage sensitive data securely by leveraging memory protection mechanisms. It extends the functionality of the [secrecy](https://crates.io/crates/secrecy) crate to provide enhanced security features using memory locking and protection techniques. Specifically, `shush-rs` ensures that secrets are kept safe from unauthorized access and are properly zeroized when no longer needed.

### Brief overview

- `mlock`: this is a system call that locks a specified range of memory into RAM, preventing it from being swapped out to disk.
- `mprotect`: is a system call that changes the access protections (read, write, execute) for a specified range of memory.

### Features

- Memory Locking: It uses a mlock to lock the secret's memory page, preventing it from being swapped to disk.
- Memory Protection: Employs mprotect to initially set the memory page to non-readable/writable and then to readable/writable only when needed.
- Zeroization: Guarantees that secrets are securely zeroized before they are dropped, minimizing the risk of sensitive data lingering in memory.

### Key Components

- `SecretBox`: A secure container for sensitive data. It locks the memory of the contained secret and ensures it is zeroized on drop.
- `CloneableSecret`: A trait for secrets that can be cloned while ensuring the original is zeroized after cloning.
- `ExposeSecret` and `ExposeSecretMut`: Traits that provide controlled access to secrets, allowing read-only or mutable access while maintaining security.

### Usage

```rust
fn protect_secret(){

  let secret = Box::new(String::from("Encrypted"));

  let mut secret_box = SecretBox::new(secret); // Secret's memory page is mlocked

  println!("Secret: {:?}", secret_box); // Prints "Secret: SecretBox<alloc::string::String>([REDACTED])"

  let exposed_secret = secret_box.expose_secret();

  println!("Exposed Secret:{:?}", exposed_secret); // Prints "ExposedSecret: SecretGuardMut { data: "Encrypted" }"
} // Memory page is munlocked when it's dropped

```

# Limitations

> [!WARNING]  
> **We can securely `mlock` memory of ONLY max the length of the [PAGESIZE](https://www.gnu.org/software/libc/manual/html_node/Query-Memory-Parameters.html) of the system, usually `4KB`**

That is because we are using [std::mem::size_of_val](https://doc.rust-lang.org/std/mem/fn.size_of_val.html) to get the size of the wrapped data. But in some cases, like for `Vec<T>,` mostly any collections or other structs that hold pointers to the actual data, we can't correctly determine the exact combined actual size. This is because `Vec<T>`, for example, holds a pointer on the stack to the first element in the list, and the actual elements are allocated on the heap.

For example, for a `Vec<u8>` with 3 elements, let's say, the actual size is `27 bytes`, but the value returned by `size_of_val` is `8 bytes`. To resolve that, when we calculate the end address to `mlock` of the memory for the wrapped value, we add `PAGESIZE` too, so it will `mlock` the next page too. But if the actual memory is larger than `PAGESIZE,` it could spawn on 3 pages, let's say, but we will only `block` the first 2 of them.

## How a `Vec<u8>` with 3 elements is represented in the memory

In Rust, a `Vec<T>` is a heap-allocated data structure, and its memory usage consists of two parts:
1. **The stack-allocated part**: The Vec<T> itself is a small structure stored on the stack. It contains:
    - A pointer to the start of the data on the heap.
    - The current length of the vector.
    - The allocated capacity of the vector.
   The size of this structure is constant and depends on the platform:
    - On a 64-bit system, this is usually 3 pointers in size (24 bytes).
    - On a 32-bit system, this is 3 pointers in size (12 bytes).
2. **The heap-allocated part**: The actual elements of the vector are stored in a contiguous memory block on the heap, the size of which depends on the length and the element size.
    - length * size_of::<T>(): For your example, the T is u8 (1 byte per element), and the length is 3, so the data consumes 3 * 1 = 3 bytes on the heap.
    - There might also be some unused space due to over-allocation, but the capacity is likely equal to the length for small Vec instances like this.

**Total Memory Usage**

For a specific Vec<u8> (vec![1u8, 2u8, 3u8]):
- **Stack memory**: 24 bytes (on a 64-bit system) or 12 bytes (on a 32-bit system).
- **Heap memory**: 3 bytes for the actual data.

**Total**:
- **64-bit system**: 24 + 3 = 27 bytes.
- **32-bit system**: 12 + 3 = 15 bytes.

Remember that additional heap allocation overhead (from the allocator) is possible but usually negligible for such a small vector.
