# shush
A Rust crate designed to manage sensitive data securely by leveraging memory protection mechanisms. It extends the functionality of the [secrecy](https://crates.io/crates/secrecy) crate to provide enhanced security features using memory locking and protection techniques. Specifically, `shush` ensures that secrets are kept safe from unauthorized access and are properly zeroized when no longer needed.


### Features
- Memory Locking: Uses mlock to lock the secret's memory page, preventing it from being swapped to disk.
- Memory Protection: Employs mprotect to initially set the memory page to non-readable/writable and then to readable/writable only when needed.
- Zeroization: Guarantees that secrets are securely zeroized before they are dropped, minimizing the risk of sensitive data lingering in memory.

### Key Components
- `SecretBox`: A secure container for sensitive data. It locks the memory of the contained secret and ensures it is zeroized on drop.
- `CloneableSecret`: A trait for secrets that can be cloned, while ensuring the original is zeroized after cloning.
- `ExposeSecret` and `ExposeSecretMut`: Traits that provide controlled access to secrets, allowing read-only or mutable access while maintaining security.

### Usage
```rust
  let encrypted_secret = "Encrypted Secret";

  let secret_box = SecretBox::new(encrypted_secret);

  println!("Secret: {#:?}", secret_box);

  let exposed_secret = secret_box.expose();

  println!("Exposed Secret:{}", exposed_secret);

```
