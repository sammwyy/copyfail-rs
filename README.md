# copyfail-rs

**Copy Fail** exploit (CVE-2026-31431) but in Rust, a critical vulnerability chaining `AF_ALG` and `splice()` to achieve a 4-byte page cache write, leading to local privilege escalation on major Linux distributions.

Based on the research and PoC by [Xint Code](https://xint.io/blog/copy-fail-linux-distributions).

## Disclaimer
> [!CAUTION]
> This project is for **educational and research purposes only**. Running this exploit on systems you do not own or have explicit permission to test is illegal and unethical. Use this code responsibly to understand and defend against similar vulnerabilities.

## Features
- **Pure Rust**: A high-performance, memory-safe implementation of the original Python PoC.
- **Dynamic ELF Builder**: Programmatically constructs the exploit payload at runtime, allowing for custom commands.
- **Zero-Copy Exploitation**: Directly interacts with the Linux kernel's `AF_ALG` and `splice()` syscalls via `libc`.
- **Customizable**: Specify the command you want to run as root via CLI arguments.

## Prerequisites
- A Linux kernel vulnerable to **CVE-2026-31431** (typically kernels before the patch in April 2026).
- Rust and Cargo installed.
- Access to a target binary with read permissions (default is `/usr/bin/su`).

## Installation
Clone the repository and build the binary:
```bash
git clone https://github.com/sammwyy/copyfail-rs.git
cd copyfail-rs
cargo build --release
```

## Usage
Run the exploit without arguments to default to `/bin/sh`:
```bash
./target/release/copyfail-rs
```

Or specify a custom command to run as root:
```bash
./target/release/copyfail-rs "whoami > /tmp/pwned"
```

## How it Works
The exploit leverages a bug in the `authencesn` implementation within the Linux kernel's Crypto API (`AF_ALG`). By chaining `sendmsg` with `MSG_MORE` and `splice()`, it's possible to overwrite small chunks of the page cache for arbitrary files (like `/usr/bin/su`) with a malicious ELF payload.

1. **Socket Setup**: Creates an `AF_ALG` socket and binds to `authencesn(hmac(sha256),cbc(aes))`.
2. **Payload Generation**: Constructs a minimal ELF in memory that executes the target command with root privileges.
3. **Cache Injection**: Iteratively splices the payload into the target file's page cache using the `AF_ALG` vulnerability.
4. **Trigger**: Executes the modified target file, running the injected shellcode.

## References
- [Original Blog Post - Xint Code](https://xint.io/blog/copy-fail-linux-distributions)
- [CVE-2026-31431 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-31431)