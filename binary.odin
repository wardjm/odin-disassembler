package binary

import "core:fmt"
import "core:strings"
import "core:os"
import bfd "./odin-bfd"

symbol_type :: enum {
    SYM_TYPE_UNK,
    SYM_TYPE_FUNC
}

binary_type :: enum {
    BINARY_TYPE_AUTO,
    BINARY_TYPE_ELF,
    BINARY_TYPE_PE
}

binary_arch :: enum {
    ARCH_NONE,
    ARCH_X86,
    ARCH_X64,
    ARCH_ARM,
    ARCH_AARCH64
}

section_type :: enum {
    SEC_TYPE_NONE,
    SEC_TYPE_CODE,
    SEC_TYPE_DATA
}

Section :: struct {
    binary : ^Binary,
    name : string,
    type : section_type,
    vma : u64,
    size : u64,
    bytes : []u8
}

Symbol :: struct {
    type: symbol_type,
    name: string,
    addr: u64
}

Binary :: struct {
    filename: string,
    type: binary_type,
    type_str: string,
    arch: binary_arch,
    arch_str: string,
    bits: u32,
    entry: u64,
    sections: [dynamic]Section,
    symbols: [dynamic]Symbol
}

get_text_section :: proc(bin: ^Binary) -> ^Section {
    s : Section

    for &s in bin.sections {
	if s.name == ".text" {
	    return &s
	}
    }
    return nil
}

open_bfd :: proc(filename : string) -> ^bfd.bfdt {

    bfd.bfd_init()

    b : ^bfd.bfdt = bfd.bfd_openr(strings.clone_to_cstring(filename), nil)

    ok : bool = bfd.bfd_check_format(b, bfd.bfd_format.bfd_object)

    if !ok {
	fmt.println("Format not recognized")
	return nil
    }

    bfd.bfd_set_error(.bfd_error_no_error)

    if (bfd.bfd_get_flavour(b) == .bfd_target_unknown_flavour) {
	fmt.println("Unrecognized format: ", bfd.bfd_errmsg(bfd.bfd_get_error()))
	return nil
    }

    return b
}

set_flavour :: proc(bin : ^Binary, b : ^bfd.bfdt) -> bool {

#partial switch bfd.bfd_get_flavour(b) {
    
    case .bfd_target_elf_flavour:
    bin.type = .BINARY_TYPE_ELF

    case .bfd_target_unknown_flavour:
    fmt.println("Unknown flavour")
    return false
    
    // TODO: Add other flavours
    case:
    fmt.println("No flavour")
}
    return true
}

set_arch :: proc(bin : ^Binary, arch_info : ^bfd.bfd_arch_info_type) -> bool {

    arch := bfd.bfd_get_arch(arch_info)

    switch arch_info.mach {
    case bfd.bfd_mach_i386_i386:
	bin.arch = .ARCH_X86
	bin.bits = 32
    case bfd.bfd_mach_x86_64:
	bin.arch = .ARCH_X64
	bin.bits = 64
	
	case:
	fmt.println("Unsupported architecture")
	return false
    }
    return true
    
}

load_symbols_bfd :: proc(bf : ^bfd.bfdt, bin : ^Binary) -> i32 {

    n : i64
    nsyms : i64
    bfd_symtab : []^bfd.asymbol
    
    n = bfd._bfd_elf_get_symtab_upper_bound(bf)

    if n < 0 {
	fmt.println("Failed to read symtab")
	fmt.println(bfd.bfd_errmsg(bfd.bfd_get_error()))
	return -1
    }

    bfd_symtab = make([]^bfd.asymbol, n)
    defer delete(bfd_symtab)
    
    nsyms = bfd._bfd_elf_canonicalize_symtab(bf, bfd_symtab)

    fmt.println("Got syms = ", nsyms)

    if (nsyms < 0) {
	fmt.println("Failed to read symbols")
	fmt.println(bfd.bfd_errmsg(bfd.bfd_get_error()))
	return -1
    }

    i : i64
    
    for i = 0; i < nsyms; i+=1 {

	if (bfd_symtab[i].flags & bfd.BSF_FUNCTION != 0) {

	    sym := new(Symbol)
	    defer free(sym)

	    sym.type = symbol_type.SYM_TYPE_FUNC
	    sym.name = strings.clone_from_cstring(bfd_symtab[i].name)
	    sym.addr = bfd.bfd_asymbol_value(bfd_symtab[i])

	    append(&bin.symbols, sym^)
	}
    }
    
    return 0
}

load_dynsym_bfd :: proc(bf : ^bfd.bfdt, bin : ^Binary) -> i32 {

    n : i64
    nsyms : i64
    bfd_dynsym : []^bfd.asymbol
    
    n = bfd._bfd_elf_get_dynamic_symtab_upper_bound(bf)

    if n < 0 {
	fmt.println("Failed to read symtab")
	fmt.println(bfd.bfd_errmsg(bfd.bfd_get_error()))
	return -1
    }

    bfd_dynsym = make([]^bfd.asymbol, n)
    defer delete(bfd_dynsym)
    
    nsyms = bfd._bfd_elf_canonicalize_dynamic_symtab(bf, bfd_dynsym)

    fmt.println("Got syms = ", nsyms)

    if (nsyms < 0) {
	fmt.println("Failed to read symbols")
	fmt.println(bfd.bfd_errmsg(bfd.bfd_get_error()))
	return -1
    }

    i : i64
    
    for i = 0; i < nsyms; i+=1 {

	if (bfd_dynsym[i].flags & bfd.BSF_FUNCTION != 0) {

	    sym := new(Symbol)
	    defer free(sym)

	    sym.type = symbol_type.SYM_TYPE_FUNC
	    sym.name = strings.clone_from_cstring(bfd_dynsym[i].name)
	    sym.addr = bfd.bfd_asymbol_value(bfd_dynsym[i])

	    append(&bin.symbols, sym^)
	}
    }
    
    return 0
}

load_sections_bfd :: proc(bf : ^bfd.bfdt, bin : ^Binary) -> i32 {

    bfd_sec : ^bfd.asection = bf.sections
    fmt.println("Num sections = ", bf.section_count)

    sectype : section_type

    for bfd_sec != nil {

	sec := new(Section)
	defer free(sec)
	
	sectype = section_type.SEC_TYPE_NONE
	
	if bfd_sec.flags & bfd.SEC_CODE != 0 {
	    sectype = section_type.SEC_TYPE_CODE
	}
	else if bfd_sec.flags & bfd.SEC_DATA != 0 {
	    sectype = section_type.SEC_TYPE_DATA
	}
	else {
	    fmt.println("Skipping section:", bfd_sec.name, " type = ", bfd_sec.flags)
	    bfd_sec = bfd_sec.next
	    continue
	}
	
	sec.binary = bin
	sec.name = strings.clone_from_cstring(bfd_sec.name)
	sec.type = sectype
	sec.vma = bfd_sec.vma
	sec.size = bfd_sec.size
	sec.bytes = make([]u8, sec.size)

	res := bfd.bfd_get_section_contents(bf, bfd_sec, &sec.bytes[0], 0, sec.size)
	if res == false {
	    fmt.println(bfd.bfd_errmsg(bfd.bfd_get_error()))
	    return -1
	}
	
	append(&bin.sections, sec^)
	
	bfd_sec = bfd_sec.next
    }
    
    return 0
}
