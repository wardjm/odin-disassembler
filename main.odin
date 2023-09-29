package binary

import "core:fmt"
import "core:strings"
import "core:os"
import bfd "./odin-bfd"

main :: proc() {

    if len(os.args) != 2 {
	fmt.println(os.args[0], "<bin>")
	return 
    }

    // Load binary, then do disassembly
    
    bin : Binary
    ok : bool

    b := open_bfd(os.args[1])

    if (b == nil) {
	return
    }

    bin.filename = strings.clone_from_cstring(b.filename)

    fmt.println("Filename = ", bin.filename)

    bin.entry = bfd.bfd_get_start_address(b)

    fmt.println("Start = ", bin.entry)

    bin.type_str = strings.clone_from_cstring(b.xvec.name)

    fmt.println("Type = ", bin.type_str)

    ok = set_flavour(&bin, b)
    if !ok {
	return
    }
    
    fmt.println("Flavour = ", bin.type)

    bfd_info := bfd.bfd_get_arch_info(b)

    bin.arch_str = strings.clone_from_cstring(bfd_info.printable_name)

    fmt.println(bin.arch_str)

    ok = set_arch(&bin, bfd_info)
    if !ok {
	return
    }

    fmt.println("Arch = ", bin.arch, bin.bits)

    load_symbols_bfd(b, &bin)

    load_dynsym_bfd(b, &bin)

    ret := load_sections_bfd(b, &bin)

    if ret < 0 {
	fmt.println("Failed to load sections")
	return
    }
    
    fmt.println("Binary loaded")

    n_secs := len(bin.sections)

    code : string

    i : int
    
    for i = 0; i < n_secs; i+=1 {

	if bin.sections[i].type == section_type.SEC_TYPE_CODE {
	    code = "CODE"
	}
	else {
	    code = "DATA"
	}

	fmt.printf("0x%016x %d %s %s\n", bin.sections[i].vma, bin.sections[i].size, bin.sections[i].name, code)

    }

    n_syms := len(bin.symbols)

    for i = 0; i < n_syms; i+=1 {

	if bin.symbols[i].type == .SYM_TYPE_FUNC {
	    code = "FUNC"
	}
	else {
	    code = ""
	}
	
	fmt.printf("%s 0x%016x %s\n", bin.symbols[i].name, bin.symbols[i].addr, code)
	
    }


    // Loaded binary, now do disassembly

    disasm(&bin)
    
}

