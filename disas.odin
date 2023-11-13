package binary

import "core:fmt"
import "core:slice"

import cap "./odin-capstone"

recursive_disasm :: proc(bin: ^Binary) {

    fmt.println("Recursive")

    dis : cap.csh
    insns : ^cap.cs_insn
    cs_ins : ^cap.cs_insn
    text : ^Section
    addr : u64
    err : cap.cs_err
    n : u32
    i : u32
    Q : [dynamic]u64 // could use actual Queue in the future
    
    text = get_text_section(bin)

    if text == nil {
	fmt.println("No text section")
	return
    }

    fmt.println(text.name, text.vma, text.size)

    err = cap.cs_open(cap.cs_arch.CS_ARCH_X86, cap.cs_mode.CS_MODE_64, &dis)
    defer cap.cs_close(&dis)
    
    fmt.println(err)
    fmt.println(dis)

    cap.cs_option(dis, cap.cs_opt_type.CS_OPT_DETAIL, cap.cs_opt_value.CS_OPT_ON)

    cs_ins = cap.cs_malloc(dis)

    if cs_ins == nil {
	fmt.println("Out of memory")
	return
    }
    
    addr = bin.entry
    fmt.println("start = ", addr)

    if contains(text, addr) {
	fmt.println("In text")
	append(&Q, addr)
    }

    for sym in bin.symbols {
	if sym.type == .SYM_TYPE_FUNC && contains(text, sym.addr) {
	    append(&Q, sym.addr)
	    fmt.println(sym)
	}
    }

    for len(Q) != 0 {
	addr = pop_front(&Q)
	fmt.println(addr)
	
    }
    
}

disasm :: proc(bin: ^Binary) {

    dis : cap.csh
    insns : ^cap.cs_insn
    text : ^Section
    err : cap.cs_err
    n : u32
    i : u32
    
    text = get_text_section(bin)

    if text == nil {
	fmt.println("No text section")
	return
    }

    fmt.println(text.name, text.vma, text.size)

    err = cap.cs_open(cap.cs_arch.CS_ARCH_X86, cap.cs_mode.CS_MODE_64, &dis)

    fmt.println(err)
    fmt.println(dis)

    n = cap.cs_disasm(dis, &text.bytes[0], u32(text.size), text.vma, 0, &insns)

    fmt.println(n)

    the_insns : []cap.cs_insn = slice.from_ptr(insns, int(n))
    
    for i = 0; i < n; i+=1 {

	fmt.printf("0x%016x: ", the_insns[i].address)

	j : u16

	for j = 0; j < 16; j+=1 {
	    if j < the_insns[i].size {
		fmt.printf("%02x ", the_insns[i].bytes[j])
	    }
	    else {
		fmt.printf(" ")
	    }
	}
	fmt.printf("%s %s\n", the_insns[i].mnemonic, the_insns[i].op_str)
    }

    fmt.println("")

    return
}
