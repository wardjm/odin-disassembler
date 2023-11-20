package binary

import "core:fmt"
import "core:slice"
import "core:strings"

import cap "./odin-capstone"

print_ins :: proc(ins : ^cap.cs_insn) {

    fmt.printf("0x%016x: ", ins.address)
    
    j : u16
    
    for j = 0; j < 16; j+=1 {
	if j < ins.size {
	    fmt.printf("%02x ", ins.bytes[j])
	}
	else {
	    fmt.printf("   ")
	}
    }
    
    str1 : cstring = cstring(raw_data(ins.mnemonic[:]))
    str2 : cstring = cstring(raw_data(ins.op_str[:]))

    fmt.println(str1, str2)
    
}

is_cs_cflow_ins :: proc(ins : ^cap.cs_insn) -> bool {

    i : u8

    for i = 0; i < ins.detail.groups_count; i += 1 {
	if is_cs_cflow_group(ins.detail.groups[i]) {
	    return true
	}
    }
    
    return false
    
}

is_cs_cflow_group :: proc(g : u8) -> bool {

    if g == u8(cap.cs_group_type.CS_GRP_JUMP) || g == u8(cap.cs_group_type.CS_GRP_CALL) || g == u8(cap.cs_group_type.CS_GRP_RET) || g == u8(cap.cs_group_type.CS_GRP_IRET) {
	return true
    }

    return false
}

get_cs_ins_immediate_target :: proc(ins : ^cap.cs_insn) -> u64 {

    cs_op : ^cap.cs_x86_op

    i : u8
    j : u8
    x86 : ^cap.cs_x86
    
    for i = 0; i < ins.detail.groups_count; i += 1 {
	x86 = &ins.detail.ins_info 
	if x86 == nil {
	    return 0
	}
	
	for j = 0; j < x86.op_count; j += 1 {
	    cs_op = &x86.operands[j]
	    if cs_op.type == cap.x86_op_type.X86_OP_IMM {
		return u64(cs_op.imm)
	    }
	}
    }
    
    return 0
    
}

is_cs_unconditional_cflow_ins :: proc(ins : ^cap.cs_insn) -> bool {

    id : cap.x86_insn = cap.x86_insn(ins.id)
    
    #partial switch (id) {
	case cap.x86_insn.X86_INS_JMP, cap.x86_insn.X86_INS_LJMP, cap.x86_insn.X86_INS_RET, cap.x86_insn.X86_INS_RETF, cap.x86_insn.X86_INS_RETFQ:
	return true
	
    }
    return false
}

contains_local :: proc(vma : u64, addr : u64, size : u64) -> bool {

    if addr < vma {
	return false
    }
    if addr > vma + size {
	return false
    }
    return true

}

exists :: proc(Q : ^[dynamic]u64, test : u64) -> bool {

    for q in Q {
	if q == test {
	    return true
	}
    }
    return false
}

// Disassemble bin of length size starting at start with optional vma and symbols
// If size == 0, go until ret (for single function disassembly)
recursive_disasm_piece :: proc(bin : []u8, size : u64, start : u64, vma : u64, symbols : []Symbol) {

    dis : cap.csh
    insns : ^cap.cs_insn
    cs_ins : ^cap.cs_insn
    text : ^Section
    addr : u64
    err : cap.cs_err
    n : u32
    i : u32
    Q : [dynamic]u64 // could use actual Queue in the future
    seen : map[u64]bool
    symbol_tab : map[u64]string

    if symbols != nil {
	for s in symbols {
	    symbol_tab[s.addr] = s.name
	}
    }
    
    err = cap.cs_open(cap.cs_arch.CS_ARCH_X86, cap.cs_mode.CS_MODE_64, &dis)
    defer cap.cs_close(&dis)

    if err != cap.cs_err.CS_ERR_OK {
	fmt.println(err)
	return
    }

    err = cap.cs_option(dis, cap.cs_opt_type.CS_OPT_DETAIL, cap.cs_opt_value.CS_OPT_ON)

    if err != cap.cs_err.CS_ERR_OK {
	fmt.println(err)
	return
    }
    
    cs_ins = cap.cs_malloc(dis)
    defer cap.cs_free(cs_ins, 1)
    
    if cs_ins == nil {
	fmt.println("Out of memory")
	return
    }
    
    addr = start + vma
    
    append(&Q, addr)

    for sym in symbols {

	if sym.type == .SYM_TYPE_FUNC && contains_local(vma, sym.addr, size) {

	    if exists(&Q, sym.addr) {
		continue
	    }

	    append(&Q, sym.addr)

	    fmt.println(sym)
	}
    }

    for len(Q) != 0 {
	
	addr = pop_front(&Q)
	
	if addr in seen {
	    continue
	}

	if addr in symbol_tab {
	    fmt.println(symbol_tab[addr], ":")
	}

	offset := addr - vma
	pc := bin[offset:]
	n : u64

	if size == 0 {
	    n = u64(len(pc))
	}
	else {
	    n = size - offset
	}

	for cap.cs_disasm_iter(dis, &pc, &n, &addr, cs_ins) {
	    
	    if cs_ins.id == u32(cap.x86_insn.X86_INS_INVALID) || cs_ins.size == 0 {
		fmt.println("Bad instruction")
		break
	    }
	    
	    seen[cs_ins.address] = true

	    print_ins(cs_ins)

	    if is_cs_cflow_ins(cs_ins) {
		
		// Instruction is a jmp
		target := get_cs_ins_immediate_target(cs_ins)

		if target != 0 && !(addr in seen) && contains_local(vma, target, size) {
		    append(&Q, target)
		    fmt.printf(" --> new target: 0x%016x\n", target)
		}
		if is_cs_unconditional_cflow_ins(cs_ins) {
		    break
		}
	    }
	    else if cs_ins.id == u32(cap.x86_insn.X86_INS_HLT) {
		break
	    }
	    
	}
	fmt.println("-----------")
	
    }

}

disasm_func :: proc(bin : ^Binary, func_name : string) {

    text : ^Section

    addr : u64 = 0
    
    text = get_text_section(bin)

    if text == nil {
	fmt.println("No text section")
	return
    }

    for s in bin.symbols {
	if s.name == func_name {
	    addr = s.addr
	}
    }

    if addr == 0 {
	fmt.println("Unable to find function: ", func_name)
	return
    }

    offset := addr - text.vma

    recursive_disasm_piece(text.bytes[offset:], 0, 0, addr, bin.symbols[:])

}

recursive_disasm_bin :: proc(bin : ^Binary) {

    text : ^Section
    
    text = get_text_section(bin)

    if text == nil {
	fmt.println("No text section")
	return
    }

    start : u64 = bin.entry - text.vma
    
    recursive_disasm_piece(text.bytes[:], text.size, start, text.vma, bin.symbols[:])    

}

disasm_bin :: proc(bin: ^Binary) {

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
