package binary

import "core:fmt"
import "core:slice"

import cap "./odin-capstone"

print_ins :: proc(ins : ^cap.cs_insn) {

    fmt.printf("0x%016x: ", ins.address)
    
    j : u16
    
    for j = 0; j < 16; j+=1 {
	if j < ins.size {
	    fmt.printf("%02x ", ins.bytes[j])
	}
	else {
	    fmt.printf(" ")
	}
    }
    fmt.printf("%s %s\n", ins.mnemonic, ins.op_str)
    
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
    seen : map[u64]bool
    
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
	
	if addr in seen {
	    continue
	}

	offset := addr - text.vma
	pc := text.bytes[offset:]
	n := text.size - offset

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

		if target != 0 && !(addr in seen) && contains(text, target) {
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

    cap.cs_free(cs_ins, 1)
    cap.cs_close(&dis)
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
