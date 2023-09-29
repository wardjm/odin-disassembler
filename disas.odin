package binary

import "core:fmt"

import cap "./odin-capstone"

disasm :: proc(bin: ^Binary) {

    dis : cap.csh
    insns : ^cap.cs_insn
    text : ^Section

    text = get_text_section(bin)

    if text == nil {
	fmt.println("No text section")
	return
    }

    fmt.println(text.name, text.vma)
    
    fmt.println("in")
    return
}
