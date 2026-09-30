INCLUDE generated/output_format.ld
ENTRY(_start)

__DYNAMIC = 0;

INCLUDE generated/regions.ld

_stack_size = DEFINED(_stack_size) ? _stack_size : 500k;
_heap_size  = DEFINED(_heap_size)  ? _heap_size  : 500k;

SECTIONS
{
	.text :
	{
		_ftext = .;
		*crt0*(.text)
		KEEP(*crt0*(.text))
		KEEP(*(.text.isr))
		*(.text .stub .text.* .gnu.linkonce.t.*)
		KEEP(*(.init))
		KEEP(*(.init_array .ctors .ctors.*))
		_etext = .;
	} > main_ram

	.rodata :
	{
		. = ALIGN(8);
		_frodata = .;
		*(.rodata .rodata.* .srodata .srodata.* .gnu.linkonce.r.*)
		*(.rodata1)
		*(.got .got.*)
		*(.toc .toc.*)
		. = ALIGN(8);
		_erodata = .;
	} > main_ram

	.data :
	{
		. = ALIGN(8);
		_fdata = .;
		*(.data .data.* .gnu.linkonce.d.*)
		*(.data1)
		_gp = ALIGN(16);
		*(.sdata .sdata.* .gnu.linkonce.s.*)
		. = ALIGN(8);
		_edata = .;
	} > main_ram

	.bss :
	{
		. = ALIGN(8);
		_fbss = .;
		*(.dynsbss)
		*(.sbss .sbss.* .gnu.linkonce.sb.*)
		*(.scommon)
		*(.dynbss)
		*(.bss .bss.* .gnu.linkonce.b.*)
		*(COMMON)
		. = ALIGN(8);
		_ebss = .;
		__end = .;
	} > main_ram

	._user_heap (NOLOAD) :
	{
		. = ALIGN(8);
		__heap_start = .;
		. = . + _heap_size;
		. = ALIGN(8);
		__heap_end = .;
	} > main_ram

	/* Stack placed safely at 32MB offset in main_ram */
	__stack_end = ORIGIN(main_ram) + 0x02000000;
	__stack_start = __stack_end - _stack_size;

	._stack (NOLOAD) :
	{
		. = ALIGN(16);
	} > main_ram
}

PROVIDE(_fstack = __stack_end);
PROVIDE(_fdata_rom = LOADADDR(.data));
PROVIDE(_edata_rom = LOADADDR(.data) + SIZEOF(.data));
