import idc
import idaapi

def main():
	addr = idc.get_screen_ea()
	funcstart = idc.get_func_attr(addr, idc.FUNCATTR_START)
	if addr == idc.BADADDR or funcstart == idc.BADADDR:
		print("Make sure you are in a function!")
		return

	print("Offset from %X to %X:\n%d (0x%X)" % (funcstart, addr, addr - funcstart, addr - funcstart))

main()