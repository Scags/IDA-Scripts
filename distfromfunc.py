import idc
import idaapi

def main():
	addr = idaapi.get_screen_ea()
	if addr == idc.BADADDR:
		print("Make sure you are in a function!")
		idaapi.beep()
		return

	func = idaapi.get_func(addr)
	if func is None:
		print("Make sure you are in a function!")
		idaapi.beep()
		return
	
	funcname = idaapi.get_name(func.start_ea)
	demangled = idaapi.demangle_name(funcname, idc.get_inf_attr(idc.INF_SHORT_DN))
	print(f"{demangled or funcname}:")
	print(f"Offset from {func.start_ea:08X} to {addr:08X} = {addr - func.start_ea} ({addr - func.start_ea:#X})")

main()