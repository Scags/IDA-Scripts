import idc
import idautils
import idaapi

def get_dt_size(dtype):
	return {
		idaapi.dt_byte: 1,
		idaapi.dt_word: 2,
		idaapi.dt_dword: 4,
		idaapi.dt_float: 4,
		idaapi.dt_double: 8,
	}.get(dtype, -1)

def print_wildcards(count):
	return "?" * count

def is_good_sig(sig, mask):
	search = " ".join('?' if m == '?' else b for b, m in zip(sig.strip().split(), mask))

	# Get the first segment that is executable to use its addresses for parse_binpat_str
	endea = idc.BADADDR
	for segea in idautils.Segments():
		s = idaapi.getseg(segea)
		if s.perm & idaapi.SEGPERM_EXEC:
			segstart = segea
			# Set the end ea to the end of the last executable segment
			# Speed isn't as important in this script, so reading any extra X
			# segments is fine
			if endea == idc.BADADDR or endea < segstart + s.size():
				endea = segstart + s.size()

	count = 0
	addr = 0
	addr = idaapi.find_binary(addr, endea, search, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	while addr != idc.BADADDR:
		count = count + 1
		if count > 1:
			break
		addr = idaapi.find_binary(addr, endea, search, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)

	return count == 1

	# binpat = idaapi.compiled_binpat_vec_t()
	# idaapi.parse_binpat_str(binpat, segstart, search, 16, idaapi.get_encoding_bpu_by_name("UTF-8"))

	# count = 0
	# addr = 0
	# addr, _ = idaapi.bin_search3(addr, endea, binpat, idaapi.BIN_SEARCH_FORWARD)

	# while addr != idc.BADADDR:
	# 	count += 1
	# 	if count > 1:
	# 		break

	# 	# +1 because the search finds itself
	# 	addr, _ = idaapi.bin_search3(addr + 1, endea, binpat, idaapi.BIN_SEARCH_FORWARD)
	

	# return count == 1

def makesig(ea, sz=-1):
	func = idaapi.get_func(ea)
	name = idc.get_name(func.start_ea, idaapi.GN_VISIBLE)

	sig = ""
	mask = ""
	found = 0
	done = 0

	addr = ea
	end = ea + sz if sz != -1 else idc.BADADDR
	while addr != idc.BADADDR and (sz == -1 or addr < ea + sz):
		info = idaapi.insn_t()
		if not idaapi.decode_insn(info, addr):
			print(f"Failed to decode instruction at {addr:#X}?")
			idaapi.beep()
			return

		sig += " ".join(f"{idaapi.get_byte(addr+i):02X}" for i in range(info.size)) + " "

		done = 0
		if info.Op1.type in (idaapi.o_near, idaapi.o_far):
			insnsz = 2 if idaapi.get_byte(addr) == 0x0F else 1
			mask += f"{'x' * insnsz}{print_wildcards(info.size - insnsz)}"
			done = 1
		elif info.Op1.type == idaapi.o_reg and info.Op2.type == idaapi.o_mem and info.Op2.addr != idc.BADADDR:
			mask += f"{'x' * info.Op2.offb}{print_wildcards(info.size - info.Op2.offb)}"
			done = 1

		if not done: 	# Unknown, just wildcard addresses
			i = 0
			while i < info.size:
				loc = addr + i
				if ((idc.get_fixup_target_type(loc) & 0x0F) == idaapi.FIXUP_OFF32):
					mask += print_wildcards(4)
					i += 3
				elif (idc.get_fixup_target_type(loc) & 0x0F) == idaapi.FIXUP_OFF64:
					mask += print_wildcards(8)
					i += 7
				else:
					mask += 'x'

				i += 1

		if is_good_sig(sig, mask):
			found = 1
			break

		addr = idaapi.next_head(addr, end)

	if found == 0:
		print(sig)
		print("Ran out of bytes to create unique signature.")
		idaapi.beep()
		return

	sig = sig.strip()
	csig = r"\x" + sig.replace(" ", r"\x")

	align = len("Wildcarded Bytes: ")
	wildcarded = f"{'Wildcarded Bytes:':<{align}} {' '.join('?' if m == '?' else b for b, m in zip(sig.split(), mask))}\n" if "?" in mask else ""
	smsig = r"\x" + r"\x".join("2A" if m == "?" else b for b,
	                           m in zip(sig.split(), mask))

	print("==================================================")
	print(
		f"Signature for {name} + {ea - func.start_ea} ({ea - func.start_ea:#x}):\n"
		f"{'Mask:':<{align}} {mask}\n"
		f"{'Bytes:':<{align}} {sig}\n"
		f"{wildcarded}"
		f"{'Byte String:':<{align}} {csig}\n"
		f"{'SourceMod':<{align}} {smsig}"
	)

	try:
		import pyperclip
		pyperclip.copy(smsig)
		print(f"SourceMod signature copied to clipboard")
	except:
		print("'pip install pyperclip' to automatically copy the SourceMod signature to your clipboard")
	return csig

def main():
	ea = idaapi.get_screen_ea()
	func = idaapi.get_func(ea)
	if ea == idc.BADADDR or func is None:
		print("Make sure you are in a function!")
		idaapi.beep()
		return
	
	sz = func.end_ea - ea

	makesig(ea, sz)

main()