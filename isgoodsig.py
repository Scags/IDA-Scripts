import idc
import idaapi

FUNCS_SEGEND = idaapi.get_segm_by_name(".text").end_ea

def main():
	sig = idaapi.ask_str("", 0, "Insert signature: ")

	# wtfwtfwtfwtf
	oldsig = sig
	sig = sig.replace(r"\x", " ").replace("2A", "?").replace("2a", "?").strip()
#	print(sig)

	count = checksig(sig)
	if not count:
		print(r"INVALID: {}".format(oldsig))
		print("Could not find any matching signatures for input")
	elif count == 1:
		print(r"VALID: {}".format(oldsig))
	else:
		print(r"INVALID: {}".format(oldsig))
		print("Found {} instances of input signature".format(count))

def checksig(sig):
	count = 0
	addr = 0
	addr = idaapi.find_binary(addr, FUNCS_SEGEND, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	while addr != idc.BADADDR:
		count = count + 1
		addr = idaapi.find_binary(addr, FUNCS_SEGEND, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)

	return count

main()