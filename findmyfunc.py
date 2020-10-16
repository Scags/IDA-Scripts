import idc
import idaapi

def getsigloc(sig):
	segend = ida_segment.get_segm_by_name(".text").end_ea
	addr = ida_search.find_binary(0, FUNCS_SEGEND, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	return addr

def main():
	sig = ida_kernwin.ask_str("", 0, "Insert signature: ")

	oldsig = sig
	sig = sig.replace(r"\x", " ").replace("2A", "?").replace("2a", "?").strip()

	loc = getsigloc(sig)
	if loc != idc.BADADDR:
		ida_kernwin.jumpto(loc)

if __name__ == "__main__":
	main()