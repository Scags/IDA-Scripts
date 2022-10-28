import idc
import idaapi

def getsigloc(sig):
	segend = idaapi.get_segm_by_name(".text").end_ea
	addr = idaapi.find_binary(0, segend, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	return addr

sig = idaapi.ask_str("", 0, "Insert signature: ")

oldsig = sig
sig = sig.replace(r"\x", " ").replace("2A", "?").replace("2a", "?").strip()

def main():
	loc = getsigloc(sig)
	if loc != idc.BADADDR:
		idaapi.jumpto(loc)
