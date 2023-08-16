import idc
import idaapi
import idautils

def getsigloc(sig):
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
			break

	count = 0
	first = idaapi.find_binary(0, endea, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	addr = first
	while addr != idc.BADADDR:
		count = count + 1
		addr = idaapi.find_binary(addr, endea, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	
	return first, count

	# binpat = idaapi.compiled_binpat_vec_t()
	# # This returns false but it works?
	# idaapi.parse_binpat_str(binpat, segstart, sig, 16, idaapi.get_default_encoding_idx(idaapi.get_encoding_bpu_by_name("UTF-8")))
	# addr, _ = idaapi.bin_search3(0, endea, binpat, idaapi.BIN_SEARCH_FORWARD)
	# return addr


def main():
	bytesig = idaapi.ask_str("", 0, "Insert signature: ")
	if bytesig is None:
		return

	sig = bytesig.replace(r"\x", " ").replace("2A", "?").replace("2a", "?").strip()

	loc, count = getsigloc(sig)
	if loc != idc.BADADDR:
		idaapi.jumpto(loc)
		if count > 1:
			print(f"Found {count} instances of signature. Jumping to first at {loc:#X}")
	else:
		# Beep, nothing found
		idaapi.beep()

main()