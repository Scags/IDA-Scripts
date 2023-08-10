import idc
import idaapi
import idautils

def main():
	bytesig = idaapi.ask_str("", 0, "Insert signature: ")

	sig = bytesig.replace(r"\x", " ").replace("2A", "?").replace("2a", "?").strip()

	count = checksig(sig)
	if not count:
		print(r"INVALID: {}".format(bytesig))
		print("Could not find any matching signatures for input")
	elif count == 1:
		print(r"VALID: {}".format(bytesig))
	else:
		print(r"INVALID: {}".format(bytesig))
		print("Found {} instances of input signature".format(count))

def checksig(sig):
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
	addr = 0
	addr = idaapi.find_binary(addr, endea, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	while addr != idc.BADADDR:
		count = count + 1
		addr = idaapi.find_binary(addr, endea, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)

	return count

	# bin_search3 breaks after 15 or so bytes or something, idk man
	# binpat = idaapi.compiled_binpat_vec_t()
	# idaapi.parse_binpat_str(binpat, segstart, sig, 16, idaapi.get_default_encoding_idx(idaapi.get_encoding_bpu_by_name("UTF-8")))

	# count = 0
	# addr = 0
	# addr, _ = idaapi.bin_search3(addr, endea, binpat, idaapi.BIN_SEARCH_FORWARD)
	# while addr != idc.BADADDR:
	# 	count += 1

	# 	# +1 because the search finds itself
	# 	addr, _ = idaapi.bin_search3(addr + 1, endea, binpat, idaapi.BIN_SEARCH_FORWARD)

	# return count

main()