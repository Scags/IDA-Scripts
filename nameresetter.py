import idc
import idautils
import idaapi

def main():
	segstart = 0
	segend = None

	segm = idaapi.get_segm_by_name(".text")
	if segm:
		segstart = segm.start_ea
		segend = segm.end_ea

	for fea in idautils.Functions(segstart, segend):
		flags = idc.get_func_attr(fea, idc.FUNCATTR_FLAGS)
		if flags & idaapi.FUNC_LIB:
			continue

		idc.set_name(fea, "")

main()