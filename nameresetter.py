import idc
import idautils
import idaapi

def main():
	count = 0
	for segstart in idautils.Segments():
		segend = idaapi.getseg(segstart).end_ea
		for fea in idautils.Functions(segstart, segend):
			flags = idaapi.get_full_flags(fea)
			if not (flags & idaapi.FF_NAME):
				continue

			fflags = idc.get_func_attr(fea, idc.FUNCATTR_FLAGS)
			if fflags & idaapi.FUNC_LIB:
				continue

			if idc.set_name(fea, ""):
				count += 1
	
	print(f"Successfully renamed {count} functions")

main()