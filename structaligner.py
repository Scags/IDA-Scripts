import idc
import idautils
import idaapi

from time import time
from math import floor

UPDATE_TIME = time()
def update_window(s):
	global UPDATE_TIME
	currtime = time()
	if currtime - UPDATE_TIME > 0.2:
		idaapi.replace_wait_box(s)
		UPDATE_TIME = currtime

def main():
	maxstructs = idaapi.get_last_struc_idx()
	i = idaapi.get_first_struc_idx()
	while i < maxstructs:
		update_window("{}%".format(floor(i / float(maxstructs) * 100.0 * 10.0) / 10.0))
		strucid = idaapi.get_struc_by_idx(i)
		struc = idaapi.get_struc(strucid)
		k = 0
		struclen = idaapi.get_max_offset(struc)
		while k < struclen:
			member = idaapi.get_member(struc, k)
			if not member:
				idaapi.add_struc_member(struc, "field_{}".format(hex(k)[2:].upper()), k, idc.FF_BYTE, None, 1)
				k += 1
			else:
				k += idaapi.get_member_size(member)

		i += 1

main()