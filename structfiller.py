import idc
import idautils
import idaapi
import time

from math import floor

# Idiot proof IDA wait box
class WaitBox:
	buffertime = 0.0
	shown = False
	msg = ""

	@staticmethod
	def _show(msg):
		WaitBox.msg = msg
		if WaitBox.shown:
			idaapi.replace_wait_box(msg)
		else:
			idaapi.show_wait_box(msg)
			WaitBox.shown = True

	@staticmethod
	def show(msg, buffertime=0.1):
		if msg == WaitBox.msg:
			return

		if buffertime > 0.0:
			if time.time() - WaitBox.buffertime < buffertime:
				return
			WaitBox.buffertime = time.time()
		WaitBox._show(msg)

	@staticmethod
	def hide():
		if WaitBox.shown:
			idaapi.hide_wait_box()
			WaitBox.shown = False

def main():
	try:
		idaapi.begin_type_updating(idaapi.UTP_STRUCT)
		maxstructs = idaapi.get_struc_qty()
		i = idaapi.get_first_struc_idx()
		while i < maxstructs:
			WaitBox.show(f"{floor(i / float(maxstructs) * 100.0 * 10.0) / 10.0}%")
			strucid = idaapi.get_struc_by_idx(i)
			struc = idaapi.get_struc(strucid)
			k = 0
			struclen = idaapi.get_max_offset(struc)
			while k < struclen:
				member = idaapi.get_member(struc, k)
				if not member:
					idaapi.add_struc_member(struc, f"field_{k:X}", k, idc.FF_BYTE, None, 1)
					k += 1
				else:
					k += idaapi.get_member_size(member)

			i += 1

		print("Done!")
	except:
		import traceback
		traceback.print_exc()
		print("Please file a bug report with supporting information at https://github.com/Scags/IDA-Scripts/issues")
		idaapi.beep()

	WaitBox.hide()
	idaapi.end_type_updating(idaapi.UTP_STRUCT)

main()