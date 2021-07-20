import idautils
import idc
import idaapi
import yaml

from math import floor
from time import time, strftime, gmtime

MAX_SIG_LENGTH = 512

FUNCS_SEGSTART = 0
FUNCS_SEGEND = None

# Change to 1 to have a very optimized makesig
# Will produce useable signatures but theyll be a bit more volatile
# since they rely on the position of the function in the binary
# Uses the end of the function to search compared to the end of the .text segment
ABSOLUTE_OPTIMIZATION = 0

def get_dt_size(dtype):
	if dtype == ida_ua.dt_byte:
		return 1
	elif dtype == ida_ua.dt_word:
		return 2
	elif dtype == ida_ua.dt_dword:
		return 4
	elif dtype == ida_ua.dt_float:
		return 4
	elif dtype == ida_ua.dt_double:
		return 8
	else:
		print("Unknown type size (%d)" % dtype)
		return -1

def print_wildcards(count):
	return "? " * count

def is_good_sig(sig, funcend):
	endea = funcend if ABSOLUTE_OPTIMIZATION else FUNCS_SEGEND
	count = 0
	addr = FUNCS_SEGSTART	# Linux has a .LOAD section in front
							# The odds of this having matching bytes are about 0
							# so let's just skip it, would save a lot of time
	addr = ida_search.find_binary(addr, endea, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	while count < 2 and addr != idc.BADADDR:
		count = count + 1
		addr = ida_search.find_binary(addr, endea, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)

	return count == 1

def makesig(func):
	sig = ""
	found = 0
	funcstart = func.start_ea
	funcend = func.end_ea
	done = 0
	global MAX_SIG_LENGTH

	addr = funcstart
	while addr != idc.BADADDR:
		info = ida_ua.insn_t()
		if not ida_ua.decode_insn(info, addr):
			return None

		done = 0
		if info.Op1.type == ida_ua.o_near or info.Op1.type == ida_ua.o_far:
			if (idc.get_wide_byte(addr)) == 0x0F: 	# Two-byte instruction
				sig = sig + ("0F %02X " % idc.get_wide_byte(addr + 1)) + print_wildcards(get_dt_size(info.Op1.dtype))
			else:
				sig = sig + ("%02X " % idc.get_wide_byte(addr)) + print_wildcards(get_dt_size(info.Op1.dtype))
			done = 1

		if not done: 	# Unknown, just wildcard addresses
			i = 0
			size = idc.get_item_size(addr)
			while 1:	# Screw u python
				loc = addr + i
				if ((idc.get_fixup_target_type(loc) & 0xF) == ida_fixup.FIXUP_OFF32):
					sig = sig + print_wildcards(4)
					i = i + 3
				else:
					sig = sig + ("%02X " % idc.get_wide_byte(loc))

				i = i + 1

				if i >= size:
					break

		# Escape the evil functions that break everything
		if len(sig) > MAX_SIG_LENGTH:
			return "Signature is too long!"
		# Save milliseconds and only check for good sigs after a fewish bytes
		# Trust me, it matters
		elif sig.count(" ") >= 5 and is_good_sig(sig, funcend):
			found = 1
			break

		addr = idc.next_head(addr, funcend)

	if found == 0:
		return "Ran out of bytes!"

	l = len(sig) - 1
	smsig = r"\x"
	for i in range(l):
		c = sig[i]
		if c == " ":
			smsig = smsig + r"\x"
		elif c == "?":
			smsig = smsig + "2A"
		else:
			smsig = smsig + c

	return smsig

UPDATE_TIME = time()
def update_window(activity):
	global UPDATE_TIME
	currtime = time()
	if currtime - UPDATE_TIME > 0.2:
		UPDATE_TIME = currtime
		ida_kernwin.replace_wait_box(activity)

def calc_func_segments():
	global FUNCS_SEGSTART, FUNCS_SEGEND
	seg = ida_segment.get_segm_by_name(".text")
	if seg:
		FUNCS_SEGSTART = seg.start_ea
		FUNCS_SEGEND = seg.end_ea

def main():
	ida_auto.set_ida_state(ida_auto.st_Work)
	root = {}

	count = 0
	sigcount = 0
	sigattempts = 0

	calc_func_segments()

	funcs = list(idautils.Functions(FUNCS_SEGSTART, FUNCS_SEGEND))

	alltime = 0.0
	avgtime = 0.0

	f = ida_kernwin.ask_file(1, "*.yml", "Choose a file to save to")
	if not f:
		return

	skip = ida_kernwin.ask_yn(1, "Skip functions that start with \"sub_\"?")
	if skip == -1:
		return

	# Clean up and get rid of shitty funcs
	funccpy = funcs[:]
	for fea in funccpy:
		funcname = ida_funcs.get_func_name(fea)
		if funcname is None or funcname.startswith("nullsub"):
			funcs.remove(fea)
			continue

		if skip and funcname.startswith("sub"):
			funcs.remove(fea)
			continue			

		flags = idc.get_func_attr(fea, FUNCATTR_FLAGS)
		if flags & ida_funcs.FUNC_LIB:
			funcs.remove(fea)
			continue

	funccount = len(funcs)
	for fea in funcs:
		starttime = time()

		func = idaapi.get_func(fea)
		funcname = ida_funcs.get_func_name(fea)
		if funcname != None:
			unmangled = idc.demangle_name(funcname, idc.get_inf_attr(idc.INF_SHORT_DN))
			if unmangled is None:
				unmangled = funcname

			sig = makesig(func)
			sigattempts += 1
			root[unmangled] = {"mangled": funcname, "signature": sig}

			if sig:
				sigcount += (0 if "!" in sig else 1)

		# Only ETA makesig() attempts, otherwise the timing is really off
		# Unfortunately, sigging takes progressively longer the further along the function list
		# this goes, as makesig() searches from up to down while functions are ordered from up to down
		# So this isn't really accurate but w/e

		multpct = 2.0 - count / float(funccount)	# Scale up a bit the lower we start at the get a halfass decent eta
		alltime += time() - starttime
		avgtime = alltime / sigattempts
		eta = int(avgtime * (funccount - count) * multpct)
		etastr = strftime("%H:%M:%S", gmtime(eta))

		count += 1
		update_window("Evaluated {} out of {} ({}%)\nETA: {}".format(count, funccount, floor(count / float(funccount) * 100.0 * 10.0) / 10.0, etastr))

	while f.count(".yml") >= 2:
		f = f.replace(".yml", "", 1)
	if not f.endswith(".yml"):
		f += ".yml"

	with open(f, "w") as f:
		yaml.safe_dump(root, f, default_flow_style = False, width = 999999)

	ida_kernwin.hide_wait_box()
	print("Successfully generated {} signatures from {} functions".format(sigcount, funccount))

	ida_auto.set_ida_state(ida_auto.st_Ready)

if __name__ == "__main__":
	main()