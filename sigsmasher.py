import idautils
import idc
import idaapi
import yaml
import time

from math import floor

MAX_SIG_LENGTH = 512

# Change to 1 to have a very optimized makesig
# Will produce useable signatures but theyll be a bit more volatile
# since they rely on the position of the function in the binary
# Uses the end of the function to search compared to the end of the .text segment
ABSOLUTE_OPTIMIZATION = 0

# Write-only trie for signatures
# This is slightly faster than constantly running search_binary as 
# common signature prologues will be caught early and more quickly
class Trie(object):
	def __init__(self):
		self.root = {}

	def add(self, data):
		node = self.root
		for d in data:
			if d not in node:
				node[d] = {}
			node = node[d]

	def find(self, data):
		node = self.root
		for d in data:
			if d not in node:
				return False
			node = node[d]
		return True

	def __contains__(self, data):
		return self.find(data)
	
TRIE = Trie()

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

FUNCS_SEGEND = idc.BADADDR
def calc_sigstop():
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

	return endea

def is_good_sig(sig, funcend):
	if sig in TRIE:
		return False
	
	bytesig = " ".join(sig)

	endea = funcend if ABSOLUTE_OPTIMIZATION else FUNCS_SEGEND
	count = 0
	addr = 0
	addr = idaapi.find_binary(addr, endea, bytesig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	while count < 2 and addr != idc.BADADDR:
		count = count + 1
		addr = idaapi.find_binary(addr, endea, bytesig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)

	# Good sig, add it to the trie
	if count == 1:
		TRIE.add(sig)
		return True

	return False

def makesigfast(func):
	addr = func.start_ea
	found = 0

	sig = []
	while addr != idc.BADADDR:
		info = idaapi.insn_t()
		if not idaapi.decode_insn(info, addr):
			return None

		done = 0
		if info.Op1.type in (idaapi.o_near, idaapi.o_far):
			insnsz = 2 if idaapi.get_byte(addr) == 0x0F else 1
			sig += [f"{idaapi.get_byte(addr+i):02X}" for i in range(insnsz)] + ["?"] * (info.size - insnsz)
			done = 1
		elif info.Op1.type == idaapi.o_reg and info.Op2.type == idaapi.o_mem and info.Op2.addr != idc.BADADDR:
			sig += [f"{idaapi.get_byte(addr+i):02X}" for i in range(info.Op2.offb)] + ["?"] * (info.size - info.Op2.offb)
			done = 1

		if not done: 	# Unknown, just wildcard addresses
			i = 0
			while i < info.size:
				loc = addr + i
				if ((idc.get_fixup_target_type(loc) & 0x0F) == idaapi.FIXUP_OFF32):
					sig += ["?"] * 4
					i += 3
				elif (idc.get_fixup_target_type(loc) & 0x0F) == idaapi.FIXUP_OFF64:
					sig += ["?"] * 8
					i += 7
				else:
					sig += [f"{idaapi.get_byte(addr+i):02X}"]

				i += 1

		# Escape the evil functions that break everything
		if len(sig) > MAX_SIG_LENGTH:
			return "Signature is too long!"
		# Save milliseconds and only check for good sigs after a fewish bytes
		# Trust me, it matters
		elif len(sig) >= 5 and is_good_sig(sig, func.end_ea):
			found = 1
			break

		addr = idc.next_head(addr, func.end_ea)

	if found == 0:
		return "Ran out of bytes!"

	smsig = r"\x" + r"\x".join(sig)
	smsig = smsig.replace("?", "2A")
	return smsig

def main():
	try:
		root = {}

		f = idaapi.ask_file(1, "*.yml", "Choose a file to save to")
		if not f:
			return

		skip = idaapi.ask_yn(1, "Skip unnamed functions (e.g. ones that start with \"sub_\")?")
		if skip == -1:
			return

		idaapi.set_ida_state(idaapi.st_Work)
		global FUNCS_SEGEND
		FUNCS_SEGEND = calc_sigstop()

		funcs = list(idautils.Functions())
		siglist = []

		for i in range(len(funcs)):
			fea = funcs[i]
			flags = idaapi.get_full_flags(fea)
			if not idaapi.is_func(flags):
				continue

			if skip and not idaapi.has_name(flags):
				continue

			func = idaapi.get_func(fea)
			# Thunks and lib funcs
			if func.flags & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK):
				continue

			funcname = idaapi.get_name(fea)
			unmangled = idaapi.demangle_name(funcname, idaapi.MNG_SHORT_FORM)
			if unmangled is not None:
				# Skip jmp stubs
				if unmangled.startswith("j_"):
					continue

				# Nullsub
				if unmangled.startswith("nullsub"):
					continue

			siglist.append(func)

		totalcount = len(siglist)
		actualstarttime = time.time()
		sigcount = 0
		for i, func in enumerate(siglist):
			funcname = idaapi.get_name(func.start_ea)
			unmangled = idaapi.demangle_name(funcname, idaapi.MNG_SHORT_FORM)
			if unmangled is None:
				unmangled = funcname

			sig = makesigfast(func)
			root[unmangled] = {"mangled": funcname, "signature": sig}

			if sig:
				sigcount += (0 if "!" in sig else 1)

			# Unfortunately, sigging takes progressively longer the further along the function list
			# this goes, as makesig() searches from top to bottom while functions are ordered from top to bottom
			# So this isn't really accurate but w/e

			totaltime = time.time() - actualstarttime
			count = i + 1
			avgtime = totaltime / count
			eta = int(avgtime * (totalcount - count))
			etastr = time.strftime("%H:%M:%S", time.gmtime(eta))

			WaitBox.show(f"Evaluated {count} out of {totalcount} ({floor(i / float(totalcount) * 100.0 * 10.0) / 10.0}%)\nETA: {etastr}")

		WaitBox.show("Saving to file")
		with open(f, "w") as f:
			yaml.safe_dump(root, f, default_flow_style=False, width=999999)

		totaltime = time.strftime("%H:%M:%S", time.gmtime(time.time() - actualstarttime))
		print(f"Successfully generated {sigcount} signatures from {totalcount} functions in {totaltime}")
	except:
		import traceback
		traceback.print_exc()
		print("Please file a bug report with supporting information at https://github.com/Scags/IDA-Scripts/issues")
		idaapi.beep()

	idaapi.set_ida_state(idaapi.st_Ready)
	WaitBox.hide()

# import cProfile
# cProfile.run("main()", "sigsmasher.prof")
main()
