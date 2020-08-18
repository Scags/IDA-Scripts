import idc
import idautils
import idaapi

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

def is_good_sig(sig):
	count = 0
	addr = 0
	addr = idc.find_binary(addr, idc.SEARCH_DOWN|idc.SEARCH_NEXT, sig)
	while count <= 2 and addr != idc.BADADDR:
		count = count + 1
		addr = idc.find_binary(addr, idc.SEARCH_DOWN|idc.SEARCH_NEXT, sig)

	return count == 1

def makesig():
	addr = idc.get_screen_ea()
	addr = idc.get_func_attr(addr, idc.FUNCATTR_START)
	funcstart = addr
	if addr == idc.BADADDR:
		print("Make sure you are in a function!")
		return

	name = idc.get_name(addr, ida_name.GN_VISIBLE);
	funcend = idc.get_func_attr(addr, idc.FUNCATTR_END);

	sig = ""
	found = 0
	done = 0

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

		if (is_good_sig(sig)):
			found = 1
			break

		addr = idc.next_head(addr, funcend)

	if found is 0:
		print(sig)
		print("Ran out of bytes to create unique signature.");
		return None

	l = len(sig) - 1
	smsig = r"\x"
	for i in xrange(l):
		c = sig[i]
		if c == " ":
			smsig = smsig + r"\x"
		elif c == "?":
			smsig = smsig + "2A"
		else:
			smsig = smsig + c

	print("Signature for %s:\n%s\n%s\n" % (name, sig, smsig));
	return smsig

def main():
	makesig()

if __name__ == "__main__":
	main()