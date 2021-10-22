import idc
import idautils
import idaapi
import json

from time import time
from sys import version_info

# Are we reading this DB or writing to it. Not to be confused with reading from/writing to the work file
Mode_Invalid = -1
Mode_Write = 0
Mode_Read = 1

DEBUG = 0

def get_action():
	return ida_kernwin.ask_buttons("Reading from", "Writing to", "", 0, "What action are we performing on this database?")

def get_file(action):
	forsaving, rw, s = (1, "w", "write to") if action == Mode_Read else (0, "r", "read from")
	fname = "*.json"
	f = ida_kernwin.ask_file(forsaving, fname, "Choose a file to {}".format(s))

	return open(f, rw) if f else None

# Show how many functions we've found
FOUND_FUNCS = set()
# Don't update asap as that throttles script speed, split sec is fine ig
UPDATE_TIME = time()
def update_window(activity, hidefuncs = False):
	global UPDATE_TIME
	if not hidefuncs:
		currtime = time()
		if currtime - UPDATE_TIME > 0.2:
			activity += "\nFunctions found: {}".format(len(FOUND_FUNCS))
			UPDATE_TIME = currtime
		else:
			return

	ida_kernwin.replace_wait_box(activity)

# Format:
# "String Name":
# {
# 	"_ZN8Function5Name",
# 	"_ZN8Function6Name2",
# 	etc...
# }
def build_xref_dict(strings):
	xrefs = {}
	for s in strings:
		xrefs[str(s)] = []

		for xref in idautils.XrefsTo(s.ea):
			funcname = ida_funcs.get_func_name(xref.frm)
			if funcname is None:
				continue

			node = xrefs[str(s)]
			node.append(funcname)
			xrefs[str(s)] = node

		# Empty, trash, we don't want it
		if not len(xrefs[str(s)]):
			del xrefs[str(s)]

	return xrefs

# Format:
# "_ZN8Function5Name":
# {
# 	"str1",
# 	"str2",
# 	"str1",
# }
def build_data_dict(strdict):
	funcs = {}
	for s, value in get_bcompat_iter(strdict):
		for funcname in value:
			node = funcs.get(funcname, [])
			node.append(s)
			funcs[funcname] = node
	return funcs

def read_strs(strings, file):
	update_window("Reading strings", True)
	# Build an organized dictionary of the string data we can get
	strdict = build_xref_dict(strings)
	# Then reorient it around functions, then dump it
	funcdict = build_data_dict(strdict)
	update_window("Dumping to file", True)
	# Running the script in write mode will build a similar dict then compare the two through functions
	json.dump(funcdict, file, indent = 4, sort_keys = True)

def get_bcompat_iter(d):
	return d.items() if version_info[0] >= 3 else d.iteritems()

def get_bcompat_keys(d):
	return d.keys() if version_info[0] >= 3 else d.iterkeys()

def write_exact_comp(strdict, funcdict, myfuncs):
	global FOUND_FUNCS
	update_window("Writing exact comparisons")
	count = 0

	for strippedname, strippedlist in get_bcompat_iter(strdict):
		if not ida_funcs.get_func_name(myfuncs[strippedname]).startswith("sub_"):
			continue

		possibilities = []
		strippedlist = sorted(strippedlist)
		for symname, symlist in get_bcompat_iter(funcdict):
			if strippedlist == sorted(symlist):
				possibilities.append(str(symname))
			else:
				continue

			if len(possibilities) >= 2:
				break

		if len(possibilities) != 1:
			continue

		if possibilities[0] not in FOUND_FUNCS and possibilities[0] not in myfuncs:
#			print(ida_funcs.get_func_name(myfuncs[strippedname]))
			idc.set_name(myfuncs[strippedname], possibilities[0], ida_name.SN_FORCE)
			count += 1

			FOUND_FUNCS.add(possibilities[0])
			update_window("Writing exact comparisons")
		elif DEBUG:
			print("{} is probably wrong!".format(idc.demangle_name(possibilities[0], idc.get_inf_attr(idc.INF_SHORT_DN))))

	return count

def write_simple_comp(strdict, funcdict, myfuncs, liw = True):
	global FOUND_FUNCS
	s = "symboled in stripped" if liw else "stripped in symboled"
	update_window("Writing simple comparisons ({})".format(s))
	count = 0

	for strippedname, strippedlist in get_bcompat_iter(strdict):
		if not ida_funcs.get_func_name(myfuncs[strippedname]).startswith("sub_"):
			continue

		possibilities = []
		for symname, symlist in get_bcompat_iter(funcdict):
			if liw:
				if all(val in strippedlist for val in symlist):
					possibilities.append(str(symname))
				else:
					continue
			else:
				if all(val in symlist for val in strippedlist):
					possibilities.append(str(symname))
				else:
					continue

			if len(possibilities) >= 2:
				break

		if len(possibilities) != 1:
			continue

		if possibilities[0] not in FOUND_FUNCS and possibilities[0] not in myfuncs:
			idc.set_name(myfuncs[strippedname], possibilities[0], ida_name.SN_FORCE)
			count += 1

			FOUND_FUNCS.add(possibilities[0])
			update_window("Writing simple comparisons ({})".format(s))
		elif DEBUG:
			print("{} is probably wrong!".format(idc.demangle_name(possibilities[0], idc.get_inf_attr(idc.INF_SHORT_DN))))

	return count

def get_bin_funcs():
	seg = ida_segment.get_segm_by_name(".text")
	return {ida_funcs.get_func_name(ea): ea for ea in idautils.Functions(seg.start_ea, seg.end_ea)}

# So to prevent bad things, we're going to destroy any functions that have the exact same string xrefs
# This is to protect against inlining but ultimately fails as this compares direct values
# Foo() could call inlined Bar() twice which would fuck this up
# What to do, what to do...
def clean_data_dict(strdict):
	pass
#	resultant = {}
#	for key, value in get_bcompat_iter(strdict):
#		if sorted(value) not in resultant.values():
#			resultant[key] = sorted(value)
#
#	strdict = resultant

def write_symbols(strings, file):
	update_window("Loading file", True)
	funcdict = json.load(file)
	if not funcdict:
		ida_kernwin.warning("Could not load function data from file")
		return

	strdict = build_data_dict(build_xref_dict(strings))
	clean_data_dict(strdict)
	myfuncs = get_bin_funcs()

	# Writing uniques is much more liable to produce bad typing
	# Unique, one-off strings seem to be inlined much more often, so it's
	# better to use the simple comparison technique
	# This will reduce the amount of types, but the reduced types
	# wouldve been wrong or duplicated anyways
#	strdict = write_uniques(strings, funcdict["Uniques"])

	# A good test is to just simply compare xrefs
	# If a function references "fizzbuzz" 2 times and "foobar" once and its the only function
	# that does anything like that, chances are that we found something to smash
	exact_count = write_exact_comp(strdict, funcdict, myfuncs)

	# Since a lot of functions that have good strings have inlined strings in them, let's just look for containment
	# If "fizz", "buzz", and "foo" exist in Bar::Foo which has "fizz", "buzz", "foo", and "fizzbuzz" for example
	# Obviously we're only checking for 1 instance
	liw = write_simple_comp(strdict, funcdict, myfuncs)			# Symboled strings in stripped
	wil = write_simple_comp(strdict, funcdict, myfuncs, False)	# Stripped strings in symboled

	# TODO IDEAS;
	# -	Dance around some function xrefs. By now, a solid chunk of them should have symboled names (a few thousand at least)
	# 	A unique set of named xrefs could guarantee something
	#	Would need a new section in the data file (to and from)
	return exact_count, liw, wil

def main():
	action = get_action()
	if action == Mode_Invalid:
		return

	file = get_file(action)
	if file is None:
		ida_kernwin.warning("Invalid file specified!")
		return

#	strings = get_strs()
	strings = list(idautils.Strings())
	if action == Mode_Read:
		read_strs(strings, file)
		print("Done!")
	else:
		c1, c2, c3 = write_symbols(strings, file)
		print("Successfully typed {} functions".format(len(FOUND_FUNCS)))
		print("\t- {} Exact\n\t- {} Symboled in stripped\n\t- {} Stripped in symboled".format(c1, c2, c3))

	ida_kernwin.hide_wait_box()
	file.close()

if __name__ == "__main__":
	main()