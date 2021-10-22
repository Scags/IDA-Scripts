# IDA Scripts
Some random IDA scripts I wrote


### findmyfunc.py ###

Takes a SourceMod signature and jumps you to the function it's for. If it's a bad signature, then you won't go anywhere.


### gamedata_checker.py ###

Name says it all, but this verifies SourceMod gamedata files. This requires Valve's VDF library, install it with `pip install vdf`.

Has a few quirks with it at the moment:
- It does not support multi-line comments within gamedata files nor will it support multiple instances of `#default` keys. Parsing core SourceMod gamedata files is essentially verboten.
- VTable functions that are stripped cannot be verified, obviously.
- Function overloads tends to mess up VTable offset checking; e.g. `GiveNamedItem`.
- Offset checking is variably difficult depending on naming conventions. If the gamedata key name is not named exactly the same as the function name, it will not be found; e.g. `OnTakeDamage` -> `CBaseEntity::OnTakeDamage` and `CTFPlayer::OnTakeDamage` -> `CBaseEntity::OnTakeDamage` but `TakeDamage` != `CBaseEntity::OnTakeDamage`.


### getfuncoffset.py ###

Get the offset from the cursor address and the start of a function. Useful for byte patching.


### isgoodsig.py ###

Takes a SourceMod signature input and detects if it's unique or not.


### makesig.py ###

Python translation of [makesig](https://github.com/alliedmodders/sourcemod/blob/master/tools/ida_scripts/makesig.idc)


### makesigfromhere.py ###

Creates a signature from the cursor offset. Useful for byte patching.

### nameresetter.py ###

Resets the name of every function in IDA's database. Does not include library or external functions.


### netprop_importer.py ###

Imports netprops and owner classes as structs and struct members into IDA's DB. Only works with the XML file provided by sm_dump_netprops_xml. Datatables only work most of the time. You should also use the proper netprop dump for your OS, or else you will be very confused.

You also have the option of importing vtables from the found classes into IDA. This is a bit more sane than the **vtable_structs.py** script, but only works on classes with netprops.


### sigsmasher.py ###

Makes SourceMod ready signatures for every function in IDA's database. Yes, this will take a long, long time. Requires PyYAML so you'll need to `pip install pyyaml`. You have the option of only generating signatures for typed functions so this works very well with [Symbol Smasher](https://github.com/Scags/IDA-Source-Symbol-Smasher).


### structaligner.py ###

Sanitizes undefined struct members as if IDA had parsed a header file. Each structure will have its undefined members replaced with a one-byte-sized member in order to prevent pseudocode from falling apart. Only makes sense to use it after running the netprop importer.


### symbolsmasher.py ###

Renames functions in a stripped library database based on unique string cross-references.

Running the script presents 2 options: you can read and export data from the current database, or you can import and write data into it.

If you're on a symbol library, you should run it in read mode and export it to a file. This file is what is used to import back into a stripped binary.

When on Windows or another stripped database, run the script in write mode and select the file you exported earlier. A solid amount of functions should be typed within a few seconds.

This works well with the Signature Smasher. However to save you an hour or so, I publicly host dumps of most Source games [here](https://brewcrew.tf/sigdump).

### vtable_io.py ###

Imports and exports virtual tables. Run it through a Linux binary to export to a file, then run it through a Windows binary to import those VTables into the database. This is similar to [Asherkin's VTable Dumper](https://asherkin.github.io/vtable/) but doesn't suffer from the pitfalls of multiple inheritance. Since it doesn't have those liabilities, it's function typing will almost always be perfect. 32-bit only for now.

Only works on libraries that have virtual thunks *after* the virtual table declaration such as in TF2. Fixing this is a TODO.

### vtable_structs.py ###

Runs through virtual tables and creates structs for them. Doesn't work with template classes. Use at your own risk since it screws up refencing members through pseudocode.