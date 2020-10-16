# IDA Scripts
 Some random IDA scripts I wrote

### makesig.py ###

Python translation of [makesig](https://github.com/alliedmodders/sourcemod/blob/master/tools/ida_scripts/makesig.idc)


### isgoodsig.py ###

Takes a SourceMod signature input and detects if it's unique or not.


### netprop_importer.py ###

Imports netprops and owner classes as structs and struct members into IDA's DB. Only works with the XML file provided by sm_dump_netprops_xml. It's still a WIP and doesn't catch all of them though; really shits the bed when it comes to datatables. You should also use the proper netprop dump for your OS, or else you will be very confused.

You also have the option of importing vtables from the found classes into IDA. I plan on separating this into another script, but until then, this will work.


### gamedata_checker.py ###

Name says it all, but this verifies SourceMod gamedata files. This requires Valve's VDF library, install it with `pip install vdf`.

Has a few quirks with it at the moment:
- It does not support multi-line comments within gamedata files nor will it support multiple instances of `#default` keys. Parsing core SourceMod gamedata files is essentially verboten.
- Windows or stripped VTable offsets cannot be verified.
- Function overloads tends to mess up VTable offset checking; e.g. `GiveNamedItem`.
- Offset checking is variably difficult depending on naming conventions. If the gamedata key name is not named exactly the same as the function name, it will not be found; e.g. `OnTakeDamage` -> `CBaseEntity::OnTakeDamage` and `CTFPlayer::OnTakeDamage` -> `CBaseEntity::OnTakeDamage` but `TakeDamage` != `CBaseEntity::OnTakeDamage`.


### sigsmasher.py ###

Makes SourceMod ready signatures for every function in IDA's database. Yes, this will take a long, long time. Requires PyYAML so you'll need to `pip install pyyaml`. You have the option of only generating signatures for typed functions so this works very well with [Symbol Smasher](https://github.com/Scags/IDA-Source-Symbol-Smasher).


### findmyfunc.py ###

Takes a SourceMod signature and jumps you to the function it's for. If it's a bad signature, then you won't go anywhere.


### nameresetter.py ###

Resets the name of every function in IDA's database. Does not include library or external functions.