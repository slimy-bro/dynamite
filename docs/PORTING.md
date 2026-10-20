Porting to a new game version
===

dynamite hooks game functions and patches game code at fixed addresses, which are valid only for game version 1.0.15.3.
Version 1.0.15.4 (June 9, 2026 update) moved almost everything. To support it, these must be found in the new exe:

  - 202 function addresses, `hook/src/mgsvtpp_addresses_1_0_15_3_en.h`
  - 25 byte patches and master server url, `hook/src/dynamitePatches.cpp`

Progress: `hook/src/mgsvtpp_addresses_1_0_15_4_en.h` (functions), `hook/src/mgsvtpp_patches_1_0_15_4_en.h` (patches).

### Method

No function names are needed, only both exes analyzed in Ghidra. 1.0.15.3 exe can be made from 1.0.15.4 one with
[MGSV 1.0.15.3 Downgrader](https://www.nexusmods.com/metalgearsolidvtpp/mods/2489) or downloaded from Steam console
(`download_depot 287700 287701 2518831260221836800`).

  1. Run `hook/ghidra/ExportFunctionFingerprints.java` on both exes. It writes every function with its size and hashes
     of its instructions and constants.
  2. Match dynamite's 1.0.15.3 functions to 1.0.15.4 ones:
      - same instructions, unique in new exe
      - several functions with same instructions: the one between functions that surround it in old exe (neighbours
        with unique instructions keep their order; checked on 20000 known pairs: correct 98.8%)
      - changed function: function in the same position with same constants, similar size and number of calls
  3. Patches: same offset in a function with same instructions and size. Expected bytes are checked when applied.
  4. The rest is compared by hand: `hook/ghidra/ExportBytesForDynamite.java` writes code bytes of remaining 1.0.15.3
     functions, of the place in 1.0.15.4 exe where each of them should be (step 2) and the master server url address.

All 18 addresses known from IHHook 1.0.15.4 table agree with the matches.

### Remaining

  - functions and patches still commented out in the files above
  - game scripts: dynamite replaces some game scripts with edited 1.0.15.3 versions (`moddata/standalone`, mission
    files in `moddata/moddata.go`) and checks 1.0.15.3 `00.dat` checksum (`installer/installer.go`); 1.0.15.4 versions
    must be compared with them
  - hook must pick address and patch tables by game version (`hook/src/dynamite.cpp`, `hook/src/dynamitePatches.cpp`)
    and accept 1.0.15.4 in version checks (hook and installer)
  - testing with two players on 1.0.15.4
