Porting to a new game version
===

dynamite hooks game functions and patches game code at fixed addresses, which are valid only for game version 1.0.15.3.
Version 1.0.15.4 (June 9, 2026 update) moved almost everything. To support it, these must be found in the new exe:

  - 202 function addresses, `hook/src/mgsvtpp_addresses_1_0_15_3_en.h`
  - 25 byte patches and master server url, `hook/src/dynamitePatches.cpp`

Progress is tracked in `hook/src/mgsvtpp_addresses_1_0_15_4_en.h`. Ghidra script `hook/ghidra/DynamitePort.java`
does most of the lookups; whatever it can't match is left for a human.

### 1. Access and tools

  - Ask for access to the shared MGSV Ghidra server in [Modders' Heaven](https://discord.gg/3XwAsWV) Discord. It has
    both exe versions with tens of thousands of named functions, see
    [Ghidra tips](https://mgsvmoddingwiki.github.io/Ghidra_tips/)
  - Ghidra (same version as the server, ask on Discord) and JDK 21
  - `hook/ghidra/DynamitePort.java`, it doesn't need the rest of this repository

### 2. Function names in the new exe

The script matches functions by name, so names must be transferred from 1.0.15.3 exe to 1.0.15.4 exe first.

Check whether it was done already: open 1.0.15.4 exe, press `G`, enter a full name of a function dynamite uses (open
1.0.15.3 exe, press `G`, enter an address from `mgsvtpp_addresses_1_0_15_3_en.h` to get one). If Ghidra finds it,
names are there. Otherwise run [Version Tracking](https://mgsvmoddingwiki.github.io/Ghidra_version_tracking/)
(takes hours and a lot of memory).

### 3. Run the script

Open the project in Ghidra, open any program in CodeBrowser, then `Window -> Script Manager`,
`Manage Script Directories` (list icon), add the folder with `DynamitePort.java`. Run `DynamitePort.java` from
`Dynamite` category.

It finds 1.0.15.3 and 1.0.15.4 exes in the project by version info (asks if it can't tell), opens them read-only
(no checkout needed) and writes results to `dynamite_port` folder in your home directory:

  - `mgsvtpp_addresses_1_0_15_4_en.h` - function addresses
  - `dynamite_patches_1_0_15_4.txt` - byte patches and master server url

Console shows how many functions and patches were found. Copy results to `hook/src` when done.

Headless: `analyzeHeadless <project dir> <project> -process <any program> -noanalysis -readOnly -scriptPath
hook/ghidra -postScript DynamitePort.java [<1.0.15.3 program path> <1.0.15.4 program path> [<out dir>]]`

The script carries a copy of dynamite's address and patch files; after changing them run
`go run hook/ghidra/generate.go` (`go test` checks that the copy is up to date).

### 4. Finish by hand

`mgsvtpp_addresses_1_0_15_4_en.h`:

| Entry                                     | Meaning                                                                                         |
|-------------------------------------------|-------------------------------------------------------------------------------------------------|
| active, function name in comment          | found by name, size is similar                                                                  |
| active, `kept`                            | was in the file before, script didn't change it                                                 |
| active, `CHECK <name> is at <address>`    | address in the file is not the function with that name; decide which one is right, fix address |
| commented, `CHECK <name>, size a -> b`    | found by name, but size changed a lot; compare decompiled code, uncomment if it is the same     |
| commented, `AMBIGUOUS`                    | several functions have that name (overloads); compare each one with the old function            |
| commented, `NOT FOUND`                    | no function with that name in new exe                                                           |
| commented, `UNNAMED`, `NOFUNCTION`, `THUNK` | no usable name in old exe                                                                     |

Finding a function by hand: open it in 1.0.15.3 exe (`G`, old address), select a few instructions in `Listing`,
`Search -> For Matching Instructions -> Exclude Operands`, search for that pattern in 1.0.15.4 exe and compare
decompiled code. More approaches (strings, vtables, debugger) are in [Ghidra tips](https://mgsvmoddingwiki.github.io/Ghidra_tips/).
Name the function in the new exe and check it in, so others don't have to do it again.

The script can be run again any time: active entries of previous result in `dynamite_port` folder are kept, so fill in
addresses there by hand or name more functions in Ghidra and re-run it.

`dynamite_patches_1_0_15_4.txt`: `FOUND` patches are in the same function, surrounded by the same instructions and
have the same original bytes; look at them in Ghidra anyway. Port the rest by hand: find the function, then the
instruction from patch description, check that its bytes match `.expected`.

### 5. Game scripts

dynamite replaces some game scripts with edited 1.0.15.3 versions (`moddata/standalone`, mission files listed in
`moddata/moddata.go`) and checks 1.0.15.3 `00.dat` checksum (`installer/installer.go`). Extract these scripts from
1.0.15.4 game files, compare them with 1.0.15.3 ones and move Konami's changes, if any, into dynamite's copies.

### 6. Code

Not done yet: hook must pick address table and patch addresses by game version
(`hook/src/dynamite.cpp`, `hook/src/dynamitePatches.cpp`) and accept 1.0.15.4 in version checks (hook and installer).

### 7. Test

Two players on 1.0.15.4. Start with missions that worked on 1.0.15.3. Crash on start or in a mission most likely
means a wrong address; `dynamite/dynamite.log.txt` in game directory shows what happened last.
