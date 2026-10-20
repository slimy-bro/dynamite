// Ports dynamite addresses from game version 1.0.15.3 to 1.0.15.4 in one step.
// Finds both mgsvtpp.exe versions in the current project (shared MGSV project works), opens them read-only, so no
// checkout is needed, and writes results to dynamite_port folder in user's home directory:
//   mgsvtpp_addresses_1_0_15_4_en.h - function addresses, commented out entries need a human
//   dynamite_patches_1_0_15_4.txt   - byte patches and master server url
// Functions are matched by name, so names must be transferred to the new exe first (Version Tracking or by hand).
// Run it again after naming more functions or filling in addresses: active entries of previous result are kept.
// dynamite's 1.0.15.3 addresses and patches are embedded at the end, see generate.go.
// Headless: analyzeHeadless <project dir> <project> -process <any program> -noanalysis -readOnly
//   -scriptPath hook/ghidra -postScript DynamitePort.java [<1.0.15.3 program path> <1.0.15.4 program path> [<out dir>]]
//@category Dynamite

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class DynamitePort extends GhidraScript {
    static final String OLD_VERSION = "1.0.15.3";
    static final String NEW_VERSION = "1.0.15.4";
    // Steam 1.0.15.3 mgsvtpp.exe, see patch/patch.go
    static final String OLD_MD5 = "7cc5f282b068f741adda2bb1076fb721";

    static final String TSV = "dynamite_1_0_15_3.tsv";
    static final String ADDRESSES = "mgsvtpp_addresses_1_0_15_4_en.h";
    static final String REPORT = "dynamite_patches_1_0_15_4.txt";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = args.length > 2 ? new File(args[2]) : new File(System.getProperty("user.home"), "dynamite_port");
        Files.createDirectories(outDir.toPath());

        List<DomainFile> programs = new ArrayList<>();
        collectPrograms(state.getProject().getProjectData().getRootFolder(), programs);
        DomainFile oldFile = args.length > 1 ? projectFile(args[0]) : pick(programs, OLD_VERSION, OLD_MD5);
        DomainFile newFile = args.length > 1 ? projectFile(args[1]) : pick(programs, NEW_VERSION, null);
        println(OLD_VERSION + ": " + oldFile.getPathname());
        println(NEW_VERSION + ": " + newFile.getPathname());

        List<String> tsv;
        Program oldProgram = open(oldFile);
        try {
            tsv = new Exporter(oldProgram).export(ADDRESSES_1_0_15_3, PATCHES_1_0_15_3);
        } finally {
            oldProgram.release(this);
        }
        Files.write(new File(outDir, TSV).toPath(), tsv, StandardCharsets.UTF_8);

        // previous result has addresses filled in by hand
        File addresses = new File(outDir, ADDRESSES);
        String known = addresses.isFile() ? Files.readString(addresses.toPath()) : ADDRESSES_1_0_15_4;

        Finder finder;
        Program newProgram = open(newFile);
        try {
            finder = new Finder(newProgram, monitor);
            finder.find(tsv, Finder.readKnown(known));
        } finally {
            newProgram.release(this);
        }

        Files.write(addresses.toPath(), finder.addresses(), StandardCharsets.UTF_8);
        Files.write(new File(outDir, REPORT).toPath(), finder.report(), StandardCharsets.UTF_8);

        println(String.format("functions: %d of %d found", finder.funcsFound, finder.funcs));
        if (finder.conflicts > 0) {
            println(String.format("%d existing entries disagree with function names, see CHECK comments",
                finder.conflicts));
        }
        println(String.format("patches: %d of %d found", finder.patchesFound, finder.patches));
        println("results: " + outDir);
    }

    static void collectPrograms(DomainFolder folder, List<DomainFile> result) {
        for (DomainFile f : folder.getFiles()) {
            if ("Program".equals(f.getContentType())) {
                result.add(f);
            }
        }

        for (DomainFolder sub : folder.getFolders()) {
            collectPrograms(sub, result);
        }
    }

    DomainFile projectFile(String path) {
        DomainFile f = state.getProject().getProjectData().getFile(path);
        if (f == null) {
            throw new IllegalArgumentException("no " + path + " in project");
        }

        return f;
    }

    // by version info or md5 recorded on import; asks if there is no single match
    DomainFile pick(List<DomainFile> programs, String version, String md5) throws Exception {
        List<DomainFile> matches = new ArrayList<>();
        for (DomainFile f : programs) {
            Map<String, String> meta = f.getMetadata();
            if (version.equals(fileVersion(meta)) || (md5 != null && md5.equalsIgnoreCase(meta.get("Executable MD5")))) {
                matches.add(f);
            }
        }

        if (matches.size() == 1) {
            return matches.get(0);
        }

        List<DomainFile> choices = matches.isEmpty() ? programs : matches;
        if (choices.isEmpty()) {
            throw new IllegalStateException("no programs in project");
        }

        // English exe is needed, offer it first
        choices.sort(Comparator.comparing((DomainFile f) -> f.getPathname().toLowerCase().contains("jp"))
            .thenComparing(DomainFile::getPathname));
        Map<String, DomainFile> byLabel = new LinkedHashMap<>();
        for (DomainFile f : choices) {
            String v = fileVersion(f.getMetadata());
            byLabel.put(f.getPathname() + (v.isEmpty() ? "" : " (" + v + ")"), f);
        }

        List<String> labels = new ArrayList<>(byLabel.keySet());
        String message = matches.isEmpty()
            ? "Could not tell which program is mgsvtpp.exe " + version + ", select it"
            : "Several programs look like mgsvtpp.exe " + version + " (English version is needed), select one";
        String choice = askChoice("mgsvtpp.exe " + version, message, labels, labels.get(0));
        return byLabel.get(choice);
    }

    // "1, 0, 15, 3" -> "1.0.15.3"
    static String fileVersion(Map<String, String> meta) {
        String v = meta.getOrDefault("PE Property[FileVersion]", meta.getOrDefault("PE Property[ProductVersion]", ""));
        Matcher m = Pattern.compile("(\\d+)\\D+(\\d+)\\D+(\\d+)\\D+(\\d+)").matcher(v);
        return m.find() ? m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4) : "";
    }

    Program open(DomainFile f) throws Exception {
        println("opening " + f.getPathname() + ", may take a while");
        return (Program) f.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
    }

    static class Util {
        static long parseHex(String s) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }

        static String hex(long v) {
            return String.format("0x%x", v);
        }

        static String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b & 0xff));
            }

            return sb.toString();
        }

        static byte[] hexToBytes(String s) {
            byte[] result = new byte[s.length() / 2];
            for (int i = 0; i < result.length; i++) {
                result[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
            }

            return result;
        }

        static List<Instruction> instructions(Program program, Function f) {
            List<Instruction> result = new ArrayList<>();
            InstructionIterator it = program.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                result.add(it.next());
            }

            return result;
        }

        // null if not all bytes are readable
        static byte[] readBytes(Program program, Address a, int len) {
            byte[] result = new byte[len];
            try {
                int n = program.getMemory().getBytes(a, result);
                return n == len ? result : Arrays.copyOf(result, n);
            } catch (Exception e) {
                return null;
            }
        }
    }

    // Records names of hooked functions, positions of byte patches inside their functions and patched strings.
    // Output is one tab-separated record per line:
    //   break
    //   func, name, old address, full name, size, status
    //   patch, index, old address, function full name, offset, expected bytes, mnemonics before, mnemonics after,
    //     status, description
    //   string, index, old address, string bytes, status, description
    static class Exporter {
        // number of instructions before and after patched one, used to find it in new exe
        static final int WINDOW = 6;
        static final int MAX_STRING = 1024;

        static final Pattern ENTRY = Pattern.compile("\\{\\s*\"([^\"]+)\"\\s*,\\s*(0x[0-9a-fA-F]+)\\s*\\}");
        static final Pattern HEX = Pattern.compile("0x[0-9a-fA-F]+");
        static final Pattern PATCH_ADDRESS = Pattern.compile("\\.address\\s*=\\s*(0x[0-9a-fA-F]+)");
        static final Pattern QUOTED = Pattern.compile("\"([^\"]*)\"");

        static class PatchSource {
            long address;
            byte[] expected; // null if expected bytes are not a literal (string patch)
            String description = "";
        }

        final Program program;

        Exporter(Program program) {
            this.program = program;
        }

        List<String> export(String addresses, String patches) {
            List<String> out = new ArrayList<>();

            int funcs = 0;
            boolean previousBlank = false;
            for (String line : addresses.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) {
                    previousBlank = true;
                    continue;
                }

                if (t.startsWith("//")) {
                    continue;
                }

                Matcher m = ENTRY.matcher(t);
                if (!m.find()) {
                    continue;
                }

                if (previousBlank && funcs > 0) {
                    out.add("break");
                }
                previousBlank = false;

                exportFunction(m.group(1), Util.parseHex(m.group(2)), out);
                funcs++;
            }

            int index = 0;
            for (PatchSource p : readPatches(patches)) {
                index++;
                if (p.expected == null) {
                    exportString(index, p, out);
                } else {
                    exportPatch(index, p, out);
                }
            }

            return out;
        }

        Address toAddr(long offset) {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }

        void exportFunction(String name, long address, List<String> out) {
            Function f = program.getFunctionManager().getFunctionAt(toAddr(address));
            String status;
            String fullName = "";
            long size = 0;
            if (f == null) {
                status = "nofunction";
            } else {
                fullName = f.getName(true);
                size = f.getBody().getNumAddresses();
                if (f.getSymbol().getSource() == SourceType.DEFAULT) {
                    status = "unnamed";
                } else if (f.isThunk()) {
                    status = "thunk";
                } else {
                    status = "ok";
                }
            }

            out.add(String.join("\t", "func", name, Util.hex(address), fullName, Long.toString(size), status));
        }

        void exportPatch(int index, PatchSource p, List<String> out) {
            Address a = toAddr(p.address);
            Function f = program.getFunctionManager().getFunctionContaining(a);
            String status = "ok";
            String fullName = "";
            long offset = 0;
            String before = "";
            String after = "";

            byte[] actual = Util.readBytes(program, a, p.expected.length);
            if (actual == null || !Arrays.equals(actual, p.expected)) {
                status = "bytesdiffer";
            }

            if (f == null) {
                status = "nofunction";
            } else {
                fullName = f.getName(true);
                offset = p.address - f.getEntryPoint().getOffset();
                if (f.getSymbol().getSource() == SourceType.DEFAULT && status.equals("ok")) {
                    status = "unnamed";
                }

                List<Instruction> instructions = Util.instructions(program, f);
                int i = indexOf(instructions, a);
                if (i < 0) {
                    status = "notinstruction";
                } else {
                    before = mnemonics(instructions, Math.max(0, i - WINDOW), i);
                    after = mnemonics(instructions, i, Math.min(instructions.size(), i + WINDOW));
                }
            }

            out.add(String.join("\t", "patch", Integer.toString(index), Util.hex(p.address), fullName,
                Util.hex(offset), Util.bytesToHex(p.expected), before, after, status, p.description));
        }

        void exportString(int index, PatchSource p, List<String> out) {
            String status = "ok";
            String bytes = "";
            byte[] data = Util.readBytes(program, toAddr(p.address), MAX_STRING);
            int len = -1;
            if (data != null) {
                for (int i = 0; i < data.length; i++) {
                    if (data[i] == 0) {
                        len = i;
                        break;
                    }
                }
            }

            if (len <= 0) {
                status = "nostring";
            } else {
                // keep terminating zero, otherwise search finds the string as part of a longer one
                bytes = Util.bytesToHex(Arrays.copyOf(data, len + 1));
            }

            out.add(String.join("\t", "string", Integer.toString(index), Util.hex(p.address), bytes, status,
                p.description));
        }

        static List<PatchSource> readPatches(String patches) {
            List<PatchSource> result = new ArrayList<>();
            PatchSource current = null;
            boolean inDescription = false;
            // expected bytes may span several lines: ".expected =", "{", values, "}"
            boolean expectedPending = false;
            StringBuilder expected = null;
            for (String line : patches.split("\n")) {
                String t = line.trim();
                if (t.startsWith("//")) {
                    continue;
                }

                // description is split into several string literals
                if (inDescription && t.startsWith("\"")) {
                    Matcher q = QUOTED.matcher(t);
                    while (q.find()) {
                        current.description += q.group(1);
                    }
                    continue;
                }
                inDescription = false;

                // comments next to expected bytes contain hex values too
                String code = stripComment(t);
                if (expected != null || (expectedPending && code.startsWith("{"))) {
                    expectedPending = false;
                    if (expected == null) {
                        expected = new StringBuilder();
                    }
                    int close = code.indexOf('}');
                    expected.append(close >= 0 ? code.substring(0, close) : code).append(' ');
                    if (close >= 0) {
                        current.expected = parseExpected(expected.toString());
                        expected = null;
                    }
                    continue;
                }
                expectedPending = false;

                Matcher m = PATCH_ADDRESS.matcher(code);
                if (m.find()) {
                    current = new PatchSource();
                    current.address = Util.parseHex(m.group(1));
                    result.add(current);
                    continue;
                }

                if (current == null) {
                    continue;
                }

                if (code.startsWith(".expected")) {
                    String value = code.substring(code.indexOf('=') + 1).trim();
                    if (value.isEmpty()) {
                        expectedPending = true;
                    } else if (value.startsWith("{")) {
                        int close = value.indexOf('}');
                        if (close >= 0) {
                            current.expected = parseExpected(value.substring(0, close));
                        } else {
                            expected = new StringBuilder(value).append(' ');
                        }
                    }
                    // otherwise expected bytes are a variable, string patch
                } else if (code.startsWith(".description")) {
                    Matcher q = QUOTED.matcher(t);
                    while (q.find()) {
                        current.description += q.group(1);
                    }
                    inDescription = true;
                }
            }

            return result;
        }

        static String stripComment(String s) {
            int i = s.indexOf("//");
            return i >= 0 ? s.substring(0, i).trim() : s;
        }

        static byte[] parseExpected(String s) {
            List<Long> values = new ArrayList<>();
            Matcher h = HEX.matcher(s);
            while (h.find()) {
                values.add(Util.parseHex(h.group()));
            }

            byte[] result = new byte[values.size()];
            for (int i = 0; i < values.size(); i++) {
                result[i] = (byte) (long) values.get(i);
            }

            return result;
        }

        static int indexOf(List<Instruction> instructions, Address a) {
            for (int i = 0; i < instructions.size(); i++) {
                if (instructions.get(i).getAddress().equals(a)) {
                    return i;
                }
            }

            return -1;
        }

        static String mnemonics(List<Instruction> instructions, int from, int to) {
            List<String> result = new ArrayList<>();
            for (int i = from; i < to; i++) {
                result.add(instructions.get(i).getMnemonicString());
            }

            return String.join(",", result);
        }
    }

    // Finds exported records in new exe by function name.
    static class Finder {
        // function size may change a bit between versions, bigger difference needs a human
        static final double MIN_SIZE_RATIO = 0.75;
        static final double MAX_SIZE_RATIO = 1.33;

        static final Pattern ENTRY = Pattern.compile("\\{\\s*\"([^\"]+)\"\\s*,\\s*(0x[0-9a-fA-F]+)\\s*\\}");

        final Program program;
        final TaskMonitor monitor;
        final Map<String, List<Function>> functionsByName = new HashMap<>();
        final List<String> entries = new ArrayList<>();
        final List<String> report = new ArrayList<>();
        int funcs, funcsFound, conflicts, patches, patchesFound;

        Finder(Program program, TaskMonitor monitor) {
            this.program = program;
            this.monitor = monitor;

            // thunks are named after the function they jump to, they would make every name ambiguous
            FunctionIterator it = program.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                if (f.isThunk() || f.getSymbol().getSource() == SourceType.DEFAULT) {
                    continue;
                }

                functionsByName.computeIfAbsent(f.getName(true), k -> new ArrayList<>()).add(f);
            }
        }

        // active entries of addresses file, filled in by hand or by previous run
        static Map<String, Long> readKnown(String addresses) {
            Map<String, Long> result = new LinkedHashMap<>();
            for (String line : addresses.split("\n")) {
                String t = line.trim();
                if (t.startsWith("//")) {
                    continue;
                }

                Matcher m = ENTRY.matcher(t);
                if (m.find()) {
                    result.put(m.group(1), Util.parseHex(m.group(2)));
                }
            }

            return result;
        }

        void find(List<String> tsv, Map<String, Long> known) throws Exception {
            for (String line : tsv) {
                String[] r = line.split("\t", -1);
                switch (r[0]) {
                    case "break" -> entries.add("");
                    case "func" -> {
                        funcs++;
                        String entry = findFunction(r, known);
                        if (!entry.trim().startsWith("//")) {
                            funcsFound++;
                            if (entry.contains("// CHECK")) {
                                conflicts++;
                            }
                        }
                        entries.add(entry);
                    }
                    case "patch" -> {
                        patches++;
                        if (findPatch(r)) {
                            patchesFound++;
                        }
                    }
                    case "string" -> {
                        patches++;
                        if (findString(r)) {
                            patchesFound++;
                        }
                    }
                    default -> throw new IllegalArgumentException("unexpected record: " + line);
                }
            }
        }

        // r: func, name, old address, full name, size, status
        String findFunction(String[] r, Map<String, Long> known) {
            String name = r[1];
            String oldAddress = r[2];
            String fullName = r[3];
            long oldSize = Long.parseLong(r[4]);
            String status = r[5];
            Long knownAddress = known.get(name);

            if (!status.equals("ok")) {
                if (knownAddress != null) {
                    return active(name, knownAddress, "kept");
                }

                return missing(name,
                    String.format("%s in 1.0.15.3 exe (%s), find by hand", status.toUpperCase(), oldAddress));
            }

            List<Function> candidates = functionsByName.getOrDefault(fullName, List.of());
            List<Long> addresses = new ArrayList<>();
            List<String> hexAddresses = new ArrayList<>();
            for (Function f : candidates) {
                addresses.add(f.getEntryPoint().getOffset());
                hexAddresses.add(Util.hex(f.getEntryPoint().getOffset()));
            }

            // active entries were set by hand or accepted earlier, never replace them
            if (knownAddress != null) {
                if (addresses.isEmpty()) {
                    return active(name, knownAddress, "kept, " + fullName + " not found by name");
                }

                if (addresses.contains(knownAddress)) {
                    return active(name, knownAddress, fullName);
                }

                return active(name, knownAddress,
                    String.format("CHECK %s is at %s", fullName, String.join(", ", hexAddresses)));
            }

            if (addresses.isEmpty()) {
                return missing(name, String.format("NOT FOUND %s (1.0.15.3: %s)", fullName, oldAddress));
            }

            if (addresses.size() > 1) {
                return missing(name,
                    String.format("AMBIGUOUS %s at %s", fullName, String.join(", ", hexAddresses)));
            }

            Function f = candidates.get(0);
            long address = f.getEntryPoint().getOffset();
            long newSize = f.getBody().getNumAddresses();

            if (oldSize > 0) {
                double ratio = (double) newSize / oldSize;
                if (ratio < MIN_SIZE_RATIO || ratio > MAX_SIZE_RATIO) {
                    return candidate(name, address,
                        String.format("CHECK %s, size %d -> %d", fullName, oldSize, newSize));
                }
            }

            return active(name, address, fullName);
        }

        // r: patch, index, old address, function full name, offset, expected bytes, before, after, status,
        // description
        boolean findPatch(String[] r) {
            String index = r[1];
            String oldAddress = r[2];
            String fullName = r[3];
            long oldOffset = Util.parseHex(r[4]);
            byte[] expected = Util.hexToBytes(r[5]);
            List<String> before = split(r[6]);
            List<String> after = split(r[7]);
            String status = r[8];
            String description = r[9];

            String result;
            boolean found = false;
            if (!status.equals("ok")) {
                result = String.format("%s in 1.0.15.3 exe, port by hand", status.toUpperCase());
            } else {
                List<Function> candidates = functionsByName.getOrDefault(fullName, List.of());
                if (candidates.size() != 1) {
                    result = String.format("%s %s, port by hand", candidates.isEmpty() ? "NOT FOUND" : "AMBIGUOUS",
                        fullName);
                } else {
                    Function f = candidates.get(0);
                    List<Instruction> instructions = Util.instructions(program, f);
                    List<Instruction> matches = matchPatch(instructions, expected, before, after);
                    if (matches.isEmpty()) {
                        // compiler may change instructions before the patch, try without them
                        matches = matchPatch(instructions, expected, List.of(), after);
                    }

                    if (matches.size() == 1) {
                        Address a = matches.get(0).getAddress();
                        long offset = a.getOffset() - f.getEntryPoint().getOffset();
                        result = String.format("FOUND %s -> %s, %s +%s (was +%s)", oldAddress, Util.hex(a.getOffset()),
                            fullName, Util.hex(offset), Util.hex(oldOffset));
                        found = true;
                    } else if (matches.isEmpty()) {
                        result = String.format("NOT FOUND in %s at %s, port by hand", fullName,
                            Util.hex(f.getEntryPoint().getOffset()));
                    } else {
                        List<String> addresses = new ArrayList<>();
                        for (Instruction i : matches) {
                            addresses.add(Util.hex(i.getAddress().getOffset()));
                        }
                        result = String.format("AMBIGUOUS in %s: %s, port by hand", fullName,
                            String.join(", ", addresses));
                    }
                }
            }

            report.add(String.format("#%s %s", index, result));
            report.add("    " + description + " (1.0.15.3: " + oldAddress + ")");
            return found;
        }

        List<Instruction> matchPatch(List<Instruction> instructions, byte[] expected, List<String> before,
                                     List<String> after) {
            List<Instruction> result = new ArrayList<>();
            for (int i = 0; i < instructions.size(); i++) {
                if (!mnemonicsMatch(instructions, i - before.size(), before)
                    || !mnemonicsMatch(instructions, i, after)) {
                    continue;
                }

                byte[] actual = Util.readBytes(program, instructions.get(i).getAddress(), expected.length);
                if (Arrays.equals(actual, expected)) {
                    result.add(instructions.get(i));
                }
            }

            return result;
        }

        static boolean mnemonicsMatch(List<Instruction> instructions, int from, List<String> mnemonics) {
            if (from < 0 || from + mnemonics.size() > instructions.size()) {
                return false;
            }

            for (int i = 0; i < mnemonics.size(); i++) {
                if (!instructions.get(from + i).getMnemonicString().equals(mnemonics.get(i))) {
                    return false;
                }
            }

            return true;
        }

        // r: string, index, old address, string bytes, status, description
        boolean findString(String[] r) throws Exception {
            String index = r[1];
            String oldAddress = r[2];
            String status = r[4];
            String description = r[5];

            String result;
            boolean found = false;
            if (!status.equals("ok")) {
                result = String.format("%s in 1.0.15.3 exe, port by hand", status.toUpperCase());
            } else {
                List<String> addresses = new ArrayList<>();
                for (Address a : findAll(Util.hexToBytes(r[3]))) {
                    addresses.add(Util.hex(a.getOffset()));
                }

                if (addresses.size() == 1) {
                    result = String.format("FOUND %s -> %s, string", oldAddress, addresses.get(0));
                    found = true;
                } else if (addresses.isEmpty()) {
                    result = "NOT FOUND string, port by hand";
                } else {
                    result = "AMBIGUOUS string at " + String.join(", ", addresses) + ", port by hand";
                }
            }

            report.add(String.format("#%s %s", index, result));
            report.add("    " + description + " (1.0.15.3: " + oldAddress + ")");
            return found;
        }

        List<Address> findAll(byte[] bytes) throws Exception {
            List<Address> result = new ArrayList<>();
            Memory memory = program.getMemory();
            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized()) {
                    continue;
                }

                Address start = block.getStart();
                while (start != null && start.compareTo(block.getEnd()) <= 0) {
                    Address a = memory.findBytes(start, block.getEnd(), bytes, null, true, monitor);
                    if (a == null) {
                        break;
                    }
                    result.add(a);
                    start = a.next();
                }
            }

            return result;
        }

        List<String> addresses() {
            List<String> out = new ArrayList<>();
            out.add("#ifndef HOOK_DYNAMITE_MGSVTPP_ADDRESSES_1_0_15_4");
            out.add("#define HOOK_DYNAMITE_MGSVTPP_ADDRESSES_1_0_15_4");
            out.add("");
            out.add("#include <cstdint>");
            out.add("#include <map>");
            out.add("#include <string>");
            out.add("");
            out.add("// Addresses for game version 1.0.15.4 (June 9, 2026 update), not used yet.");
            out.add(String.format("// %d of %d addresses are known. Generated by hook/ghidra/DynamitePort.java, see",
                funcsFound, funcs));
            out.add("// docs/PORTING.md; re-running it keeps active entries. Commented out entries need a human.");
            out.add("// Initial known entries came from IHHook 1.0.15.4 table (MIT, https://github.com/Phobos1641/mgs5-ihhook).");
            out.add("");
            out.add("namespace Dynamite {");
            out.add("    inline std::map<std::string, uint64_t> mgsvtpp_adresses_1_0_15_4_en{");
            out.addAll(entries);
            out.add("    };");
            out.add("}");
            out.add("");
            out.add("#endif");
            return out;
        }

        List<String> report() {
            List<String> out = new ArrayList<>();
            out.add(String.format("dynamite patches for 1.0.15.4, generated by DynamitePort.java: %d of %d found",
                patchesFound, patches));
            out.add("FOUND: same function, same surrounding instructions and original bytes, check it in Ghidra anyway");
            out.add("");
            out.addAll(report);
            return out;
        }

        static String active(String name, long address, String comment) {
            return String.format("        {\"%s\", %s}, // %s", name, Util.hex(address), comment);
        }

        // found, but needs a human to confirm
        static String candidate(String name, long address, String comment) {
            return String.format("        // {\"%s\", %s}, // %s", name, Util.hex(address), comment);
        }

        static String missing(String name, String comment) {
            return String.format("        // {\"%s\", 0x0}, // %s", name, comment);
        }

        static List<String> split(String s) {
            return s.isEmpty() ? List.of() : Arrays.asList(s.split(","));
        }
    }

    // BEGIN GENERATED by generate.go from hook/src, do not edit
    // mgsvtpp_addresses_1_0_15_3_en.h
    static final String ADDRESSES_1_0_15_3 = """
#ifndef HOOK_DYNAMITE_MGSVTPP_ADDRESSES
#define HOOK_DYNAMITE_MGSVTPP_ADDRESSES

#include <map>
#include <string>

// do _not_ hook lua_newstate, it will crash no matter what if compiled with mingw

namespace Dynamite {
    inline std::map<std::string, uint64_t> mgsvtpp_adresses_1_0_15_3_en{
        {"IsDefenseTeamByOnlineFobLocal", 0x14d9ba3b0},
        {"IsOffenseTeamByOnlineFobLocal", 0x141e02e40},
        {"CreateHostSession", 0x1459f3e20},
        {"NetworkSystemCreateHostSession", 0x14da33790},
        {"CreateClientSession", 0x1459f3910},
        {"SetSteamId", 0x14c404640},
        {"FobTargetCtor", 0x1459ed160},
        {"SessionConnectInfoCtor", 0x1459edf00},
        {"NetInfoCreateSession", 0x14da5c070},
        {"IsConnectReady", 0x1459d0cc0},
        {"UpdateClientEstablished", 0x140316610},
        {"SessionImpl2IsHost", 0x143e64400},
        {"GetFobOffensePlayerInstanceIndex", 0x14d9b00e0},
        {"GetFobDefensePlayerInstanceIndex", 0x14d9afbc0},
        {"CommandPost2ImplGetAvailableMemberCount", 0x1472a0500},
        {"CommandPost2ImplGetMaxCpCount", 0x140c93de0},
        {"GetUiMarkerTypeFromSystemType2", 0x140934580},
        {"SightManagerImplSetMarker", 0x149c687d0},
        {"SteamUdpSocketImplOnP2PSessionRequest", 0x14c4040c0},
        {"MessageBufferAddMessage", 0x1435ce000},
        {"AddLocalDamage", 0x141192af0},
        {"DamageControllerImplInitialize", 0x14991a290},
        {"SynchronizerImplGetDamage", 0x149cb4c70},
        {"Marker2SystemImpl", 0x144fdb110},
        {"Marker2SystemImplPlacedUserMarkerFixed", 0x144fe5400},
        {"GetLocalPlayerID", 0x144c972c0},
        {"RemoveUserMarker", 0x1460706a0},
        {"EquipHudSystemImplInitData", 0x14606c570},
        {"Marker2SystemImplRemovedUserMarker", 0x144fe6a80},
        {"Marker2SystemImplPlacedUserMarkerFollow", 0x144fe5920},
        {"Marker2SystemImplRemovedAllUserMarker", 0x1405c52f0},
        {"SightManagerImplInitialize", 0x149c63e20},
        {"UiControllerImplSetNoUseEquipId", 0x1496b3b50},
        {"EquipCrossEvCallIsItemNoUse", 0x145d0b630},
        {"TppUiEmblemImplEmblemEditorSystemImplCreateEmblemParameters", 0x14094c300},
        {"TppUiEmblemImplEmblemEditorSystemImplCreateEmblem", 0x146073350},
        {"TppUiEmblemImplEmblemEditorSystemImplLoadEmblemTextureInfo", 0x14607be80},
        {"FoxNtImplSessionImpl2DeleteMember", 0x143e5c940},
        {"FoxImplMessage2MessageBox2ImplSendMessageToSubscribers", 0x1435d1f00},
        {"TppUiEmblemImplEmblemEditorSystemImplDeleteTexture", 0x1460741f0},
        {"TppUiEmblemImplEmblemEditorSystemImplUnloadEmblemTextureInfo", 0x14607e250},
        {"TppGkTppGameKitModuleEnd", 0x144d18950},
        {"TppUiEmblemImplEmblemEditorSystemImplDeleteBlender", 0x146074060},
        {"TppGkEmblemManagerCreateBlender", 0x144d1e170},
        {"TppUiEmblemImplEmblemEditorSystemImplIsReady", 0x14607bd70},
        {"TppGmPlayerImplClimbActionPluginImplCheckActionState", 0x149876920},
        {"FoxGeoPathResultGetNumPoint", 0x14ce84090},

        {"HashMapFindKey", 0x142ed7be0},
        {"GetQuarkSystemTable", 0x140bff3f0},
        {"FoxStrHash32", 0x14c1bd730},
        {"FoxFindEntity", 0x14312acb0},
        {"FoxGetEntityHandle", 0x14321e540},
        {"FoxGetEntityProperty", 0x1400c4e80},
        {"FoxCreatePropertyInfo", 0x1400926a0},
        {"ValueGetAsUInt32", 0x140065480},
        {"FoxString", 0x142eaf970},
        {"FindGameObjectWithID", 0x146c95580},
        {"Soldier2ImplGetInterface", 0x149f2f3d0},
        {"PlayerInfoServiceGetPositionAtIndex", 0x14d9b7770},
        {"FoxNtSessionGetMainSession", 0x143e60970},
        {"GetSessionMemberCount", 0x143e60ef0},
        {"CloseSession", 0x146457b20},
        {"Player2GameObjectImplWarp", 0x14627c6f0},
        {"ScriptDeclVarsImplSetVarValue", 0x140ae2090},
        {"SoldierRouteAiImplPreUpdate", 0x141572270},
        {"RouteGroupImplGetEventId", 0x144b8d070},
        {"AiControllerImplAddNode", 0x140c0f230},
        {"AiControllerImplSleepNode", 0x146d1bf60},
        {"AiControllerImplWakeNode", 0x146d1c6c0},
        {"CoreAiImplGetVehicleId", 0x149170560},
        {"CoreAiImplGetVehicleRideState", 0x14a0a2ab0},
        {"CoreAiImplIsVehicleRetain", 0x14a0a3f30},
        {"SoldierImplRouteAiImplCheckVehicleAndWalkerGearGetInAndOutStep", 0x14156d590},
        {"StatusControllerImplIsSet", 0x144cba8d0},
        {"ScriptDeclVarsImplGetVarHandleWithVarIndex", 0x140ae17c0},
        {"GmGetScriptVarInfo", 0x1461f02b0},
        {"BandWidthManagerImplCalcAverageRttOfBetterHalfConnection", 0x1407e0580},
        {"BandWidthManagerImplCalcAverageLostRateOfBetterHalfConnection", 0x1407e0370},
        {"BandWidthManagerImplStartLimitState", 0x1459bf210},
        {"FoxNioMpMessageContainerGetFreeSize", 0x14c408840},
        {"FoxNioImplMpMuxImplSend", 0x141a59f30},
        {"FoxNioImplMpMuxImplRecv1", 0x141a59690},
        {"FoxNioImplMpMuxImplRecv2", 0x141a59870},
        {"FoxNtPeerControllerSend", 0x143e73b60},
        {"FoxNtImplGameSocketImplPeerIsSendPacketEmpty", 0x143eab090},
        {"FoxNtTotalControllerSend", 0x143e72910},
        {"FoxNtImplTransceiverManagerImplPeerSend", 0x14031aec0},
        {"FoxNioImplMpSocketImplSend", 0x141a5b150},
        {"FoxNioImplMpMuxImplGetTotalPayloadSize", 0x1467a3500},
        {"FoxNioMpMessageSerializerSerialize", 0x141a60a90},
        {"FoxNioMpMessageContainerCreate", 0x14c407c00},
        {"FoxNioMpMessageContainerAddMessage", 0x14c406e40},
        {"FoxNioImplSppSocketImplGetState", 0x14c2db550},
        {"FoxNtImplSyncMemoryCollectorSyncMemoryCollector", 0x143ebb4b0},
        {"FoxNtImplGameSocketBufferImplAlloc", 0x143ea6510},
        {"TppGmImplScriptDeclVarsImplOnSessionNotify", 0x140ae1bc0},
        {"FoxBitStreamWriterPrimitiveWrite", 0x143ea3d10},
        {"TppGmImplScriptDeclVarsImplGetVarHandleWithVarIndex", 0x140ae17c0},
        {"FoxNtImplTransceiverManagerImplPeerSendImpl1", 0x143e7c130},
        {"FoxNtImplTransceiverManagerImplPeerSendImpl2", 0x143e7c270},
        {"FoxNtImplTransceiverImplTransceiverImpl", 0x140323ad0},
        {"FoxNtImplGameSocketImplPeerRequestToSend", 0x1403257f0},
        {"FoxNtImplGameSocketBufferImplGameSocketBufferImpl", 0x143ea61a0},
        {"FoxNioMpMessageCreate", 0x14c407850},
        {"FoxNtImplNetworkSystemImplGetMainSession", 0x143eae4b0},
        {"FoxImplScopeAllocatorImplAlloc", 0x142f32e00},
        {"FoxScopeMemoryScopeMemory1", 0x140034710},
        {"FoxScopeMemoryScopeMemoryDtor", 0x1400347f0},
        {"TppGmImplScriptDeclVarsImplUpdate", 0x140ae2180},
        {"FoxNtImplGameSocketImplGetPacketCount", 0x143ea9a10},
        {"FoxNtImplGameSocketImplGetPacket", 0x143ea9670},
        {"FoxNtImplNetworkSystemImplCreateGameSocket", 0x143ead9d0},
        {"FoxNtNtModuleInit", 0x14d365da0},
        {"FoxNtImplGameSocketImplRequestToSendToMember", 0x143eab200},
        {"FoxNtImplGameSocketImplSetInterval", 0x143eabc30},
        {"FoxNtImplPeerCommonInitializeLastSendTime", 0x143e9da20},
        {"FoxNtImplGameSocketImplGetPacketSize", 0x143ea9db0},
        {"FoxNtImplGameSocketImplGameSocketImplDtor", 0x143ea8150},
        {"TppGmImplScriptDeclVarsImplGetVarHandle", 0x140ae1630},
        {"TppGmImplScriptDeclVarsImplScriptDeclVarsImpl", 0x146845ab0},
        {"TppGmImplScriptSystemImplGetScriptDeclVarHandle", 0x1461f4ce0},
        {"TppGmImplScriptDeclVarsImplGetVarIndexWithName", 0x146849370},
        {"TppGmGetGVars", 0x146848a40},
        {"TppGmGetSVars", 0x1468490b0},
        {"FoxNtImplSessionImpl2GetMemberInterfaceAtIndex", 0x143e61370},
        {"FoxNtImplGameSocketImplHandleMessage", 0x143eaa120},
        {"FoxNtImplPeerCommonPeerCommon", 0x143e9cf60},
        {"TppGmPlayerImplSynchronizerImplInitialize", 0x1412a6c50},
        {"TppGmImplScriptDeclVarsImplScriptDeclVarsImplDtor", 0x146845fc0},
        {"TppGmPlayerImplAnonymous_namespaceCamouflageControllerImplInitialize", 0x140fdd420},
        {"FoxNtImplTransceiverManagerImplPeerAddToSendQueue", 0x143e78970},
        {"FoxNioImplMpMuxImplSendUpdate", 0x141a5a6c0},
        {"FoxNioImplSppSocketImplSendImpl", 0x141a57b00},
        {"FoxNioImplSteamUdpSocketImplSend", 0x14c4044f0},
        {"FoxNioImplSteamUdpSocketImplRecv", 0x14c4042c0},
        {"TppUiMenuUiCommonDataManagerLoadLanguageBlock", 0x145bddb50},
        {"TppUiUtilityChangeLanguage", 0x14090f130},
        {"TppGmPlayerImplEquipControllerImplInitialize", 0x149a02ca0},
        {"TppGmPlayerImplEquipControllerImplGetEquipIdSlot", 0x1411add10},
        {"TppGmBossquietImplActionControllerImplSetCommand", 0x1417a9e40},
        {"TppGmBossquietImplActionControllerImplSetExtraActionCommand", 0x14a922d70},
        {"TppGmLiquidImplActionControllerImplSetActionTaskCompleted", 0x14bf31450},
        {"TppGmBossquietImplActionControllerImplSetActionTask", 0x14a922960},
        {"TppGmBossquietImplActionControllerImplSetNextActionTask", 0x1417aa020},
        {"TppGmBossquietImplActionControllerImplInitialize", 0x14a921790},
        {"TppGmSahelanImplActionControllerImplSetTaskParamFromActionCommand", 0x14bbbd160},
        {"TppGmImplNavigationController2ImplGetNavigator", 0x149586ed0},
        {"TppGmImplNavigationController2ImplIsCurrentRequestPrepared", 0x149588720},
        {"TppGmBossquietImplActionControllerImplCheckUseOutOfNavJump", 0x14a91ff50},
        {"TppGmImplNavigationController2ImplGetPath", 0x1495879e0},
        {"TppGmImplNavigationController2ImplGetResultState", 0x149587cd0},
        {"TppGmBossquietImplSnipeManagerImplGetOptimalLandingPosition",0x1417fa3d0},
        {"TppGmSahelanActionTaskoperatorAssign", 0x14a91f960},
        {"TppGmBossquietImplActionControllerImplUpdate", 0x14a923930},
        {"TppGmBossquietImplBasicAction2ImplPolling", 0x14b6bebe0},
        {"TppGmBossquietImplActionControllerImplUpdateActionTask", 0x14a923c70},
        {"TppGmBossquietImplActionControllerImplUpdateCommandForSingle", 0x14a923f60},
        {"TppGmBossquietImplBasicAction2ImplGetNextPositionInMoving", 0x14b6bd7c0},
        {"TppGmBossquietImplCloseCombatAiImplStepMove", 0x1417c9380},
        {"TppGmBossquietImplRecoveryAiImplStepMove", 0x1417f56b0},
        {"TppGmBossquietImplSearchAiImplStepMove", 0x1417f8200},
        {"TppGmBossquietImplCombatAiImplRequestMoveAction", 0x14b6d5970},
        {"TppGmBossquietImplSearchAiImplRequestMoveAction", 0x14b772070},
        {"TppGmBossquietImplRecoveryAiImplRequestMoveAction", 0x14b76a2f0},
        {"TppGmBossquietImplCloseCombatAiImplRequestMoveAction", 0x14b6cd920},
        {"TppGmBossquietImplAvoidAiImplSetJumpPoint", 0x14b6b87d0},
        {"TppGmImplAiControllerImplGetCoreKnowledge", 0x146d18c90},
        {"TppGmBossquietImplanonymous_namespaceLifeControllerImplUpdateLife", 0x14b73b3d0},

        {"BlockHeapAlloc", 0x143264660},
        {"BlockHeapFree", 0x1432651b0},
        {"FoxBlockProcess", 0x14006df80},
        {"FoxBlockUnload", 0x143154a00},
        {"FoxBlockReload", 0x1431533b0},
        {"FoxBlockActivate", 0x14006cb20},
        {"FoxBlockDeactivate", 0x14314a000},
        {"FoxGenerateUniqueName", 0x1400e0210},
        {"FoxBlock", 0x143145960},
        {"FoxBlockLoad", 0x143151e80},
        {"BlockMemoryAllocTail", 0x1400dbb30},
        {"BlockMemoryAllocHeap", 0x143261bf0},
        {"GetCurrentBlockMemory", 0x14328e410},
        {"FoxCreateQuark", 0x146c6a650},

        {"FoxLuaPushVector3", 0x143257590},
        {"FoxLuaPushQuat", 0x143256e30},
        {"l_AnnounceLogView", 0x145d5ded0},
        {"TppUiUiCommandAnnounceLogViewLangId", 0x1408cc280},

        {"lua_pushinteger", 0x14c1e6ef0},
        {"lua_pushstring", 0x14c1e7ee0},
        {"lua_pushboolean", 0x14c1db230},
        {"lua_getfield", 0x14c1d7320},
        {"lua_setfield", 0x14c1eabb0},
        {"lua_pcall", 0x14c1daff0},
        {"luaI_openlib", 0x14c201610},
        {"luaL_checkinteger", 0x14c1ff430},
        {"luaL_openlibs", 0x14c1fd0c0},
        {"luaL_checknumber", 0x14c1ffb30},
        {"lua_toboolean", 0x14c1ebe40},
        {"lua_createtable", 0x14c1d6320},
        {"lua_pushvalue", 0x14c1e87e0},
        {"lua_remove", 0x14c1ea0c0},
        {"luaL_checklstring", 0x14c1ff790},
        {"lua_pushnumber", 0x14c1e7dd0},

        // /*
        //                 {"StrCode64", 0x14c1bd730},
        //                 {"PathCode64", 0x14c1bd5d0},//tex TODO need to verify naming and purpose. technically this is PathFileNameExt64, but given that
        //                 PathCode
        // - without ext is likely less used than PathCode would have been a better name for PathFileNameExt64
        //                 {"FNVHash32", 0x143f33a20},
        //                 {"GetFreeRoamLangId", 0x145e60f40},
        //                 {"UpdateFOVLerp", 0x141116800},//tex: TODO: verify the return AL>RAX
        //                 {"UnkPrintFuncStubbedOut", 0x142ef2bf0},//tex: Some info printing function that has been stubbed out
        //                 {"l_StubbedOut", 0x14024a8e0},//tex: another retail stubb out to wrangle
        //                 {"nullsub_2", 0x1409c8f90},//tex: another retail stubb out to wrangle
        //                 {"LoadFileSub", 0x142f784a0},
        //                 {"LoadFile", 0x14319ea20},
        //                 {"LoadFile_01", 0x14319d620},
        //                 {"LoadFile_02", 0x14319eb70},
        //                 {"LoadFile_03", 0x1431a0130},
        //                 {"LoadFile_05", 0x14319ee10},
        //                 {"LoadPlayerPartsFpk", 0x146866c80},
        //                 {"LoadPlayerPartsParts", 0x146865f80},
        //                 {"LoadPlayerCamoFpk", 0x146864180},
        //                 {"LoadPlayerCamoFv2", 0x146863f80},
        //                 {"LoadPlayerFacialMotionFpk", 0x1468656c0},
        //                 {"LoadPlayerFacialMotionMtar", 0x146865370},
        //                 {"LoadPlayerBionicArmFpk", 0x140ae90f0},
        //                 {"LoadPlayerBionicArmFv2", 0x140ae9040},
        //                 {"CheckPlayerPartsIfShouldApplySkinToneFv2", 0x140ae9400},
        //                 {"LoadPlayerPartsSkinToneFv2", 0x140ae8560},
        //                 {"IsHeadNeededForPartsType", 0x140ae84b0},
        //                 {"IsHeadNeededForPartsTypeAndAvatar", 0x140ae8500},
        //                 {"LoadPlayerSnakeFaceFpk", 0x140ae8df0},
        //                 {"LoadPlayerSnakeFaceFv2", 0x140ae8ce0},
        //                 {"LoadAvatarOgreHornFpk", 0x14685dd50},
        //                 {"LoadAvatarOgreHornFv2", 0x14685da20},
        //                 {"LoadBuddyMainFile", 0x140a461d0},
        //                 {"LoadBuddyQuietWeaponFpk", 0x1464d5dc0},
        //                 {"LoadBuddyWalkerGearArmFpk", 0x1464d3fc0},
        //                 {"LoadBuddyWalkerGearHeadFpk", 0x1464d44a0},
        //                 {"LoadBuddyWalkerGearWeaponFpk", 0x1464d47f0},
        //                 {"LoadDefaultFpksFunc", 0x143151e80},
        //                 {"PreparePlayerVehicleInSortie", 0x146a95640},
        //                 {"PreparePlayerVehicleInGame", 0x146a95380},
        //                 {"LoadDefaultFpkPtrFunc", 0x14314bda0},
        //                 {"LoadAllVehicleCamoFpks", 0x145006860},
        //                 {"CreateInPlace", 0x142e8a5d0},
        //                 {"lua_newstate", 0x14c1fc960},//tex could use default implementation, but may want to hook if we want to see what the engine is up to
        //                 {"lua_close", 0x14c1fc380},
        //                 {"lua_newthread", 0x14c1d9d90},
        //                 {"lua_atpanic", 0x14c1d5120},
        //                 //{"lua_gettop", USING_CODE},
        //                 {"lua_settop", 0x14c1ebbe0},
        //                 {"lua_insert", 0x14c1d8150},
        //                 {"lua_replace", 0x14c1ea370},
        //                 {"lua_checkstack", 0x14c1d5900},
        //                 {"lua_xmove", 0x14c1edcd0},
        //                 {"lua_isnumber", 0x14c1d8c90},
        //                 {"lua_isstring", 0x14c1d9250},
        //                 {"lua_iscfunction", 0x141a11650},
        //                 //{"lua_isuserdata", USING_CODE},//tex: No calls in lua distro, so may be hard to find, or have been culled by compilation
        //                 {"lua_type", 0x14c1ed760},
        //                 //{"lua_typename", USING_CODE},
        //                 //{"lua_equal", NOT_FOUND},//tex: lua implementation goes a bit deeper than I'm happy with to use at the moment. No calls in lua
        //                 distro,
        //  so may be hard to find, or have been culled by compilation
        //                 {"lua_rawequal", 0x14c1e8d70},
        //                 {"lua_lessthan", 0x14c1d9890},
        //                 {"lua_tonumber", 0x14c1ecdd0},
        //                 {"lua_tointeger", 0x14c1ec760},
        //                 {"lua_toboolean", 0x14c1ebe40},
        //                 {"lua_tolstring", 0x14c1eca70},
        //                 {"lua_objlen", 0x14c1da960},
        //                 {"lua_tocfunction", 0x14c1ec560},
        //                 {"lua_touserdata", 0x14c1ed4b0},
        //                 {"lua_tothread", 0x14c1ed3c0},
        //                 {"lua_topointer", 0x14c1ed230},
        //                 {"lua_pushnil", 0x14c1e7cc0},
        //                 {"lua_pushlstring", 0x14c1e7310},
        //                 {"lua_pushvfstring", 0x14c1e8b10},
        //                 {"lua_pushfstring", 0x14c1e6a70},
        //                 {"lua_pushcclosure", 0x14c1e67b0},
        //                 {"lua_pushlightuserdata", 0x14c1e71b0},
        //                 {"lua_pushthread", 0x14c1e86a0},
        //                 {"lua_gettable", 0x14c1d7c10},
        //                 {"lua_rawget", 0x14c1e9190},
        //                 {"lua_rawgeti", 0x14c1e9320},//via MACRO lua_getref
        //                 {"lua_newuserdata", 0x14c1d9f80},
        //                 {"lua_getmetatable", 0x14c1d79b0},
        //                 {"lua_getfenv", 0x14c1d7160},
        //                 {"lua_settable", 0x14c1eb2b0},
        //                 {"lua_rawset", 0x14c1e9cf0},
        //                 {"lua_rawseti", 0x14c1e9ff0},
        //                 {"lua_setmetatable", 0x14c1eb040},
        //                 {"lua_setfenv", 0x14c1eaa00},
        //                 {"lua_call", 0x14c1d5690},
        //                 {"lua_cpcall", 0x146c7dd00},
        //                 {"lua_load", 0x14c1d99c0},
        //                 {"lua_dump", 0x14c1d6690},
        //                 //{"lua_yield", USING_CODE},//tex: DEBUGNOW uses lua_lock, may not be a good idea due to thread issues and not knowing what the
        //                 engine
        //  is doing to the state. Seems to be inlined in luaB_yield (it's only call in lua distro)
        //                 {"lua_resume", 0x14c1f0d80},
        //                 //{"lua_status", USING_CODE},//tex DEBUGNOW hmm, address range. ida finds this as sig though, but the prior functions have entries in
        // .pdata which put them in the same range (0x14cdb)
        //                 {"lua_gc", 0x141a11220},
        //                 {"lua_error", 0x14c1d6c90},
        //                 {"lua_next", 0x14c1da770},
        //                 {"lua_concat", 0x14c1d5d50},
        //                 //{"lua_getallocf", NO_USE},//tex don't really want to mess with allocator function anyway, DEBUGNOW no calls in lua distro, so may
        //                 be
        //  hard to find, or have been culled by compilation
        //                 //{"lua_setallocf", NO_USE},//tex don't really want to mess with allocator function anyway
        //                 //{"lua_setlevel", NO_USE},//tex: labeled by lua as a hack to be removed in lua 5.2
        //                 {"lua_getstack", 0x14c20fbd0},
        //                 {"lua_getinfo", 0x14c20f650},
        //                 {"lua_getlocal", 0x14c20f880},
        //                 {"lua_setlocal", 0x14c20fff0},
        //                 {"lua_getupvalue", 0x14c1d7ea0},
        //                 {"lua_setupvalue", 0x141a12240},
        //                 {"lua_sethook", 0x14c20fde0},
        //                 //{"lua_gethook", USING_CODE},
        //                 //{"lua_gethookmask", USING_CODE},
        //                 //{"lua_gethookcount", USING_CODE},
        //                 //{"luaL_register", USING_CODE},
        //                 {"luaL_getmetafield", 0x14c200d50},
        //                 {"luaL_callmeta", 0x14c1fec20},
        //                 {"luaL_typerror", 0x141a184c0},
        //                 {"luaL_argerror", 0x14c1fe5f0},
        //                 {"luaL_optlstring", 0x14c201de0},
        //                 //{"luaL_optnumber", USING_CODE},//tex: Only use in os_difftime, but decompilation is giving a bunch more params than it usually
        //                 takes
        //                 {"luaL_optinteger", 0x14c201a70},
        //                 {"luaL_checkstack", 0x14c200010},
        //                 {"luaL_checktype", 0x14c2004c0},
        //                 {"luaL_checkany", 0x14c1ff2f0},
        //                 {"luaL_newmetatable", 0x14c2013c0},
        //                 {"luaL_checkudata", 0x14c200630},
        //                 {"luaL_where", 0x14c203350},
        //                 {"luaL_error", 0x14c2008f0},
        //                 {"luaL_checkoption", 0x14c1ffd60},
        //                 //{"luaL_ref", USING_CODE},//tex: Unsure on this address. No uses in lua dist, found a function that looks much like it, but it was
        //  undefined, and has a errant param
        //                 //{"luaL_unref", USING_CODE},
        //                 {"luaL_loadfile", 0x141a17b90},
        //                 {"luaL_loadbuffer", 0x14c200f90},
        //                 //{"luaL_loadstring", USING_CODE},
        //                 {"luaL_newstate", 0x14c201490},
        //                 {"luaL_gsub", 0x141a17710},
        //                 {"luaL_findtable", 0x14c200aa0},
        //                 //{"luaL_buffinit", USING_CODE},
        //                 {"luaL_prepbuffer", 0x14c202140},
        //                 {"luaL_addlstring", 0x141a16e70},
        //                 //{"luaL_addstring", USING_CODE},//tex: Only call is in luaL_gsub, seems to have been optimized out as the function just wraps
        // luaL_addlstring
        //                 {"luaL_addvalue", 0x14c1fd9b0},
        //                 {"luaL_pushresult", 0x14c202280},
        //                 {"luaopen_base", 0x14c21d5c0},
        //                 {"luaopen_table", 0x14c21d8d0},
        //                 {"luaopen_io", 0x14c21da00},
        //                 {"luaopen_os", 0x14c21e020},
        //                 {"luaopen_string", 0x14c21e720},
        //                 {"luaopen_math", 0x14c21e800},
        //                 {"luaopen_debug", 0x14c21ea00},
        //                 {"luaopen_package", 0x14c21ee20},
        //                 */
    };
}

#endif
""";

    // dynamitePatches.cpp
    static final String PATCHES_1_0_15_3 = """
#include "dynamite.h"
#include "patch.h"
#include <vector>

namespace Dynamite {
    std::vector<Patch> Dynamite::GetPatches() {
        return {
            {
                .address = 0x140ffa9ff,
                .expected = {0x74, 0x07}, // JZ 0x140ffaa08
                .patch = {0xeb, 0x07},    // JMP 0x140ffaa08
                .description = "Apply damage to player no matter what, "
                               "tpp::gm::player::impl::`anonymous_namespace'::DefenseCallback::TargetCallbackExec",
            },
            {
                .address = 0x141378209,
                .expected = {0x74, 0x5c}, // JZ 0x141378267
                .patch = {0x48, 0x90},    // NOP
                .description = "Attempt to fix damage (not needed?), "
                               "tpp::gm::soldier::impl::ActionCoreImpl::ExecGrazeCallback",
            },
            {
                .address = 0x149f57ac7,
                .expected = {0x74, 0x1a}, // JZ 0x149f57ae3
                .patch = {0xeb, 0x1a},    // JMP 0x149f57ae3
                .description = "Always update action task, "
                               "tpp::gm::soldier::impl::ActionControllerImpl::UpdateActionTask",
            },
            {
                .address = 0x1417a200e,
                .expected = {0x74, 0x19}, // JZ 0x1417a2029
                .patch = {0x48, 0x90},    // NOP
                .description = "Always respawn player no matter what, "
                               "tpp::gm::player::impl::RespawnActionPluginImpl::UpdatePlaySubState",
            },
            {
                .address = 0x14133d9cb,
                .expected = {0x0f, 0x84, 0xdc, 0x03, 0x00, 0x00}, // JZ 0x14133ddad
                .patch = {0x66, 0x48, 0x90, 0x66, 0x48, 0x90},    // NOP NOP
                .description = "Skip sight controller host check, always run host code, ignore IsHost call, "
                               "tpp::gm::impl::`anonymous_namespace`::SightControllerImpl::Update. "
                               "Without it soldiers will lose track of client after raising an alert.",
            },
            {
                .address = 0x140ebcfc4,
                .expected = {0x74, 0x2e}, // JZ 0x140ebcff4
                .patch = {0x48, 0x90},    // NOP
                .description = "Client always uses host code for SetHostage2Flag lua command, "
                               "tpp::gm::hostage::impl::Hostage2FlagInfoImpl::RequestSetAndSyncImpl",
            },
            {
                .address = 0x140887905,
                .expected = {0x74, 0x1c}, // JZ 0x140887923
                .patch = {0xeb, 0x1c},    // JMP 0x140887923
                .description = "Do not send sneak result (online request) on game over, "
                               "tpp::ui::menu::GameOverEvCall::UpdateGameOver",
            },
            {
                .address = 0x1416026ce,
                .expected = {0xff, 0x90, 0x68, 0x03, 0x00, 0x00}, // CALL qword ptr RAX+0x368
                .patch = {0xf2, 0x48, 0x90, 0xf2, 0x48, 0x90},    // NOP NOP
                .description = "Do not send sneak result on mission end (fob results screen)"
                               "tpp::ui::hud::impl::TppUIFobResultImpl::UpdateFobResult",
            },
            {
                .address = 0x144e42a62,
                .expected = {0x0f, 0x094, 0xd0}, // SETZ AL
                .patch = {0x40, 0xb0, 0x01},     // MOV AL, 0x01
                .description = "Trap check is player and local is always true #2, fix crash on enter"
                               "tpp::TrapCheckIsPlayerAndLocalCallback::ExecCallback",
            },
            {
                .address = 0x144e42a8e,
                .expected = {0x30, 0xc0}, // XOR AL, AL
                .patch = {0xb0, 0x01},    // MOV AL, 0x1
                .description = "Trap check is player and local is always true, fix crash on enter"
                               "tpp::TrapCheckIsPlayerAndHostCallback::ExecCallback",
            },
            {
                .address = 0x144e46f45,
                .expected = {0x30, 0xc0}, // XOR AL, AL
                .patch = {0xb0, 0x01},    // MOV AL, 0x1
                .description = "Trap check is player and host is always true, fix crash on enter"
                               "tpp::TrapCheckIsPlayerAndHostCallback",
            },
            {
                .address = 0x14625fd1a,
                .expected = {0x75, 0xd}, // JNZ 0x14625fd29
                .patch = {0x48, 0x90},   // NOP
                .description = "DoesFobGhostPlayer remove mission ID check"
                               "tpp::gm::player::impl::Player2GameObjectImpl::DoesFobGhostPlayer"
                               "without it mission won't load (infinite loading)",
            },
            {
                .address = 0x1459b60b5,
                // clang-format off
                    .expected =
                        {
                            0x48, 0x83, 0x79, 0x58, 0x00, // CMP qword ptr [RCX + 0x58], 0x0
                            0x48, 0x89, 0xcb, // MOV RBX, RCX
                            0x75, 0x09, // JMP LAB_1459b60c8
                        },
                    .patch =
                        {
                            0xf2, 0x48, 0x90, // NOP
                            0x48, 0x90, // NOP
                            0x48, 0x89, 0xcb, // MOV RBX, RCX
                            0x48, 0x90, // NOP
                        },
                // clang-format on
                .description = "Always start fob p2p resolver, ignore exists check (not needed?)"
                               "tpp::net::Daemon::StarFobP2pNameResolver",
            },
            {
                .address = 0x140da58e5,
                .expected = {0x0f, 0x84, 0x41, 0x05, 0x00, 0x00}, // JZ LAB_140da5e2c
                .patch = {0x66, 0x48, 0x90, 0x66, 0x48, 0x90},    // NOP NOP
                .description =
                    "Always run host damage controller implementation"
                    "Fixes crash on shooting animals (like goats in PITCH BLACK after the village at {-711.90826416016, 5.1010074615479, 661.36602783203})"
                    "tpp::gm::impl::`anonymous_namespace'::DamageControllerImpl::Update",
            },
            {
                .address = 0x146457b68,
                .expected = {0x75, 0x13}, // JNZ LAB_146457b7d
                .patch = {0x48, 0x90},    // NOP
                .description = "always run full CloseSession code, ignore mission code check"
                               "tpp::gm::tool::`anonymous_namespace'::CloseSession",
            },
            {
                .address = 0x14163fcda,
                .expected = {0x0f, 0x84, 0xa2, 0x01, 0x00, 0x00}, // JZ LAB_14163fe82
                .patch = {0x66, 0x48, 0x90, 0x66, 0x48, 0x90},    // NOP NOP
                .description =
                    "add Quiet and Ocelot to staff list in sortie by ignoring tpp::ui::menu::impl::MissionPreparationSystemImpl::IsFobMissionMode check result"
                    "tpp::ui::menu::impl::CharacterSelectorCallbackImpl::SetupStaffList",

            },
            {
                .address = 0x1409cc6c0,
                .expected = {0x0f, 0x85, 0x9c, 0x07, 0x00, 0x00}, // JNZ LAB_1409cce62
                .patch = {0x48, 0xe9, 0x9c, 0x07, 0x00, 0x00},    // JMP LAB_1409cce62
                .description = "skip some check that resets player to Snake from Quiet/Ocelot"
                               "tpp::gm::player::impl::Player2GameObjectImpl::UpdatePartsStatus",
            },
            {
                .address = 0x149cfba54,
                .expected = {0x74, 0x10}, // JZ LAB_149cfba66
                .patch = {0x48, 0x90},    // NOP
                .description = "skip check and call FUN_1411b4350 that sets up dual revolvers for Ocelot"
                               "tpp::gm::player::impl::UnrealUpdaterImpl::PreUpdate",
            },
            {
                .address = 0x149f4f17b,
                .expected = {0x74, 0x07}, // JZ LAB_149f4f184
                .patch = {0xeb, 0x07},    // JMP LAB_149f4f184
                .description = "always use non-fob function to update cp member status"
                               "tpp::gm::soldier::impl::Soldier2Impl::UpdateCpMemberStatus",
            },

            {
                .address = 0x1409c9a13,
                // clang-format off
                .expected = {
                    0x84, 0xc0,             // TEST AL, AL
                    0x4c, 0x0f, 0x45, 0xc1, // CMOVNZ R8,RCX
                },
                .patch = {
                    0x49, 0x89, 0xc8, // MOV        R8,RCX
                    0x66, 0x48, 0x90, // NOP
                },
                // clang-format on
                .description = "always apply opponent (or partner) emblem"
                               "tpp::gm::player::impl::Player2Impl::SetEmblemTexture",
            },
            {
                .address = 0x149c1758d,
                .expected = {0x72, 0xf7}, // JC LAB_149c17586
                .patch = {0x48, 0x90},    // NOP
                .description = "exit motion fixing loop immediately"
                               "tpp::gm::player::impl::RideWalkerGearActionImpl::SyncMotionWithWalkerGearMotion",
            },
            {
                .address = 0x14a62cf4e,
                .expected = {0x74, 0x7b}, // JZ LAB_14a62cfcb
                .patch = {0xeb, 0x7b},    // JMP LAB_14a62cfcb
                .description = "skip walker gear equip sync handling"
                               "tpp::gm::walkergear::impl::ActionCoreImpl::ReceiveEquipInfo",
            },
            {
                .address = 0x1417cce2a,
                .expected = {0x0f, 0x85, 0xe0, 0x00, 0x00, 0x00}, // JNZ LAB_1417ccf10
                .patch = {0x48, 0xe9, 0xe0, 0x00, 0x00, 0x00},    // JMP LAB_1417ccf10
                .description = "Boss Quiet always jumps instead of running"
                               "tpp::gm::bossquiet::impl::CombatAiImpl::StepMove",
            },
            {
                .address = 0x1417ccd72,
                .expected = {0x0f, 0x85, 0xab, 0x01, 0x00, 0x00}, // JNZ LAB_1417ccf23
                .patch = {0x0f, 0x85, 0x74, 0x01, 0x00, 0x00},    // JNZ LAB_1417cceec
                .description = "Boss Quiet always jumps instead of running, patch 2"
                               "tpp::gm::bossquiet::impl::CombatAiImpl::StepMove",
            },
            {
                .address = 0x1417d54f7,
                .expected = {0x0f, 0x84, 0xf9, 0x02, 0x00, 0x00}, // JZ LAB_1417d57f6
                .patch = {0x66, 0x48, 0x90, 0x66, 0x48, 0x90},    // NOP NOP
                .description = "ignore host check to always process Boss Quiet damage locally"
                               "tpp::gm::bossquiet::impl::`anonymous_namespace'::DamageHandlerImpl::ProcessDamages",
            },
            // {
            //     .address = 0x1409b9d3b,
            //     .expected = {0x74, 0x0a}, // JZ LAB_1409b9d47
            //     .patch = {0xeb, 0x0a},    // JMP LAB_1409b9d47
            //     .description = "skip IS_ONLINE check for player action status"
            //                    "allows player to climb wall cracks"
            //                    "this patch also makes player invisible and cannot be applied"
            //                    "tpp::gm::player::impl::Player2GameObjectImpl::Player2GameObjectImpl",
            // },

            // {
            //     .address = 0x1413536b6,
            //     // clang-format off
            //     .expected = {
            //         0x8b, 0xc1,          // MOV        EAX,ECX
            //         0xd1, 0xe8,          // SHR        EAX,0x1
            //         0xf7, 0xd0,          // NOT        EAX
            //         0x33, 0xc1,          // XOR        EAX,ECX
            //         0x83, 0xe0, 0x02,    // AND        EAX,0x2
            //         0x33, 0xc1,          // XOR        EAX,ECX
            //     },
            //     .patch = {
            //         0xb8, 0x02, 0x00, 0x00, 0x00, // MOV        EAX,0x2
            //         0x66, 0x48, 0x90 ,            // NOP
            //         0x66, 0x48, 0x90,             // NOP
            //         0x48, 0x90,                   // NOP
            //     },
            //     // clang-format on
            //     .description = "ignore IS_ONLINE check at 1409e6f18, always set flag based on that check to 2 instead of calculated 4"
            //                    "allows soldiers to get in vehicles"
            //                    "this patch also breaks client detection and cannot be applied"
            //                    "tpp::gm::soldier::impl::Soldier2Impl::Initialize",
            // },
        };
    }

    bool Dynamite::PatchMasterServerURL(const std::string &url) {
        // a better approach would be changing string address in tpp::net::LoginUtility::Update
        // that will allow longer addresses
        // lets keep it simple for now

        if (url.length() > 69) {
            return false;
        }
        // clang-format off
        const auto expected = std::vector<int16_t>{0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x6d, 0x67, 0x73,
            0x74, 0x70, 0x70, 0x2d, 0x67, 0x61, 0x6d, 0x65, 0x2e, 0x6b, 0x6f, 0x6e,
            0x61, 0x6d, 0x69, 0x6f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2e, 0x63, 0x6f,
            0x6d, 0x2f, 0x74, 0x70, 0x70, 0x73, 0x74, 0x6d, 0x2f, 0x67, 0x61, 0x74,
            0x65, 0x0}; //  "https://mgstpp-game.konamionline.com/tppstm/gate\\0"
        // clang-format on

        auto patch = std::vector<int16_t>();
        for (auto v : url) {
            patch.push_back(v);
        }
        patch.push_back(0);

        auto p = Patch{
            .address = 0x142218770,
            .expected = expected,
            .patch = patch,
            .description = "override master server url",
        };

        return p.Apply();
    }
}
""";

    // mgsvtpp_addresses_1_0_15_4_en.h
    static final String ADDRESSES_1_0_15_4 = """
#ifndef HOOK_DYNAMITE_MGSVTPP_ADDRESSES_1_0_15_4
#define HOOK_DYNAMITE_MGSVTPP_ADDRESSES_1_0_15_4

#include <cstdint>
#include <map>
#include <string>

// Porting worksheet for game version 1.0.15.4 (June 9, 2026 update), not used yet.
// 18 of 202 addresses are known: taken by name from entries IHHook uses on 1.0.15.4
// (MIT, https://github.com/Phobos1641/mgs5-ihhook, eaeb079), where 1.0.15.3 addresses match this mod's table.
// Entries IHHook keeps commented out are not taken, some of them are stale 1.0.15.3 copies.
// Code layout changed between versions, missing addresses can't be derived from 1.0.15.3 ones by offset.
// Byte patches in dynamitePatches.cpp and master server url patch must be found for 1.0.15.4 as well.
// See docs/PORTING.md, hook/ghidra/DynamitePort.java rewrites this file keeping active entries.

namespace Dynamite {
    inline std::map<std::string, uint64_t> mgsvtpp_adresses_1_0_15_4_en{
        // {"IsDefenseTeamByOnlineFobLocal", 0x0}, // not found, 1.0.15.3: 0x14d9ba3b0
        // {"IsOffenseTeamByOnlineFobLocal", 0x0}, // not found, 1.0.15.3: 0x141e02e40
        // {"CreateHostSession", 0x0}, // not found, 1.0.15.3: 0x1459f3e20
        // {"NetworkSystemCreateHostSession", 0x0}, // not found, 1.0.15.3: 0x14da33790
        // {"CreateClientSession", 0x0}, // not found, 1.0.15.3: 0x1459f3910
        // {"SetSteamId", 0x0}, // not found, 1.0.15.3: 0x14c404640
        // {"FobTargetCtor", 0x0}, // not found, 1.0.15.3: 0x1459ed160
        // {"SessionConnectInfoCtor", 0x0}, // not found, 1.0.15.3: 0x1459edf00
        // {"NetInfoCreateSession", 0x0}, // not found, 1.0.15.3: 0x14da5c070
        // {"IsConnectReady", 0x0}, // not found, 1.0.15.3: 0x1459d0cc0
        // {"UpdateClientEstablished", 0x0}, // not found, 1.0.15.3: 0x140316610
        // {"SessionImpl2IsHost", 0x0}, // not found, 1.0.15.3: 0x143e64400
        // {"GetFobOffensePlayerInstanceIndex", 0x0}, // not found, 1.0.15.3: 0x14d9b00e0
        // {"GetFobDefensePlayerInstanceIndex", 0x0}, // not found, 1.0.15.3: 0x14d9afbc0
        // {"CommandPost2ImplGetAvailableMemberCount", 0x0}, // not found, 1.0.15.3: 0x1472a0500
        // {"CommandPost2ImplGetMaxCpCount", 0x0}, // not found, 1.0.15.3: 0x140c93de0
        // {"GetUiMarkerTypeFromSystemType2", 0x0}, // not found, 1.0.15.3: 0x140934580
        // {"SightManagerImplSetMarker", 0x0}, // not found, 1.0.15.3: 0x149c687d0
        // {"SteamUdpSocketImplOnP2PSessionRequest", 0x0}, // not found, 1.0.15.3: 0x14c4040c0
        // {"MessageBufferAddMessage", 0x0}, // not found, 1.0.15.3: 0x1435ce000
        // {"AddLocalDamage", 0x0}, // not found, 1.0.15.3: 0x141192af0
        // {"DamageControllerImplInitialize", 0x0}, // not found, 1.0.15.3: 0x14991a290
        // {"SynchronizerImplGetDamage", 0x0}, // not found, 1.0.15.3: 0x149cb4c70
        // {"Marker2SystemImpl", 0x0}, // not found, 1.0.15.3: 0x144fdb110
        // {"Marker2SystemImplPlacedUserMarkerFixed", 0x0}, // not found, 1.0.15.3: 0x144fe5400
        // {"GetLocalPlayerID", 0x0}, // not found, 1.0.15.3: 0x144c972c0
        // {"RemoveUserMarker", 0x0}, // not found, 1.0.15.3: 0x1460706a0
        // {"EquipHudSystemImplInitData", 0x0}, // not found, 1.0.15.3: 0x14606c570
        // {"Marker2SystemImplRemovedUserMarker", 0x0}, // not found, 1.0.15.3: 0x144fe6a80
        // {"Marker2SystemImplPlacedUserMarkerFollow", 0x0}, // not found, 1.0.15.3: 0x144fe5920
        // {"Marker2SystemImplRemovedAllUserMarker", 0x0}, // not found, 1.0.15.3: 0x1405c52f0
        // {"SightManagerImplInitialize", 0x0}, // not found, 1.0.15.3: 0x149c63e20
        // {"UiControllerImplSetNoUseEquipId", 0x0}, // not found, 1.0.15.3: 0x1496b3b50
        // {"EquipCrossEvCallIsItemNoUse", 0x0}, // not found, 1.0.15.3: 0x145d0b630
        // {"TppUiEmblemImplEmblemEditorSystemImplCreateEmblemParameters", 0x0}, // not found, 1.0.15.3: 0x14094c300
        // {"TppUiEmblemImplEmblemEditorSystemImplCreateEmblem", 0x0}, // not found, 1.0.15.3: 0x146073350
        // {"TppUiEmblemImplEmblemEditorSystemImplLoadEmblemTextureInfo", 0x0}, // not found, 1.0.15.3: 0x14607be80
        // {"FoxNtImplSessionImpl2DeleteMember", 0x0}, // not found, 1.0.15.3: 0x143e5c940
        // {"FoxImplMessage2MessageBox2ImplSendMessageToSubscribers", 0x0}, // not found, 1.0.15.3: 0x1435d1f00
        // {"TppUiEmblemImplEmblemEditorSystemImplDeleteTexture", 0x0}, // not found, 1.0.15.3: 0x1460741f0
        // {"TppUiEmblemImplEmblemEditorSystemImplUnloadEmblemTextureInfo", 0x0}, // not found, 1.0.15.3: 0x14607e250
        // {"TppGkTppGameKitModuleEnd", 0x0}, // not found, 1.0.15.3: 0x144d18950
        // {"TppUiEmblemImplEmblemEditorSystemImplDeleteBlender", 0x0}, // not found, 1.0.15.3: 0x146074060
        // {"TppGkEmblemManagerCreateBlender", 0x0}, // not found, 1.0.15.3: 0x144d1e170
        // {"TppUiEmblemImplEmblemEditorSystemImplIsReady", 0x0}, // not found, 1.0.15.3: 0x14607bd70
        // {"TppGmPlayerImplClimbActionPluginImplCheckActionState", 0x0}, // not found, 1.0.15.3: 0x149876920
        // {"FoxGeoPathResultGetNumPoint", 0x0}, // not found, 1.0.15.3: 0x14ce84090

        // {"HashMapFindKey", 0x0}, // not found, 1.0.15.3: 0x142ed7be0
        // {"GetQuarkSystemTable", 0x0}, // not found, 1.0.15.3: 0x140bff3f0
        // {"FoxStrHash32", 0x0}, // not found, 1.0.15.3: 0x14c1bd730
        // {"FoxFindEntity", 0x0}, // not found, 1.0.15.3: 0x14312acb0
        // {"FoxGetEntityHandle", 0x0}, // not found, 1.0.15.3: 0x14321e540
        // {"FoxGetEntityProperty", 0x0}, // not found, 1.0.15.3: 0x1400c4e80
        // {"FoxCreatePropertyInfo", 0x0}, // not found, 1.0.15.3: 0x1400926a0
        // {"ValueGetAsUInt32", 0x0}, // not found, 1.0.15.3: 0x140065480
        // {"FoxString", 0x0}, // not found, 1.0.15.3: 0x142eaf970
        // {"FindGameObjectWithID", 0x0}, // not found, 1.0.15.3: 0x146c95580
        // {"Soldier2ImplGetInterface", 0x0}, // not found, 1.0.15.3: 0x149f2f3d0
        // {"PlayerInfoServiceGetPositionAtIndex", 0x0}, // not found, 1.0.15.3: 0x14d9b7770
        // {"FoxNtSessionGetMainSession", 0x0}, // not found, 1.0.15.3: 0x143e60970
        // {"GetSessionMemberCount", 0x0}, // not found, 1.0.15.3: 0x143e60ef0
        // {"CloseSession", 0x0}, // not found, 1.0.15.3: 0x146457b20
        // {"Player2GameObjectImplWarp", 0x0}, // not found, 1.0.15.3: 0x14627c6f0
        // {"ScriptDeclVarsImplSetVarValue", 0x0}, // not found, 1.0.15.3: 0x140ae2090
        // {"SoldierRouteAiImplPreUpdate", 0x0}, // not found, 1.0.15.3: 0x141572270
        // {"RouteGroupImplGetEventId", 0x0}, // not found, 1.0.15.3: 0x144b8d070
        // {"AiControllerImplAddNode", 0x0}, // not found, 1.0.15.3: 0x140c0f230
        // {"AiControllerImplSleepNode", 0x0}, // not found, 1.0.15.3: 0x146d1bf60
        // {"AiControllerImplWakeNode", 0x0}, // not found, 1.0.15.3: 0x146d1c6c0
        // {"CoreAiImplGetVehicleId", 0x0}, // not found, 1.0.15.3: 0x149170560
        // {"CoreAiImplGetVehicleRideState", 0x0}, // not found, 1.0.15.3: 0x14a0a2ab0
        // {"CoreAiImplIsVehicleRetain", 0x0}, // not found, 1.0.15.3: 0x14a0a3f30
        // {"SoldierImplRouteAiImplCheckVehicleAndWalkerGearGetInAndOutStep", 0x0}, // not found, 1.0.15.3: 0x14156d590
        // {"StatusControllerImplIsSet", 0x0}, // not found, 1.0.15.3: 0x144cba8d0
        // {"ScriptDeclVarsImplGetVarHandleWithVarIndex", 0x0}, // not found, 1.0.15.3: 0x140ae17c0
        // {"GmGetScriptVarInfo", 0x0}, // not found, 1.0.15.3: 0x1461f02b0
        // {"BandWidthManagerImplCalcAverageRttOfBetterHalfConnection", 0x0}, // not found, 1.0.15.3: 0x1407e0580
        // {"BandWidthManagerImplCalcAverageLostRateOfBetterHalfConnection", 0x0}, // not found, 1.0.15.3: 0x1407e0370
        // {"BandWidthManagerImplStartLimitState", 0x0}, // not found, 1.0.15.3: 0x1459bf210
        // {"FoxNioMpMessageContainerGetFreeSize", 0x0}, // not found, 1.0.15.3: 0x14c408840
        // {"FoxNioImplMpMuxImplSend", 0x0}, // not found, 1.0.15.3: 0x141a59f30
        // {"FoxNioImplMpMuxImplRecv1", 0x0}, // not found, 1.0.15.3: 0x141a59690
        // {"FoxNioImplMpMuxImplRecv2", 0x0}, // not found, 1.0.15.3: 0x141a59870
        // {"FoxNtPeerControllerSend", 0x0}, // not found, 1.0.15.3: 0x143e73b60
        // {"FoxNtImplGameSocketImplPeerIsSendPacketEmpty", 0x0}, // not found, 1.0.15.3: 0x143eab090
        // {"FoxNtTotalControllerSend", 0x0}, // not found, 1.0.15.3: 0x143e72910
        // {"FoxNtImplTransceiverManagerImplPeerSend", 0x0}, // not found, 1.0.15.3: 0x14031aec0
        // {"FoxNioImplMpSocketImplSend", 0x0}, // not found, 1.0.15.3: 0x141a5b150
        // {"FoxNioImplMpMuxImplGetTotalPayloadSize", 0x0}, // not found, 1.0.15.3: 0x1467a3500
        // {"FoxNioMpMessageSerializerSerialize", 0x0}, // not found, 1.0.15.3: 0x141a60a90
        // {"FoxNioMpMessageContainerCreate", 0x0}, // not found, 1.0.15.3: 0x14c407c00
        // {"FoxNioMpMessageContainerAddMessage", 0x0}, // not found, 1.0.15.3: 0x14c406e40
        // {"FoxNioImplSppSocketImplGetState", 0x0}, // not found, 1.0.15.3: 0x14c2db550
        // {"FoxNtImplSyncMemoryCollectorSyncMemoryCollector", 0x0}, // not found, 1.0.15.3: 0x143ebb4b0
        // {"FoxNtImplGameSocketBufferImplAlloc", 0x0}, // not found, 1.0.15.3: 0x143ea6510
        // {"TppGmImplScriptDeclVarsImplOnSessionNotify", 0x0}, // not found, 1.0.15.3: 0x140ae1bc0
        // {"FoxBitStreamWriterPrimitiveWrite", 0x0}, // not found, 1.0.15.3: 0x143ea3d10
        // {"TppGmImplScriptDeclVarsImplGetVarHandleWithVarIndex", 0x0}, // not found, 1.0.15.3: 0x140ae17c0
        // {"FoxNtImplTransceiverManagerImplPeerSendImpl1", 0x0}, // not found, 1.0.15.3: 0x143e7c130
        // {"FoxNtImplTransceiverManagerImplPeerSendImpl2", 0x0}, // not found, 1.0.15.3: 0x143e7c270
        // {"FoxNtImplTransceiverImplTransceiverImpl", 0x0}, // not found, 1.0.15.3: 0x140323ad0
        // {"FoxNtImplGameSocketImplPeerRequestToSend", 0x0}, // not found, 1.0.15.3: 0x1403257f0
        // {"FoxNtImplGameSocketBufferImplGameSocketBufferImpl", 0x0}, // not found, 1.0.15.3: 0x143ea61a0
        // {"FoxNioMpMessageCreate", 0x0}, // not found, 1.0.15.3: 0x14c407850
        // {"FoxNtImplNetworkSystemImplGetMainSession", 0x0}, // not found, 1.0.15.3: 0x143eae4b0
        // {"FoxImplScopeAllocatorImplAlloc", 0x0}, // not found, 1.0.15.3: 0x142f32e00
        // {"FoxScopeMemoryScopeMemory1", 0x0}, // not found, 1.0.15.3: 0x140034710
        // {"FoxScopeMemoryScopeMemoryDtor", 0x0}, // not found, 1.0.15.3: 0x1400347f0
        // {"TppGmImplScriptDeclVarsImplUpdate", 0x0}, // not found, 1.0.15.3: 0x140ae2180
        // {"FoxNtImplGameSocketImplGetPacketCount", 0x0}, // not found, 1.0.15.3: 0x143ea9a10
        // {"FoxNtImplGameSocketImplGetPacket", 0x0}, // not found, 1.0.15.3: 0x143ea9670
        // {"FoxNtImplNetworkSystemImplCreateGameSocket", 0x0}, // not found, 1.0.15.3: 0x143ead9d0
        // {"FoxNtNtModuleInit", 0x0}, // not found, 1.0.15.3: 0x14d365da0
        // {"FoxNtImplGameSocketImplRequestToSendToMember", 0x0}, // not found, 1.0.15.3: 0x143eab200
        // {"FoxNtImplGameSocketImplSetInterval", 0x0}, // not found, 1.0.15.3: 0x143eabc30
        // {"FoxNtImplPeerCommonInitializeLastSendTime", 0x0}, // not found, 1.0.15.3: 0x143e9da20
        // {"FoxNtImplGameSocketImplGetPacketSize", 0x0}, // not found, 1.0.15.3: 0x143ea9db0
        // {"FoxNtImplGameSocketImplGameSocketImplDtor", 0x0}, // not found, 1.0.15.3: 0x143ea8150
        // {"TppGmImplScriptDeclVarsImplGetVarHandle", 0x0}, // not found, 1.0.15.3: 0x140ae1630
        // {"TppGmImplScriptDeclVarsImplScriptDeclVarsImpl", 0x0}, // not found, 1.0.15.3: 0x146845ab0
        // {"TppGmImplScriptSystemImplGetScriptDeclVarHandle", 0x0}, // not found, 1.0.15.3: 0x1461f4ce0
        // {"TppGmImplScriptDeclVarsImplGetVarIndexWithName", 0x0}, // not found, 1.0.15.3: 0x146849370
        // {"TppGmGetGVars", 0x0}, // not found, 1.0.15.3: 0x146848a40
        // {"TppGmGetSVars", 0x0}, // not found, 1.0.15.3: 0x1468490b0
        // {"FoxNtImplSessionImpl2GetMemberInterfaceAtIndex", 0x0}, // not found, 1.0.15.3: 0x143e61370
        // {"FoxNtImplGameSocketImplHandleMessage", 0x0}, // not found, 1.0.15.3: 0x143eaa120
        // {"FoxNtImplPeerCommonPeerCommon", 0x0}, // not found, 1.0.15.3: 0x143e9cf60
        // {"TppGmPlayerImplSynchronizerImplInitialize", 0x0}, // not found, 1.0.15.3: 0x1412a6c50
        // {"TppGmImplScriptDeclVarsImplScriptDeclVarsImplDtor", 0x0}, // not found, 1.0.15.3: 0x146845fc0
        // {"TppGmPlayerImplAnonymous_namespaceCamouflageControllerImplInitialize", 0x0}, // not found, 1.0.15.3: 0x140fdd420
        // {"FoxNtImplTransceiverManagerImplPeerAddToSendQueue", 0x0}, // not found, 1.0.15.3: 0x143e78970
        // {"FoxNioImplMpMuxImplSendUpdate", 0x0}, // not found, 1.0.15.3: 0x141a5a6c0
        // {"FoxNioImplSppSocketImplSendImpl", 0x0}, // not found, 1.0.15.3: 0x141a57b00
        // {"FoxNioImplSteamUdpSocketImplSend", 0x0}, // not found, 1.0.15.3: 0x14c4044f0
        // {"FoxNioImplSteamUdpSocketImplRecv", 0x0}, // not found, 1.0.15.3: 0x14c4042c0
        // {"TppUiMenuUiCommonDataManagerLoadLanguageBlock", 0x0}, // not found, 1.0.15.3: 0x145bddb50
        // {"TppUiUtilityChangeLanguage", 0x0}, // not found, 1.0.15.3: 0x14090f130
        // {"TppGmPlayerImplEquipControllerImplInitialize", 0x0}, // not found, 1.0.15.3: 0x149a02ca0
        // {"TppGmPlayerImplEquipControllerImplGetEquipIdSlot", 0x0}, // not found, 1.0.15.3: 0x1411add10
        // {"TppGmBossquietImplActionControllerImplSetCommand", 0x0}, // not found, 1.0.15.3: 0x1417a9e40
        // {"TppGmBossquietImplActionControllerImplSetExtraActionCommand", 0x0}, // not found, 1.0.15.3: 0x14a922d70
        // {"TppGmLiquidImplActionControllerImplSetActionTaskCompleted", 0x0}, // not found, 1.0.15.3: 0x14bf31450
        // {"TppGmBossquietImplActionControllerImplSetActionTask", 0x0}, // not found, 1.0.15.3: 0x14a922960
        // {"TppGmBossquietImplActionControllerImplSetNextActionTask", 0x0}, // not found, 1.0.15.3: 0x1417aa020
        // {"TppGmBossquietImplActionControllerImplInitialize", 0x0}, // not found, 1.0.15.3: 0x14a921790
        // {"TppGmSahelanImplActionControllerImplSetTaskParamFromActionCommand", 0x0}, // not found, 1.0.15.3: 0x14bbbd160
        // {"TppGmImplNavigationController2ImplGetNavigator", 0x0}, // not found, 1.0.15.3: 0x149586ed0
        // {"TppGmImplNavigationController2ImplIsCurrentRequestPrepared", 0x0}, // not found, 1.0.15.3: 0x149588720
        // {"TppGmBossquietImplActionControllerImplCheckUseOutOfNavJump", 0x0}, // not found, 1.0.15.3: 0x14a91ff50
        // {"TppGmImplNavigationController2ImplGetPath", 0x0}, // not found, 1.0.15.3: 0x1495879e0
        // {"TppGmImplNavigationController2ImplGetResultState", 0x0}, // not found, 1.0.15.3: 0x149587cd0
        // {"TppGmBossquietImplSnipeManagerImplGetOptimalLandingPosition", 0x0}, // not found, 1.0.15.3: 0x1417fa3d0
        // {"TppGmSahelanActionTaskoperatorAssign", 0x0}, // not found, 1.0.15.3: 0x14a91f960
        // {"TppGmBossquietImplActionControllerImplUpdate", 0x0}, // not found, 1.0.15.3: 0x14a923930
        // {"TppGmBossquietImplBasicAction2ImplPolling", 0x0}, // not found, 1.0.15.3: 0x14b6bebe0
        // {"TppGmBossquietImplActionControllerImplUpdateActionTask", 0x0}, // not found, 1.0.15.3: 0x14a923c70
        // {"TppGmBossquietImplActionControllerImplUpdateCommandForSingle", 0x0}, // not found, 1.0.15.3: 0x14a923f60
        // {"TppGmBossquietImplBasicAction2ImplGetNextPositionInMoving", 0x0}, // not found, 1.0.15.3: 0x14b6bd7c0
        // {"TppGmBossquietImplCloseCombatAiImplStepMove", 0x0}, // not found, 1.0.15.3: 0x1417c9380
        // {"TppGmBossquietImplRecoveryAiImplStepMove", 0x0}, // not found, 1.0.15.3: 0x1417f56b0
        // {"TppGmBossquietImplSearchAiImplStepMove", 0x0}, // not found, 1.0.15.3: 0x1417f8200
        // {"TppGmBossquietImplCombatAiImplRequestMoveAction", 0x0}, // not found, 1.0.15.3: 0x14b6d5970
        // {"TppGmBossquietImplSearchAiImplRequestMoveAction", 0x0}, // not found, 1.0.15.3: 0x14b772070
        // {"TppGmBossquietImplRecoveryAiImplRequestMoveAction", 0x0}, // not found, 1.0.15.3: 0x14b76a2f0
        // {"TppGmBossquietImplCloseCombatAiImplRequestMoveAction", 0x0}, // not found, 1.0.15.3: 0x14b6cd920
        // {"TppGmBossquietImplAvoidAiImplSetJumpPoint", 0x0}, // not found, 1.0.15.3: 0x14b6b87d0
        // {"TppGmImplAiControllerImplGetCoreKnowledge", 0x0}, // not found, 1.0.15.3: 0x146d18c90
        // {"TppGmBossquietImplanonymous_namespaceLifeControllerImplUpdateLife", 0x0}, // not found, 1.0.15.3: 0x14b73b3d0

        // {"BlockHeapAlloc", 0x0}, // not found, 1.0.15.3: 0x143264660
        // {"BlockHeapFree", 0x0}, // not found, 1.0.15.3: 0x1432651b0
        {"FoxBlockProcess", 0x14006e4e0},
        // {"FoxBlockUnload", 0x0}, // not found, 1.0.15.3: 0x143154a00
        // {"FoxBlockReload", 0x0}, // not found, 1.0.15.3: 0x1431533b0
        // {"FoxBlockActivate", 0x0}, // not found, 1.0.15.3: 0x14006cb20
        // {"FoxBlockDeactivate", 0x0}, // not found, 1.0.15.3: 0x14314a000
        // {"FoxGenerateUniqueName", 0x0}, // not found, 1.0.15.3: 0x1400e0210
        // {"FoxBlock", 0x0}, // not found, 1.0.15.3: 0x143145960
        {"FoxBlockLoad", 0x14006e040},
        // {"BlockMemoryAllocTail", 0x0}, // not found, 1.0.15.3: 0x1400dbb30
        // {"BlockMemoryAllocHeap", 0x0}, // not found, 1.0.15.3: 0x143261bf0
        // {"GetCurrentBlockMemory", 0x0}, // not found, 1.0.15.3: 0x14328e410
        // {"FoxCreateQuark", 0x0}, // not found, 1.0.15.3: 0x146c6a650

        // {"FoxLuaPushVector3", 0x0}, // not found, 1.0.15.3: 0x143257590
        // {"FoxLuaPushQuat", 0x0}, // not found, 1.0.15.3: 0x143256e30
        // {"l_AnnounceLogView", 0x0}, // not found, 1.0.15.3: 0x145d5ded0
        // {"TppUiUiCommandAnnounceLogViewLangId", 0x0}, // not found, 1.0.15.3: 0x1408cc280

        {"lua_pushinteger", 0x141a11880},
        {"lua_pushstring", 0x141a11970},
        {"lua_pushboolean", 0x141a11750},
        {"lua_getfield", 0x141a111e0},
        {"lua_setfield", 0x141a11e00},
        {"lua_pcall", 0x141a116c0},
        {"luaI_openlib", 0x141a17c30},
        {"luaL_checkinteger", 0x141a16f40},
        {"luaL_openlibs", 0x141a16980},
        {"luaL_checknumber", 0x141a17020},
        {"lua_toboolean", 0x141a120c0},
        {"lua_createtable", 0x141a10e80},
        {"lua_pushvalue", 0x141a119d0},
        {"lua_remove", 0x141a11c20},
        {"luaL_checklstring", 0x141a16f90},
        {"lua_pushnumber", 0x141a11950},
    };
}

#endif
""";
    // END GENERATED
}
