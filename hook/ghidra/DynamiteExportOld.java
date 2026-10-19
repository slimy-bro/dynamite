// Records what dynamite uses in 1.0.15.3 exe: names of hooked functions, positions of byte patches inside their
// functions and patched strings. Run it on 1.0.15.3 mgsvtpp.exe, then run DynamiteFindNew.java on 1.0.15.4 exe.
// Asks for dynamite's hook/src folder, reads mgsvtpp_addresses_1_0_15_3_en.h and dynamitePatches.cpp from it
// and writes dynamite_1_0_15_3.tsv there.
// Headless: analyzeHeadless ... -postScript DynamiteExportOld.java <path to hook/src>
//@category Dynamite

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.SourceType;

public class DynamiteExportOld extends GhidraScript {
    static final String ADDRESSES = "mgsvtpp_addresses_1_0_15_3_en.h";
    static final String PATCHES = "dynamitePatches.cpp";
    static final String OUT = "dynamite_1_0_15_3.tsv";

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

    @Override
    protected void run() throws Exception {
        File dir = getSrcDir();
        List<String> out = new ArrayList<>();

        int funcs = 0, funcProblems = 0;
        boolean previousBlank = false;
        for (String line : Files.readAllLines(new File(dir, ADDRESSES).toPath(), StandardCharsets.UTF_8)) {
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

            String status = exportFunction(m.group(1), parseHex(m.group(2)), out);
            funcs++;
            if (!status.equals("ok")) {
                funcProblems++;
            }
        }

        int patches = 0, patchProblems = 0;
        for (PatchSource p : readPatches(new File(dir, PATCHES))) {
            patches++;
            String status = p.expected == null ? exportString(patches, p, out) : exportPatch(patches, p, out);
            if (!status.equals("ok")) {
                patchProblems++;
            }
        }

        File outFile = new File(dir, OUT);
        Files.write(outFile.toPath(), out, StandardCharsets.UTF_8);

        println(String.format("functions: %d (%d without usable name)", funcs, funcProblems));
        println(String.format("patches: %d (%d problems)", patches, patchProblems));
        println("written " + outFile);
        if (funcProblems > 0 || patchProblems > 0) {
            println("see status column in " + OUT + ": anything other than ok must be ported by hand");
        }
    }

    File getSrcDir() throws Exception {
        String[] args = getScriptArgs();
        File dir = args.length > 0 ? new File(args[0]) : askDirectory("Select dynamite hook/src folder", "Select");
        if (!new File(dir, ADDRESSES).isFile() || !new File(dir, PATCHES).isFile()) {
            throw new IllegalArgumentException(dir + " must contain " + ADDRESSES + " and " + PATCHES);
        }

        return dir;
    }

    // func, name, old address, full name, size, status
    String exportFunction(String name, long address, List<String> out) {
        Address a = toAddr(address);
        Function f = getFunctionAt(a);
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

        out.add(String.join("\t", "func", name, hex(address), fullName, Long.toString(size), status));
        return status;
    }

    // patch, index, old address, function full name, offset, expected bytes, mnemonics before, mnemonics after,
    // status, description
    String exportPatch(int index, PatchSource p, List<String> out) {
        Address a = toAddr(p.address);
        Function f = getFunctionContaining(a);
        String status = "ok";
        String fullName = "";
        long offset = 0;
        String before = "";
        String after = "";

        byte[] actual = readBytes(a, p.expected.length);
        if (actual == null || !java.util.Arrays.equals(actual, p.expected)) {
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

            List<Instruction> instructions = instructions(f);
            int i = indexOf(instructions, a);
            if (i < 0) {
                status = "notinstruction";
            } else {
                before = mnemonics(instructions, Math.max(0, i - WINDOW), i);
                after = mnemonics(instructions, i, Math.min(instructions.size(), i + WINDOW));
            }
        }

        out.add(String.join("\t", "patch", Integer.toString(index), hex(p.address), fullName, hex(offset),
            bytesToHex(p.expected), before, after, status, p.description));
        return status;
    }

    // string, index, old address, string bytes, status, description
    String exportString(int index, PatchSource p, List<String> out) {
        String status = "ok";
        String bytes = "";
        Address a = toAddr(p.address);
        byte[] data = readBytes(a, MAX_STRING);
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
            bytes = bytesToHex(java.util.Arrays.copyOf(data, len + 1));
        }

        out.add(String.join("\t", "string", Integer.toString(index), hex(p.address), bytes, status, p.description));
        return status;
    }

    List<PatchSource> readPatches(File file) throws Exception {
        List<PatchSource> result = new ArrayList<>();
        PatchSource current = null;
        boolean inDescription = false;
        // expected bytes may span several lines: ".expected =", "{", values, "}"
        boolean expectedPending = false;
        StringBuilder expected = null;
        for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
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
                current.address = parseHex(m.group(1));
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
            values.add(parseHex(h.group()));
        }

        byte[] result = new byte[values.size()];
        for (int i = 0; i < values.size(); i++) {
            result[i] = (byte) (long) values.get(i);
        }

        return result;
    }

    List<Instruction> instructions(Function f) {
        List<Instruction> result = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            result.add(it.next());
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

    byte[] readBytes(Address a, int len) {
        byte[] result = new byte[len];
        try {
            int n = currentProgram.getMemory().getBytes(a, result);
            return n == len ? result : java.util.Arrays.copyOf(result, n);
        } catch (Exception e) {
            return null;
        }
    }

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
}
