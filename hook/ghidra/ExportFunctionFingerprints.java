// Writes every function of the current program with a fingerprint, so functions can be matched between game
// versions outside of Ghidra. Output: functions_<program name>.csv in user's home directory.
// Columns: address, size, instruction count, call count, mnemonics hash, constants hash, name (last, may contain commas).
//@category Dynamite

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class ExportFunctionFingerprints extends GhidraScript {
    @Override
    protected void run() throws Exception {
        File out = new File(System.getProperty("user.home"), "functions_" + currentProgram.getName() + ".csv");
        int count = 0;
        try (PrintWriter w = new PrintWriter(out, StandardCharsets.UTF_8)) {
            w.println("address,size,instructions,calls,mnemonics,constants,name");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                MessageDigest mnemonics = MessageDigest.getInstance("SHA-1");
                // big immediate values (hashes, offsets, flags) survive relinking, addresses don't
                TreeSet<Long> constants = new TreeSet<>();
                int instructions = 0;
                int calls = 0;
                InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (ii.hasNext()) {
                    Instruction i = ii.next();
                    instructions++;
                    mnemonics.update(i.getMnemonicString().getBytes(StandardCharsets.UTF_8));
                    mnemonics.update((byte) ',');
                    if (i.getFlowType().isCall()) {
                        calls++;
                    }

                    for (int op = 0; op < i.getNumOperands(); op++) {
                        Scalar s = i.getScalar(op);
                        if (s != null && i.getOperandReferences(op).length == 0) {
                            long v = s.getUnsignedValue();
                            if (v >= 0x100 && v < 0x140000000L) {
                                constants.add(v);
                            }
                        }
                    }
                }

                MessageDigest c = MessageDigest.getInstance("SHA-1");
                c.update(constants.toString().getBytes(StandardCharsets.UTF_8));
                w.printf("0x%x,%d,%d,%d,%s,%s,%s%n", f.getEntryPoint().getOffset(), f.getBody().getNumAddresses(),
                    instructions, calls, hex(mnemonics.digest()), constants.isEmpty() ? "" : hex(c.digest()),
                    f.getName(true));
                count++;
            }
        }

        println(String.format("%d functions written to %s", count, out));
    }

    static String hex(byte[] digest) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            sb.append(String.format("%02x", digest[i] & 0xff));
        }

        return sb.toString();
    }
}
