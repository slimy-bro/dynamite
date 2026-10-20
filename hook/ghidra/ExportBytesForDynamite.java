// Writes raw bytes of code areas dynamite needs from both game versions, so they can be compared outside of Ghidra.
// Run it on both exes. Output: dynamite_bytes_<program name>.txt in user's home directory.
//@category Dynamite

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class ExportBytesForDynamite extends GhidraScript {
    // name, 1.0.15.3 address, length, 1.0.15.4 range start, range end
    static final String[][] TARGETS = {
        {"NetworkSystemCreateHostSession", "0x14da33790", "0x40", "0x141e0ac80", "0x141e0b6f0"},
        {"NetInfoCreateSession", "0x14da5c070", "0x40", "0x141e0ca20", "0x141e0d040"},
        {"IsConnectReady", "0x1459d0cc0", "0x40", "0x1407e2910", "0x1407e4dc0"},
        {"CommandPost2ImplGetAvailableMemberCount", "0x1472a0500", "0x40", "0x140d5b190", "0x140d5b410"},
        {"CommandPost2ImplGetMaxCpCount", "0x140c93de0", "0x60", "0x140c91ac0", "0x140c93eb0"},
        {"SteamUdpSocketImplOnP2PSessionRequest", "0x14c4040c0", "0xa2", "0x141a5f8c0", "0x141a5fac0"},
        {"MessageBufferAddMessage", "0x1435ce000", "0x104", "0x1401802a0", "0x140180540"},
        {"Marker2SystemImpl", "0x144fdb110", "0xd0", "0x1405c2320", "0x1405c3510"},
        {"TppUiEmblemImplEmblemEditorSystemImplLoadEmblemTextureInfo", "0x14607be80", "0x40", "0x14094da00", "0x14094da80"},
        {"FoxNtImplSessionImpl2DeleteMember", "0x143e5c940", "0x187", "0x1403131e0", "0x140313640"},
        {"TppUiEmblemImplEmblemEditorSystemImplUnloadEmblemTextureInfo", "0x14607e250", "0x40", "0x14094de00", "0x14094de90"},
        {"TppGkTppGameKitModuleEnd", "0x144d18950", "0x40", "0x140555940", "0x140555d10"},
        {"TppUiEmblemImplEmblemEditorSystemImplDeleteBlender", "0x146074060", "0x40", "0x14094cb30", "0x14094d5f0"},
        {"TppGkEmblemManagerCreateBlender", "0x144d1e170", "0x40", "0x140556d50", "0x140556eb0"},
        {"TppUiEmblemImplEmblemEditorSystemImplIsReady", "0x14607bd70", "0x40", "0x14094da00", "0x14094da80"},
        {"GetQuarkSystemTable", "0x140bff3f0", "0x40", "0x140bfde90", "0x140c011b0"},
        {"FoxFindEntity", "0x14312acb0", "0x40", "0x140066490", "0x140068310"},
        {"FoxGetEntityHandle", "0x14321e540", "0x5a", "0x1400c4ae0", "0x1400c4ea0"},
        {"FoxString", "0x142eaf970", "0xa2", "0x14001d080", "0x14001d270"},
        {"PlayerInfoServiceGetPositionAtIndex", "0x14d9b7770", "0x40", "0x141e02ad0", "0x141e02fa0"},
        {"CoreAiImplGetVehicleRideState", "0x14a0a2ab0", "0x40", "0x14142bc80", "0x14142c2f0"},
        {"CoreAiImplIsVehicleRetain", "0x14a0a3f30", "0x6a", "0x14142bc80", "0x14142c2f0"},
        {"StatusControllerImplIsSet", "0x144cba8d0", "0x40", "0x14053e7b0", "0x14053eb40"},
        {"ScriptDeclVarsImplGetVarHandleWithVarIndex", "0x140ae17c0", "0xfb", "0x140ae1e80", "0x140ae2190"},
        {"FoxNioImplMpMuxImplGetTotalPayloadSize", "0x1467a3500", "0x40", "0x140ac6160", "0x140ac6220"},
        {"FoxNtImplGameSocketBufferImplGameSocketBufferImpl", "0x143ea61a0", "0x44", "0x140324400", "0x140324520"},
        {"FoxScopeMemoryScopeMemory1", "0x140034710", "0x40", "0x140034100", "0x140034b70"},
        {"FoxScopeMemoryScopeMemoryDtor", "0x1400347f0", "0x40", "0x140034100", "0x140034b70"},
        {"FoxNtImplGameSocketImplRequestToSendToMember", "0x143eab200", "0x43", "0x140325070", "0x1403252a0"},
        {"FoxNtImplGameSocketImplSetInterval", "0x143eabc30", "0x40", "0x140325350", "0x140325510"},
        {"TppGmImplScriptDeclVarsImplGetVarIndexWithName", "0x146849370", "0x57", "0x140ae1e00", "0x140ae27c0"},
        {"TppGmGetGVars", "0x146848a40", "0x40", "0x140ae1e00", "0x140ae27c0"},
        {"TppGmGetSVars", "0x1468490b0", "0x40", "0x140ae1e00", "0x140ae27c0"},
        {"TppUiUtilityChangeLanguage", "0x14090f130", "0xda", "0x14090ed90", "0x1409106c0"},
        {"TppGmPlayerImplEquipControllerImplGetEquipIdSlot", "0x1411add10", "0x7d", "0x1411ace40", "0x1411ad4c0"},
        {"TppGmBossquietImplActionControllerImplSetExtraActionCommand", "0x14a922d70", "0x40", "0x1417a92d0", "0x1417a9ac0"},
        {"TppGmLiquidImplActionControllerImplSetActionTaskCompleted", "0x14bf31450", "0x40", "0x1419a93f0", "0x1419a9dd0"},
        {"TppGmImplNavigationController2ImplGetNavigator", "0x149586ed0", "0x40", "0x140fa1b70", "0x140fa1cd0"},
        {"TppGmImplNavigationController2ImplIsCurrentRequestPrepared", "0x149588720", "0x40", "0x140fa1f20", "0x140fa21a0"},
        {"TppGmImplNavigationController2ImplGetPath", "0x1495879e0", "0x40", "0x140fa1e30", "0x140fa1f20"},
        {"TppGmImplNavigationController2ImplGetResultState", "0x149587cd0", "0x40", "0x140fa1e30", "0x140fa1f20"},
        {"TppGmImplAiControllerImplGetCoreKnowledge", "0x146d18c90", "0x40", "0x140c0eea0", "0x140c0f040"},
        {"FoxGenerateUniqueName", "0x1400e0210", "0x15b", "0x1400ddf60", "0x1400e9290"},
        {"FoxBlock", "0x143145960", "0x51", "0x14006bae0", "0x14006c910"},
        {"GetCurrentBlockMemory", "0x14328e410", "0x40", "0x1400e6290", "0x1400e74c0"},
        {"patch_0x144e42a62", "0x144e42a10", "0x86", "0x1405875a0", "0x140588850"},
        {"patch_0x144e46f45", "0x144e46ed0", "0x7d", "0x140587e70", "0x140589c40"},
        {"patch_0x1459b60b5", "0x1459b60b0", "0x40", "0x1407de6b0", "0x1407dec90"},
        {"patch_0x146457b68", "0x146457b20", "0x70", "0x140a1a6d0", "0x140a1adf0"},
        {"patch_0x149cfba54", "0x149cfb8d0", "0x1a6", "0x1412cc550", "0x1412cd7e0"},
        {"patch_0x149c1758d", "0x149c174d0", "0x2b1", "0x14125fad0", "0x1412633c0"},
    };

    static final String URL = "https://mgstpp-game.konamionline.com/tppstm/gate";

    @Override
    protected void run() throws Exception {
        File out = new File(System.getProperty("user.home"), "dynamite_bytes_" + currentProgram.getName() + ".txt");
        try (PrintWriter w = new PrintWriter(out, StandardCharsets.UTF_8)) {
            w.println("# " + currentProgram.getName() + " " + currentProgram.getExecutableMD5());
            for (String[] t : TARGETS) {
                long old = Long.decode(t[1]);
                dump(w, t[0], "old", old, old + Long.decode(t[2]));
                dump(w, t[0], "new", Long.decode(t[3]), Long.decode(t[4]));
            }

            for (Address a : findAll((URL + "\0").getBytes(StandardCharsets.US_ASCII))) {
                w.printf("URL 0x%x%n", a.getOffset());
            }
        }

        println("written " + out);
    }

    void dump(PrintWriter w, String name, String kind, long start, long end) {
        Address s = toAddr(start);
        Address e = toAddr(end - 1);
        w.printf("RANGE %s %s 0x%x 0x%x%n", name, kind, start, end);
        StringBuilder hex = new StringBuilder();
        Memory memory = currentProgram.getMemory();
        for (long a = start; a < end; a++) {
            try {
                hex.append(String.format("%02x", memory.getByte(toAddr(a)) & 0xff));
            } catch (Exception ex) {
                hex.append("..");
            }
        }
        w.println("HEX " + hex);

        // strings used by code in this range help to confirm a match
        try {
            InstructionIterator it = currentProgram.getListing().getInstructions(new AddressSet(s, e), true);
            while (it.hasNext()) {
                Instruction i = it.next();
                for (Reference r : i.getReferencesFrom()) {
                    Data d = getDataAt(r.getToAddress());
                    if (d != null && d.hasStringValue()) {
                        String v = String.valueOf(d.getValue()).replaceAll("[\\r\\n\\t]", " ");
                        w.printf("STR 0x%x %s%n", i.getAddress().getOffset(), v.length() > 120 ? v.substring(0, 120) : v);
                    }
                }
            }
        } catch (Exception ex) {
            w.println("STRERROR " + ex);
        }
    }

    java.util.List<Address> findAll(byte[] bytes) throws Exception {
        java.util.List<Address> result = new java.util.ArrayList<>();
        Memory memory = currentProgram.getMemory();
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
}
