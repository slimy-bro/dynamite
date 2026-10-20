#ifndef HOOK_DYNAMITE_MGSVTPP_ADDRESSES_1_0_15_4
#define HOOK_DYNAMITE_MGSVTPP_ADDRESSES_1_0_15_4

#include <cstdint>
#include <map>
#include <string>
#include <vector>

// Addresses for game version 1.0.15.4 (June 9, 2026 update): 196 of 202 found.
// Found by comparing function fingerprints of both exes (hook/ghidra/ExportFunctionFingerprints.java): unique identical
// instructions, or position between matched neighbours plus identical ("fingerprint+position") or similar code
// ("position+similar code"); the rest by comparing code by hand (reason in comment). All 18 addresses known from IHHook
// 1.0.15.4 table (MIT, https://github.com/Phobos1641/mgs5-ihhook) agree.
// Commented out entries are not found; none of them is used outside of debug options.

namespace Dynamite {
    inline std::map<std::string, uint64_t> mgsvtpp_adresses_1_0_15_4_en{
        {"IsDefenseTeamByOnlineFobLocal", 0x141e03080}, // 1.0.15.3: 0x14d9ba3b0
        {"IsOffenseTeamByOnlineFobLocal", 0x141e030b0}, // 1.0.15.3: 0x141e02e40
        {"CreateHostSession", 0x1407ee590}, // 1.0.15.3: 0x1459f3e20
        {"NetworkSystemCreateHostSession", 0x141e0afb0}, // 1.0.15.3: 0x14da33790, identical code; tail call goes to CreateHostSession 0x1407ee590 (already matched), other candidate does not
        {"CreateClientSession", 0x1407ee380}, // 1.0.15.3: 0x1459f3910
        {"SetSteamId", 0x141a5fbe0}, // 1.0.15.3: 0x14c404640, fingerprint+position
        {"FobTargetCtor", 0x1407ed6f0}, // 1.0.15.3: 0x1459ed160
        {"SessionConnectInfoCtor", 0x1407ed800}, // 1.0.15.3: 0x1459edf00
        {"NetInfoCreateSession", 0x141e0ced0}, // 1.0.15.3: 0x14da5c070, identical code; 2nd call goes to 0x1407cfaa0 = old NetworkInfo::CreateSession stub +0xd60 (neighbouring GetInstance/DeleteSession offsets agree)
        {"IsConnectReady", 0x1466d82c0}, // 1.0.15.3: 0x1459d0cc0, jump target of new stub 0x1407e4190 (stub position both sides); code is checked before hooking
        {"UpdateClientEstablished", 0x140315be0}, // 1.0.15.3: 0x140316610
        {"SessionImpl2IsHost", 0x140313fe0}, // 1.0.15.3: 0x143e64400
        {"GetFobOffensePlayerInstanceIndex", 0x141e02770}, // 1.0.15.3: 0x14d9b00e0
        {"GetFobDefensePlayerInstanceIndex", 0x141e026b0}, // 1.0.15.3: 0x14d9afbc0
        {"CommandPost2ImplGetAvailableMemberCount", 0x140d5b220}, // 1.0.15.3: 0x1472a0500, identical incl. constants 0x168 / field 0x174, in position
        // {"CommandPost2ImplGetMaxCpCount", 0x0}, // 1.0.15.3: 0x140c93de0, not found
        {"GetUiMarkerTypeFromSystemType2", 0x140935020}, // 1.0.15.3: 0x140934580
        {"SightManagerImplSetMarker", 0x14127fb10}, // 1.0.15.3: 0x149c687d0
        {"SteamUdpSocketImplOnP2PSessionRequest", 0x141a5fa10}, // 1.0.15.3: 0x14c4040c0, identical code; second of two 175-byte callbacks, old stub order ConnectFail then Request with same 0xb0 spacing
        {"MessageBufferAddMessage", 0x1439fd9d0}, // 1.0.15.3: 0x1435ce000, jump target of new stub 0x140180320 (stub position one side); code is checked before hooking
        {"AddLocalDamage", 0x1411922c0}, // 1.0.15.3: 0x141192af0
        {"DamageControllerImplInitialize", 0x141195340}, // 1.0.15.3: 0x14991a290
        {"SynchronizerImplGetDamage", 0x1412a4580}, // 1.0.15.3: 0x149cb4c70
        {"Marker2SystemImpl", 0x1405c30c0}, // 1.0.15.3: 0x144fdb110, stub position both sides; first 22 instructions identical incl. field offsets
        {"Marker2SystemImplPlacedUserMarkerFixed", 0x1405c53a0}, // 1.0.15.3: 0x144fe5400
        {"GetLocalPlayerID", 0x14053c990}, // 1.0.15.3: 0x144c972c0
        {"RemoveUserMarker", 0x14094c660}, // 1.0.15.3: 0x1460706a0
        {"EquipHudSystemImplInitData", 0x14094bc00}, // 1.0.15.3: 0x14606c570
        {"Marker2SystemImplRemovedUserMarker", 0x1405c6250}, // 1.0.15.3: 0x144fe6a80
        {"Marker2SystemImplPlacedUserMarkerFollow", 0x1405c5530}, // 1.0.15.3: 0x144fe5920
        {"Marker2SystemImplRemovedAllUserMarker", 0x1405c6190}, // 1.0.15.3: 0x1405c52f0
        {"SightManagerImplInitialize", 0x14127ea60}, // 1.0.15.3: 0x149c63e20
        {"UiControllerImplSetNoUseEquipId", 0x140fe8320}, // 1.0.15.3: 0x1496b3b50
        {"EquipCrossEvCallIsItemNoUse", 0x1408ae340}, // 1.0.15.3: 0x145d0b630
        {"TppUiEmblemImplEmblemEditorSystemImplCreateEmblemParameters", 0x14094cdd0}, // 1.0.15.3: 0x14094c300
        {"TppUiEmblemImplEmblemEditorSystemImplCreateEmblem", 0x14094cb30}, // 1.0.15.3: 0x146073350
        {"TppUiEmblemImplEmblemEditorSystemImplLoadEmblemTextureInfo", 0x14094da70}, // 1.0.15.3: 0x14607be80, loads EmblemInfoManager instance (+0x10), tail call
        {"FoxNtImplSessionImpl2DeleteMember", 0x1403132b0}, // 1.0.15.3: 0x143e5c940, first 22 instructions identical incl. field offsets, 3/3 calls match
        {"FoxImplMessage2MessageBox2ImplSendMessageToSubscribers", 0x140180f20}, // 1.0.15.3: 0x1435d1f00, fingerprint+position
        {"TppUiEmblemImplEmblemEditorSystemImplDeleteTexture", 0x14094d2d0}, // 1.0.15.3: 0x1460741f0, fingerprint+position
        {"TppUiEmblemImplEmblemEditorSystemImplUnloadEmblemTextureInfo", 0x14094de60}, // 1.0.15.3: 0x14607e250, loads EmblemInfoManager instance, jumps to UnloadTextureInfo = old stub +offset
        {"TppGkTppGameKitModuleEnd", 0x140555b60}, // 1.0.15.3: 0x144d18950, same 9-call sequence at consistent local offsets + same Set call; 1.0.15.4 appends more cleanup (hook only logs and calls original)
        {"TppUiEmblemImplEmblemEditorSystemImplDeleteBlender", 0x14094d2c0}, // 1.0.15.3: 0x146074060, loads EmblemManager instance, jumps to 0x1405590d0 = old DeleteBlender stub +0xdb0 (stub spacing 0x10/0x140/0x20 matches)
        {"TppGkEmblemManagerCreateBlender", 0x140556ea0}, // 1.0.15.3: 0x144d1e170, identical instructions, stub +0xdb0 like neighbouring EmblemManager functions
        {"TppUiEmblemImplEmblemEditorSystemImplIsReady", 0x14094da60}, // 1.0.15.3: 0x14607bd70, loads EmblemManager instance (+0x10), jumps to EmblemManager::IsReady 0x140559bb0 (IsBlending/IsReady 0x20 apart in both versions)
        {"TppGmPlayerImplClimbActionPluginImplCheckActionState", 0x14114a900}, // 1.0.15.3: 0x149876920
        {"FoxGeoPathResultGetNumPoint", 0x141bc1a20}, // 1.0.15.3: 0x14ce84090

        {"HashMapFindKey", 0x1400249f0}, // 1.0.15.3: 0x142ed7be0
        {"GetQuarkSystemTable", 0x140bff050}, // 1.0.15.3: 0x140bff3f0, old address is a jump stub; its body 0x146cde8d0 has identical fingerprint to 0x140bff050; new code calls it and reads +0x98/+0x40 like dynamite
        {"FoxStrHash32", 0x141a09ac0}, // 1.0.15.3: 0x14c1bd730
        {"FoxFindEntity", 0x140067470}, // 1.0.15.3: 0x14312acb0, only structurally identical candidate in range; callees consistent (l_StubbedOut twin, 0x140015ff0->0x140016090); stub one side
        {"FoxGetEntityHandle", 0x1400c4ba0}, // 1.0.15.3: 0x14321e540, identical code, calls mapped consistently, stub position both sides
        {"FoxGetEntityProperty", 0x1400c4f30}, // 1.0.15.3: 0x1400c4e80
        {"FoxCreatePropertyInfo", 0x1400926f0}, // 1.0.15.3: 0x1400926a0
        {"ValueGetAsUInt32", 0x1400655e0}, // 1.0.15.3: 0x140065480
        {"FoxString", 0x14001d0e0}, // 1.0.15.3: 0x142eaf970, identical incl. register use; other overload has extra parameter
        {"FindGameObjectWithID", 0x147b5c9d0}, // 1.0.15.3: 0x146c95580
        {"Soldier2ImplGetInterface", 0x1486e4f80}, // 1.0.15.3: 0x149f2f3d0
        {"PlayerInfoServiceGetPositionAtIndex", 0x141e02dd0}, // 1.0.15.3: 0x14d9b7770, identical incl. argument registers, stub position both sides
        {"FoxNtSessionGetMainSession", 0x140313780}, // 1.0.15.3: 0x143e60970
        {"GetSessionMemberCount", 0x140313860}, // 1.0.15.3: 0x143e60ef0
        {"CloseSession", 0x140a1a710}, // 1.0.15.3: 0x146457b20
        {"Player2GameObjectImplWarp", 0x1409ceae0}, // 1.0.15.3: 0x14627c6f0
        {"ScriptDeclVarsImplSetVarValue", 0x140ae28e0}, // 1.0.15.3: 0x140ae2090
        {"SoldierRouteAiImplPreUpdate", 0x141570fa0}, // 1.0.15.3: 0x141572270
        {"RouteGroupImplGetEventId", 0x140514b50}, // 1.0.15.3: 0x144b8d070
        {"AiControllerImplAddNode", 0x140c0ed90}, // 1.0.15.3: 0x140c0f230
        {"AiControllerImplSleepNode", 0x140c0f8e0}, // 1.0.15.3: 0x146d1bf60
        {"AiControllerImplWakeNode", 0x140c100b0}, // 1.0.15.3: 0x146d1c6c0
        {"CoreAiImplGetVehicleId", 0x14142bdb0}, // 1.0.15.3: 0x149170560
        {"CoreAiImplGetVehicleRideState", 0x14142bde0}, // 1.0.15.3: 0x14a0a2ab0, identical incl. field +0x36 (neighbour reads +0x37)
        {"CoreAiImplIsVehicleRetain", 0x14142c210}, // 1.0.15.3: 0x14a0a3f30, identical incl. virtual call slot +0x48 (neighbour uses +0x58), stub position both sides
        {"SoldierImplRouteAiImplCheckVehicleAndWalkerGearGetInAndOutStep", 0x14156c2a0}, // 1.0.15.3: 0x14156d590
        {"StatusControllerImplIsSet", 0x14053eb20}, // 1.0.15.3: 0x144cba8d0, identical incl. stride 0x78 and offset +0x80; other IsSet variant reads a global table
        {"ScriptDeclVarsImplGetVarHandleWithVarIndex", 0x140ae2010}, // 1.0.15.3: 0x140ae17c0, identical incl. jump table and field offsets; offset from old equals neighbouring GetGVars stub offset +0x850
        {"GmGetScriptVarInfo", 0x1409aa920}, // 1.0.15.3: 0x1461f02b0, fingerprint+position
        {"BandWidthManagerImplCalcAverageRttOfBetterHalfConnection", 0x1407e10b0}, // 1.0.15.3: 0x1407e0580
        {"BandWidthManagerImplCalcAverageLostRateOfBetterHalfConnection", 0x1407e0ea0}, // 1.0.15.3: 0x1407e0370
        {"BandWidthManagerImplStartLimitState", 0x1407e13e0}, // 1.0.15.3: 0x1459bf210
        {"FoxNioMpMessageContainerGetFreeSize", 0x141a60750}, // 1.0.15.3: 0x14c408840
        {"FoxNioImplMpMuxImplSend", 0x141a59bf0}, // 1.0.15.3: 0x141a59f30
        {"FoxNioImplMpMuxImplRecv1", 0x141a59350}, // 1.0.15.3: 0x141a59690
        {"FoxNioImplMpMuxImplRecv2", 0x141a59530}, // 1.0.15.3: 0x141a59870
        {"FoxNtPeerControllerSend", 0x140318110}, // 1.0.15.3: 0x143e73b60
        {"FoxNtImplGameSocketImplPeerIsSendPacketEmpty", 0x140325070}, // 1.0.15.3: 0x143eab090
        {"FoxNtTotalControllerSend", 0x140317ce0}, // 1.0.15.3: 0x143e72910
        {"FoxNtImplTransceiverManagerImplPeerSend", 0x14031a530}, // 1.0.15.3: 0x14031aec0
        {"FoxNioImplMpSocketImplSend", 0x141a5ae10}, // 1.0.15.3: 0x141a5b150
        // {"FoxNioImplMpMuxImplGetTotalPayloadSize", 0x0}, // 1.0.15.3: 0x1467a3500, not found
        {"FoxNioMpMessageSerializerSerialize", 0x141a60760}, // 1.0.15.3: 0x141a60a90
        {"FoxNioMpMessageContainerCreate", 0x141a606d0}, // 1.0.15.3: 0x14c407c00
        {"FoxNioMpMessageContainerAddMessage", 0x141a604a0}, // 1.0.15.3: 0x14c406e40
        {"FoxNioImplSppSocketImplGetState", 0x141a55a70}, // 1.0.15.3: 0x14c2db550
        {"FoxNtImplSyncMemoryCollectorSyncMemoryCollector", 0x1403279a0}, // 1.0.15.3: 0x143ebb4b0
        {"FoxNtImplGameSocketBufferImplAlloc", 0x140324520}, // 1.0.15.3: 0x143ea6510
        {"TppGmImplScriptDeclVarsImplOnSessionNotify", 0x140ae2410}, // 1.0.15.3: 0x140ae1bc0
        {"FoxBitStreamWriterPrimitiveWrite", 0x1403242e0}, // 1.0.15.3: 0x143ea3d10
        {"TppGmImplScriptDeclVarsImplGetVarHandleWithVarIndex", 0x140ae2010}, // 1.0.15.3: 0x140ae17c0, identical incl. jump table and field offsets; offset from old equals neighbouring GetGVars stub offset +0x850
        {"FoxNtImplTransceiverManagerImplPeerSendImpl1", 0x14031aa70}, // 1.0.15.3: 0x143e7c130
        {"FoxNtImplTransceiverManagerImplPeerSendImpl2", 0x14031ab70}, // 1.0.15.3: 0x143e7c270
        {"FoxNtImplTransceiverImplTransceiverImpl", 0x140323440}, // 1.0.15.3: 0x140323ad0, position+similar code
        {"FoxNtImplGameSocketImplPeerRequestToSend", 0x140325160}, // 1.0.15.3: 0x1403257f0
        {"FoxNtImplGameSocketBufferImplGameSocketBufferImpl", 0x144a70b40}, // 1.0.15.3: 0x143ea61a0, jump target of new stub 0x1403244c0 (old stub -0x690 like other GameSocket functions); code is checked before hooking
        {"FoxNioMpMessageCreate", 0x141a60670}, // 1.0.15.3: 0x14c407850
        {"FoxNtImplNetworkSystemImplGetMainSession", 0x1403256e0}, // 1.0.15.3: 0x143eae4b0
        {"FoxImplScopeAllocatorImplAlloc", 0x1400345a0}, // 1.0.15.3: 0x142f32e00
        {"FoxScopeMemoryScopeMemory1", 0x140034470}, // 1.0.15.3: 0x140034710, old address is a stub; body fingerprint identical; old stubs ScopeMemory/ScopeMemory/~ScopeAllocatorImpl/~ScopeMemory/Alloc align with new at constant -0x2a0
        {"FoxScopeMemoryScopeMemoryDtor", 0x140034550}, // 1.0.15.3: 0x1400347f0, old address is a stub; body fingerprint identical; same alignment as ScopeMemory ctor
        {"TppGmImplScriptDeclVarsImplUpdate", 0x140ae29d0}, // 1.0.15.3: 0x140ae2180
        {"FoxNtImplGameSocketImplGetPacketCount", 0x140324d70}, // 1.0.15.3: 0x143ea9a10
        {"FoxNtImplGameSocketImplGetPacket", 0x140324ce0}, // 1.0.15.3: 0x143ea9670
        {"FoxNtImplNetworkSystemImplCreateGameSocket", 0x1403255d0}, // 1.0.15.3: 0x143ead9d0, fingerprint+position
        {"FoxNtNtModuleInit", 0x141ced880}, // 1.0.15.3: 0x14d365da0
        {"FoxNtImplGameSocketImplRequestToSendToMember", 0x140325250}, // 1.0.15.3: 0x143eab200, identical code; stub and RequestToSendToMembers stub both moved by -0x690
        {"FoxNtImplGameSocketImplSetInterval", 0x140325420}, // 1.0.15.3: 0x143eabc30, identical incl. fields 0x14/0x18 and stride 40; its stub and the stub of its tail call PeerCommon::SetInterval both moved by -0x690
        {"FoxNtImplPeerCommonInitializeLastSendTime", 0x140323350}, // 1.0.15.3: 0x143e9da20
        {"FoxNtImplGameSocketImplGetPacketSize", 0x140324e40}, // 1.0.15.3: 0x143ea9db0
        {"FoxNtImplGameSocketImplGameSocketImplDtor", 0x1403249d0}, // 1.0.15.3: 0x143ea8150, fingerprint+position
        {"TppGmImplScriptDeclVarsImplGetVarHandle", 0x140ae1e80}, // 1.0.15.3: 0x140ae1630
        {"TppGmImplScriptDeclVarsImplScriptDeclVarsImpl", 0x140ae0950}, // 1.0.15.3: 0x146845ab0
        {"TppGmImplScriptSystemImplGetScriptDeclVarHandle", 0x1409abe20}, // 1.0.15.3: 0x1461f4ce0
        {"TppGmImplScriptDeclVarsImplGetVarIndexWithName", 0x140ae2130}, // 1.0.15.3: 0x146849370, identical incl. 0x78/0x70/0xffff offsets
        {"TppGmGetGVars", 0x140ae1e60}, // 1.0.15.3: 0x146848a40, loads adjacent global pair in same order (data +0x20), stub order GetGVars/GetSVars/GetVarHandle
        {"TppGmGetSVars", 0x140ae1e70}, // 1.0.15.3: 0x1468490b0, loads adjacent global pair in same order (data +0x20), stub order
        {"FoxNtImplSessionImpl2GetMemberInterfaceAtIndex", 0x140313930}, // 1.0.15.3: 0x143e61370
        {"FoxNtImplGameSocketImplHandleMessage", 0x140324ec0}, // 1.0.15.3: 0x143eaa120
        {"FoxNtImplPeerCommonPeerCommon", 0x140323220}, // 1.0.15.3: 0x143e9cf60
        {"TppGmPlayerImplSynchronizerImplInitialize", 0x1412a6340}, // 1.0.15.3: 0x1412a6c50
        {"TppGmImplScriptDeclVarsImplScriptDeclVarsImplDtor", 0x140ae0a40}, // 1.0.15.3: 0x146845fc0
        {"TppGmPlayerImplAnonymous_namespaceCamouflageControllerImplInitialize", 0x140fdcc00}, // 1.0.15.3: 0x140fdd420
        {"FoxNtImplTransceiverManagerImplPeerAddToSendQueue", 0x1403197d0}, // 1.0.15.3: 0x143e78970
        {"FoxNioImplMpMuxImplSendUpdate", 0x141a5a380}, // 1.0.15.3: 0x141a5a6c0
        {"FoxNioImplSppSocketImplSendImpl", 0x141a57840}, // 1.0.15.3: 0x141a57b00
        {"FoxNioImplSteamUdpSocketImplSend", 0x141a5fb60}, // 1.0.15.3: 0x14c4044f0
        {"FoxNioImplSteamUdpSocketImplRecv", 0x141a5fac0}, // 1.0.15.3: 0x14c4042c0
        {"TppUiMenuUiCommonDataManagerLoadLanguageBlock", 0x140860fd0}, // 1.0.15.3: 0x145bddb50
        {"TppUiUtilityChangeLanguage", 0x14090fa70}, // 1.0.15.3: 0x14090f130, identical through the language switch (11 cases), same constants; calls shifted consistently (Extend, GetLanguageBlock)
        {"TppGmPlayerImplEquipControllerImplInitialize", 0x1411ad920}, // 1.0.15.3: 0x149a02ca0
        {"TppGmPlayerImplEquipControllerImplGetEquipIdSlot", 0x1411ad420}, // 1.0.15.3: 0x1411add10, identical incl. stride 0x3a, jump table with 7 cases, mask 0x7ff
        {"TppGmBossquietImplActionControllerImplSetCommand", 0x1417a9370}, // 1.0.15.3: 0x1417a9e40
        {"TppGmBossquietImplActionControllerImplSetExtraActionCommand", 0x1417a9520}, // 1.0.15.3: 0x14a922d70, identical 9 instructions incl. stride 0x1c0 and fields 0x190/0x1a0/0x1b0, stub vote both sides
        // {"TppGmLiquidImplActionControllerImplSetActionTaskCompleted", 0x0}, // 1.0.15.3: 0x14bf31450, unverified candidate 0x1419a9c70
        {"TppGmBossquietImplActionControllerImplSetActionTask", 0x1417a92d0}, // 1.0.15.3: 0x14a922960
        {"TppGmBossquietImplActionControllerImplSetNextActionTask", 0x1417a9550}, // 1.0.15.3: 0x1417aa020
        {"TppGmBossquietImplActionControllerImplInitialize", 0x1417a8fd0}, // 1.0.15.3: 0x14a921790
        {"TppGmSahelanImplActionControllerImplSetTaskParamFromActionCommand", 0x1418bfc40}, // 1.0.15.3: 0x14bbbd160
        {"TppGmImplNavigationController2ImplGetNavigator", 0x140fa1cc0}, // 1.0.15.3: 0x149586ed0, identical, stub position both sides, next to GetPath/GetResultState region
        {"TppGmImplNavigationController2ImplIsCurrentRequestPrepared", 0x140fa2150}, // 1.0.15.3: 0x149588720, identical 13 instructions incl. fields 0x48/0x8/0xc and 0xffff
        {"TppGmBossquietImplActionControllerImplCheckUseOutOfNavJump", 0x1417a8ad0}, // 1.0.15.3: 0x14a91ff50
        {"TppGmImplNavigationController2ImplGetPath", 0x140fa1ed0}, // 1.0.15.3: 0x1495879e0, identical instructions
        {"TppGmImplNavigationController2ImplGetResultState", 0x140fa1ef0}, // 1.0.15.3: 0x149587cd0, identical instructions
        {"TppGmBossquietImplSnipeManagerImplGetOptimalLandingPosition", 0x1417f9b70}, // 1.0.15.3: 0x1417fa3d0
        {"TppGmSahelanActionTaskoperatorAssign", 0x1417a8600}, // 1.0.15.3: 0x14a91f960
        {"TppGmBossquietImplActionControllerImplUpdate", 0x1417a9a30}, // 1.0.15.3: 0x14a923930
        {"TppGmBossquietImplBasicAction2ImplPolling", 0x1417ba910}, // 1.0.15.3: 0x14b6bebe0
        {"TppGmBossquietImplActionControllerImplUpdateActionTask", 0x1417a9ac0}, // 1.0.15.3: 0x14a923c70
        {"TppGmBossquietImplActionControllerImplUpdateCommandForSingle", 0x1417a9b70}, // 1.0.15.3: 0x14a923f60
        {"TppGmBossquietImplBasicAction2ImplGetNextPositionInMoving", 0x1417ba250}, // 1.0.15.3: 0x14b6bd7c0
        {"TppGmBossquietImplCloseCombatAiImplStepMove", 0x1417c8700}, // 1.0.15.3: 0x1417c9380
        {"TppGmBossquietImplRecoveryAiImplStepMove", 0x1417f4e50}, // 1.0.15.3: 0x1417f56b0
        {"TppGmBossquietImplSearchAiImplStepMove", 0x1417f79a0}, // 1.0.15.3: 0x1417f8200
        {"TppGmBossquietImplCombatAiImplRequestMoveAction", 0x1417cac20}, // 1.0.15.3: 0x14b6d5970, fingerprint+position
        {"TppGmBossquietImplSearchAiImplRequestMoveAction", 0x1417f7100}, // 1.0.15.3: 0x14b772070, fingerprint+position
        {"TppGmBossquietImplRecoveryAiImplRequestMoveAction", 0x1417f47b0}, // 1.0.15.3: 0x14b76a2f0, fingerprint+position
        {"TppGmBossquietImplCloseCombatAiImplRequestMoveAction", 0x1417c7d50}, // 1.0.15.3: 0x14b6cd920
        {"TppGmBossquietImplAvoidAiImplSetJumpPoint", 0x1417f14a0}, // 1.0.15.3: 0x14b6b87d0
        // {"TppGmImplAiControllerImplGetCoreKnowledge", 0x0}, // 1.0.15.3: 0x146d18c90, unverified candidate 0x140c0ef70
        {"TppGmBossquietImplanonymous_namespaceLifeControllerImplUpdateLife", 0x1417e8ab0}, // 1.0.15.3: 0x14b73b3d0

        {"BlockHeapAlloc", 0x1400dcb50}, // 1.0.15.3: 0x143264660
        {"BlockHeapFree", 0x1400dcbc0}, // 1.0.15.3: 0x1432651b0
        {"FoxBlockProcess", 0x14006e4e0}, // 1.0.15.3: 0x14006df80, position+similar code
        {"FoxBlockUnload", 0x14006f990}, // 1.0.15.3: 0x143154a00
        {"FoxBlockReload", 0x14006f320}, // 1.0.15.3: 0x1431533b0, position+similar code
        {"FoxBlockActivate", 0x14006cfb0}, // 1.0.15.3: 0x14006cb20
        {"FoxBlockDeactivate", 0x14006d480}, // 1.0.15.3: 0x14314a000
        // {"FoxGenerateUniqueName", 0x0}, // 1.0.15.3: 0x1400e0210, unverified candidate 0x1400e1380
        {"FoxBlock", 0x14006c230}, // 1.0.15.3: 0x143145960, identical instructions, calls shifted consistently, stub position
        {"FoxBlockLoad", 0x14006e040}, // 1.0.15.3: 0x143151e80
        {"BlockMemoryAllocTail", 0x1400dbc20}, // 1.0.15.3: 0x1400dbb30
        {"BlockMemoryAllocHeap", 0x1400dbab0}, // 1.0.15.3: 0x143261bf0
        // {"GetCurrentBlockMemory", 0x0}, // 1.0.15.3: 0x14328e410, not found
        {"FoxCreateQuark", 0x140bf1650}, // 1.0.15.3: 0x146c6a650

        {"FoxLuaPushVector3", 0x1400d7c60}, // 1.0.15.3: 0x143257590
        {"FoxLuaPushQuat", 0x1400d7ba0}, // 1.0.15.3: 0x143256e30
        {"l_AnnounceLogView", 0x1408cc6e0}, // 1.0.15.3: 0x145d5ded0
        {"TppUiUiCommandAnnounceLogViewLangId", 0x1408ccbf0}, // 1.0.15.3: 0x1408cc280

        {"lua_pushinteger", 0x141a11880}, // 1.0.15.3: 0x14c1e6ef0
        {"lua_pushstring", 0x141a11970}, // 1.0.15.3: 0x14c1e7ee0
        {"lua_pushboolean", 0x141a11750}, // 1.0.15.3: 0x14c1db230
        {"lua_getfield", 0x141a111e0}, // 1.0.15.3: 0x14c1d7320
        {"lua_setfield", 0x141a11e00}, // 1.0.15.3: 0x14c1eabb0
        {"lua_pcall", 0x141a116c0}, // 1.0.15.3: 0x14c1daff0
        {"luaI_openlib", 0x141a17c30}, // 1.0.15.3: 0x14c201610
        {"luaL_checkinteger", 0x141a16f40}, // 1.0.15.3: 0x14c1ff430
        {"luaL_openlibs", 0x141a16980}, // 1.0.15.3: 0x14c1fd0c0
        {"luaL_checknumber", 0x141a17020}, // 1.0.15.3: 0x14c1ffb30
        {"lua_toboolean", 0x141a120c0}, // 1.0.15.3: 0x14c1ebe40
        {"lua_createtable", 0x141a10e80}, // 1.0.15.3: 0x14c1d6320
        {"lua_pushvalue", 0x141a119d0}, // 1.0.15.3: 0x14c1e87e0
        {"lua_remove", 0x141a11c20}, // 1.0.15.3: 0x14c1ea0c0
        {"luaL_checklstring", 0x141a16f90}, // 1.0.15.3: 0x14c1ff790
        {"lua_pushnumber", 0x141a11950}, // 1.0.15.3: 0x14c1e7dd0
    };

    // Functions found only through a jump stub, their code was not compared. Hook is skipped if code at address
    // does not start with these bytes (1.0.15.3 code, -1 is any byte: register moves are encoded differently in
    // relocated code).
    inline std::map<std::string, std::vector<int16_t>> mgsvtpp_address_checks_1_0_15_4_en{
        // PUSH RBX; SUB RSP,0x20; MOV EAX,[RCX+0x10]; MOV RBX,RCX; DEC EAX; CMP EAX,1; JBE; MOV dword ptr [RCX+0x10],0; CALL
        {"IsConnectReady",
            {0x53, 0x48, 0x83, 0xec, 0x20, 0x8b, 0x41, 0x10, 0x48, -1, -1, 0xff, 0xc8, 0x83, 0xf8, 0x01, 0x76, -1, 0xc7, 0x41, 0x10, 0x00,
                0x00, 0x00, 0x00, 0xe8}},
        // PUSH R14; SUB RSP,0x30; MOV qword ptr [RSP+0x20],-2; MOV [RSP+0x40..0x58],RBX/RBP/RSI/RDI; 4 register moves; CMP byte ptr
        {"MessageBufferAddMessage",
            {0x41, 0x56, 0x48, 0x83, 0xec, 0x30, 0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff, 0x48, 0x89, 0x5c, 0x24, 0x40, 0x48,
                0x89, 0x6c, 0x24, 0x48, 0x48, 0x89, 0x74, 0x24, 0x50, 0x48, 0x89, 0x7c, 0x24, 0x58, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, 0x80, 0x3d}},
        // MOV [RSP+0x8],RBX; PUSH RDI; SUB RSP,0x20; MOV EBX,EDX; XOR EDX,EDX; MOV RDI,RCX; CALL
        {"FoxNtImplGameSocketBufferImplGameSocketBufferImpl",
            {0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, -1, -1, -1, -1, -1, -1, -1, 0xe8}},
    };
}

#endif
