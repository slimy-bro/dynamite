#ifndef HOOK_DYNAMITE_MGSVTPP_ADDRESSES_1_0_15_4
#define HOOK_DYNAMITE_MGSVTPP_ADDRESSES_1_0_15_4

#include <cstdint>
#include <map>
#include <string>

// Addresses for game version 1.0.15.4 (June 9, 2026 update), not used yet: 156 of 202 found.
// Found by comparing function fingerprints of both exes (hook/ghidra/ExportFunctionFingerprints.java): unique identical
// instructions, or position between matched neighbours plus identical ("fingerprint+position") or similar code
// ("position+similar code"). All 18 addresses known from IHHook 1.0.15.4 table
// (MIT, https://github.com/Phobos1641/mgs5-ihhook) agree. Commented out entries are not found yet.

namespace Dynamite {
    inline std::map<std::string, uint64_t> mgsvtpp_adresses_1_0_15_4_en{
        {"IsDefenseTeamByOnlineFobLocal", 0x141e03080}, // 1.0.15.3: 0x14d9ba3b0
        {"IsOffenseTeamByOnlineFobLocal", 0x141e030b0}, // 1.0.15.3: 0x141e02e40
        {"CreateHostSession", 0x1407ee590}, // 1.0.15.3: 0x1459f3e20
        // {"NetworkSystemCreateHostSession", 0x0}, // 1.0.15.3: 0x14da33790, not found
        {"CreateClientSession", 0x1407ee380}, // 1.0.15.3: 0x1459f3910
        {"SetSteamId", 0x141a5fbe0}, // 1.0.15.3: 0x14c404640, fingerprint+position
        {"FobTargetCtor", 0x1407ed6f0}, // 1.0.15.3: 0x1459ed160
        {"SessionConnectInfoCtor", 0x1407ed800}, // 1.0.15.3: 0x1459edf00
        // {"NetInfoCreateSession", 0x0}, // 1.0.15.3: 0x14da5c070, unverified candidate 0x141e0ced0
        // {"IsConnectReady", 0x0}, // 1.0.15.3: 0x1459d0cc0, unverified candidate 0x1407e2e00
        {"UpdateClientEstablished", 0x140315be0}, // 1.0.15.3: 0x140316610
        {"SessionImpl2IsHost", 0x140313fe0}, // 1.0.15.3: 0x143e64400
        {"GetFobOffensePlayerInstanceIndex", 0x141e02770}, // 1.0.15.3: 0x14d9b00e0
        {"GetFobDefensePlayerInstanceIndex", 0x141e026b0}, // 1.0.15.3: 0x14d9afbc0
        // {"CommandPost2ImplGetAvailableMemberCount", 0x0}, // 1.0.15.3: 0x1472a0500, not found
        // {"CommandPost2ImplGetMaxCpCount", 0x0}, // 1.0.15.3: 0x140c93de0, not found
        {"GetUiMarkerTypeFromSystemType2", 0x140935020}, // 1.0.15.3: 0x140934580
        {"SightManagerImplSetMarker", 0x14127fb10}, // 1.0.15.3: 0x149c687d0
        // {"SteamUdpSocketImplOnP2PSessionRequest", 0x0}, // 1.0.15.3: 0x14c4040c0, unverified candidate 0x141a5f960
        // {"MessageBufferAddMessage", 0x0}, // 1.0.15.3: 0x1435ce000, unverified candidate 0x140180490
        {"AddLocalDamage", 0x1411922c0}, // 1.0.15.3: 0x141192af0
        {"DamageControllerImplInitialize", 0x141195340}, // 1.0.15.3: 0x14991a290
        {"SynchronizerImplGetDamage", 0x1412a4580}, // 1.0.15.3: 0x149cb4c70
        // {"Marker2SystemImpl", 0x0}, // 1.0.15.3: 0x144fdb110, unverified candidate 0x1405c2530
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
        // {"TppUiEmblemImplEmblemEditorSystemImplLoadEmblemTextureInfo", 0x0}, // 1.0.15.3: 0x14607be80, not found
        // {"FoxNtImplSessionImpl2DeleteMember", 0x0}, // 1.0.15.3: 0x143e5c940, unverified candidate 0x1403132b0
        {"FoxImplMessage2MessageBox2ImplSendMessageToSubscribers", 0x140180f20}, // 1.0.15.3: 0x1435d1f00, fingerprint+position
        {"TppUiEmblemImplEmblemEditorSystemImplDeleteTexture", 0x14094d2d0}, // 1.0.15.3: 0x1460741f0, fingerprint+position
        // {"TppUiEmblemImplEmblemEditorSystemImplUnloadEmblemTextureInfo", 0x0}, // 1.0.15.3: 0x14607e250, not found
        // {"TppGkTppGameKitModuleEnd", 0x0}, // 1.0.15.3: 0x144d18950, unverified candidate 0x140555c70
        // {"TppUiEmblemImplEmblemEditorSystemImplDeleteBlender", 0x0}, // 1.0.15.3: 0x146074060, not found
        // {"TppGkEmblemManagerCreateBlender", 0x0}, // 1.0.15.3: 0x144d1e170, unverified candidate 0x140556ea0
        // {"TppUiEmblemImplEmblemEditorSystemImplIsReady", 0x0}, // 1.0.15.3: 0x14607bd70, not found
        {"TppGmPlayerImplClimbActionPluginImplCheckActionState", 0x14114a900}, // 1.0.15.3: 0x149876920
        {"FoxGeoPathResultGetNumPoint", 0x141bc1a20}, // 1.0.15.3: 0x14ce84090

        {"HashMapFindKey", 0x1400249f0}, // 1.0.15.3: 0x142ed7be0
        // {"GetQuarkSystemTable", 0x0}, // 1.0.15.3: 0x140bff3f0, not found
        {"FoxStrHash32", 0x141a09ac0}, // 1.0.15.3: 0x14c1bd730
        // {"FoxFindEntity", 0x0}, // 1.0.15.3: 0x14312acb0, unverified candidate 0x1400664e0
        // {"FoxGetEntityHandle", 0x0}, // 1.0.15.3: 0x14321e540, unverified candidate 0x1400c4e30
        {"FoxGetEntityProperty", 0x1400c4f30}, // 1.0.15.3: 0x1400c4e80
        {"FoxCreatePropertyInfo", 0x1400926f0}, // 1.0.15.3: 0x1400926a0
        {"ValueGetAsUInt32", 0x1400655e0}, // 1.0.15.3: 0x140065480
        // {"FoxString", 0x0}, // 1.0.15.3: 0x142eaf970, unverified candidate 0x14001d0e0
        {"FindGameObjectWithID", 0x147b5c9d0}, // 1.0.15.3: 0x146c95580
        {"Soldier2ImplGetInterface", 0x1486e4f80}, // 1.0.15.3: 0x149f2f3d0
        // {"PlayerInfoServiceGetPositionAtIndex", 0x0}, // 1.0.15.3: 0x14d9b7770, not found
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
        // {"CoreAiImplGetVehicleRideState", 0x0}, // 1.0.15.3: 0x14a0a2ab0, not found
        // {"CoreAiImplIsVehicleRetain", 0x0}, // 1.0.15.3: 0x14a0a3f30, not found
        {"SoldierImplRouteAiImplCheckVehicleAndWalkerGearGetInAndOutStep", 0x14156c2a0}, // 1.0.15.3: 0x14156d590
        // {"StatusControllerImplIsSet", 0x0}, // 1.0.15.3: 0x144cba8d0, unverified candidate 0x14053ead0
        // {"ScriptDeclVarsImplGetVarHandleWithVarIndex", 0x0}, // 1.0.15.3: 0x140ae17c0, not found
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
        // {"TppGmImplScriptDeclVarsImplGetVarHandleWithVarIndex", 0x0}, // 1.0.15.3: 0x140ae17c0, not found
        {"FoxNtImplTransceiverManagerImplPeerSendImpl1", 0x14031aa70}, // 1.0.15.3: 0x143e7c130
        {"FoxNtImplTransceiverManagerImplPeerSendImpl2", 0x14031ab70}, // 1.0.15.3: 0x143e7c270
        {"FoxNtImplTransceiverImplTransceiverImpl", 0x140323440}, // 1.0.15.3: 0x140323ad0, position+similar code
        {"FoxNtImplGameSocketImplPeerRequestToSend", 0x140325160}, // 1.0.15.3: 0x1403257f0
        // {"FoxNtImplGameSocketBufferImplGameSocketBufferImpl", 0x0}, // 1.0.15.3: 0x143ea61a0, unverified candidate 0x1403244a0
        {"FoxNioMpMessageCreate", 0x141a60670}, // 1.0.15.3: 0x14c407850
        {"FoxNtImplNetworkSystemImplGetMainSession", 0x1403256e0}, // 1.0.15.3: 0x143eae4b0
        {"FoxImplScopeAllocatorImplAlloc", 0x1400345a0}, // 1.0.15.3: 0x142f32e00
        // {"FoxScopeMemoryScopeMemory1", 0x0}, // 1.0.15.3: 0x140034710, not found
        // {"FoxScopeMemoryScopeMemoryDtor", 0x0}, // 1.0.15.3: 0x1400347f0, not found
        {"TppGmImplScriptDeclVarsImplUpdate", 0x140ae29d0}, // 1.0.15.3: 0x140ae2180
        {"FoxNtImplGameSocketImplGetPacketCount", 0x140324d70}, // 1.0.15.3: 0x143ea9a10
        {"FoxNtImplGameSocketImplGetPacket", 0x140324ce0}, // 1.0.15.3: 0x143ea9670
        {"FoxNtImplNetworkSystemImplCreateGameSocket", 0x1403255d0}, // 1.0.15.3: 0x143ead9d0, fingerprint+position
        {"FoxNtNtModuleInit", 0x141ced880}, // 1.0.15.3: 0x14d365da0
        // {"FoxNtImplGameSocketImplRequestToSendToMember", 0x0}, // 1.0.15.3: 0x143eab200, unverified candidate 0x1403250e0
        // {"FoxNtImplGameSocketImplSetInterval", 0x0}, // 1.0.15.3: 0x143eabc30, unverified candidate 0x1403253f0
        {"FoxNtImplPeerCommonInitializeLastSendTime", 0x140323350}, // 1.0.15.3: 0x143e9da20
        {"FoxNtImplGameSocketImplGetPacketSize", 0x140324e40}, // 1.0.15.3: 0x143ea9db0
        {"FoxNtImplGameSocketImplGameSocketImplDtor", 0x1403249d0}, // 1.0.15.3: 0x143ea8150, fingerprint+position
        {"TppGmImplScriptDeclVarsImplGetVarHandle", 0x140ae1e80}, // 1.0.15.3: 0x140ae1630
        {"TppGmImplScriptDeclVarsImplScriptDeclVarsImpl", 0x140ae0950}, // 1.0.15.3: 0x146845ab0
        {"TppGmImplScriptSystemImplGetScriptDeclVarHandle", 0x1409abe20}, // 1.0.15.3: 0x1461f4ce0
        // {"TppGmImplScriptDeclVarsImplGetVarIndexWithName", 0x0}, // 1.0.15.3: 0x146849370, unverified candidate 0x140ae1e50
        // {"TppGmGetGVars", 0x0}, // 1.0.15.3: 0x146848a40, not found
        // {"TppGmGetSVars", 0x0}, // 1.0.15.3: 0x1468490b0, not found
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
        // {"TppUiUtilityChangeLanguage", 0x0}, // 1.0.15.3: 0x14090f130, unverified candidate 0x14090fa70
        {"TppGmPlayerImplEquipControllerImplInitialize", 0x1411ad920}, // 1.0.15.3: 0x149a02ca0
        // {"TppGmPlayerImplEquipControllerImplGetEquipIdSlot", 0x0}, // 1.0.15.3: 0x1411add10, unverified candidate 0x1411ad240
        {"TppGmBossquietImplActionControllerImplSetCommand", 0x1417a9370}, // 1.0.15.3: 0x1417a9e40
        // {"TppGmBossquietImplActionControllerImplSetExtraActionCommand", 0x0}, // 1.0.15.3: 0x14a922d70, unverified candidate 0x1417a9a30
        // {"TppGmLiquidImplActionControllerImplSetActionTaskCompleted", 0x0}, // 1.0.15.3: 0x14bf31450, unverified candidate 0x1419a9c70
        {"TppGmBossquietImplActionControllerImplSetActionTask", 0x1417a92d0}, // 1.0.15.3: 0x14a922960
        {"TppGmBossquietImplActionControllerImplSetNextActionTask", 0x1417a9550}, // 1.0.15.3: 0x1417aa020
        {"TppGmBossquietImplActionControllerImplInitialize", 0x1417a8fd0}, // 1.0.15.3: 0x14a921790
        {"TppGmSahelanImplActionControllerImplSetTaskParamFromActionCommand", 0x1418bfc40}, // 1.0.15.3: 0x14bbbd160
        // {"TppGmImplNavigationController2ImplGetNavigator", 0x0}, // 1.0.15.3: 0x149586ed0, not found
        // {"TppGmImplNavigationController2ImplIsCurrentRequestPrepared", 0x0}, // 1.0.15.3: 0x149588720, not found
        {"TppGmBossquietImplActionControllerImplCheckUseOutOfNavJump", 0x1417a8ad0}, // 1.0.15.3: 0x14a91ff50
        // {"TppGmImplNavigationController2ImplGetPath", 0x0}, // 1.0.15.3: 0x1495879e0, not found
        // {"TppGmImplNavigationController2ImplGetResultState", 0x0}, // 1.0.15.3: 0x149587cd0, not found
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
        // {"FoxBlock", 0x0}, // 1.0.15.3: 0x143145960, unverified candidate 0x14006c1f0
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
}

#endif
