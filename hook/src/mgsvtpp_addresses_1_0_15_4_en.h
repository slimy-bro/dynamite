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
