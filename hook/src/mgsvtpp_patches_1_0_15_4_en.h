#ifndef HOOK_DYNAMITE_MGSVTPP_PATCHES_1_0_15_4
#define HOOK_DYNAMITE_MGSVTPP_PATCHES_1_0_15_4

#include <cstdint>
#include <map>

// Patch addresses for game version 1.0.15.4, not used yet: 18 of 26 found.
// Key is patch address in 1.0.15.3 (dynamitePatches.cpp), value is the same instruction in 1.0.15.4: function matched by
// identical instructions and size, same offset. Expected bytes are checked when patch is applied.

namespace Dynamite {
    inline std::map<uint64_t, uint64_t> mgsvtpp_patches_1_0_15_4_en{
        {0x140ffa9ff, 0x140ffa25f}, // Apply damage to player no matter what, tpp::gm::player::impl::`anonymous_namespace'::DefenseCallback::TargetCa
        {0x141378209, 0x141376ff9}, // Attempt to fix damage (not needed?), tpp::gm::soldier::impl::ActionCoreImpl::ExecGrazeCallback
        {0x149f57ac7, 0x141373827}, // Always update action task, tpp::gm::soldier::impl::ActionControllerImpl::UpdateActionTask
        {0x1417a200e, 0x1417a16be}, // Always respawn player no matter what, tpp::gm::player::impl::RespawnActionPluginImpl::UpdatePlaySubState
        {0x14133d9cb, 0x14133c9ab}, // Skip sight controller host check, always run host code, ignore IsHost call, tpp::gm::impl::`anonymous_namespac
        {0x140ebcfc4, 0x140ebcd44}, // Client always uses host code for SetHostage2Flag lua command, tpp::gm::hostage::impl::Hostage2FlagInfoImpl::Re
        {0x140887905, 0x140888155}, // Do not send sneak result (online request) on game over, tpp::ui::menu::GameOverEvCall::UpdateGameOver
        {0x1416026ce, 0x14160154e}, // Do not send sneak result on mission end (fob results screen)tpp::ui::hud::impl::TppUIFobResultImpl::UpdateFobR
        // {0x144e42a62, 0x0}, // not found: Trap check is player and local is always true #2, fix crash on entertpp::TrapCheckIsPlayerAndLocalCallback::Ex
        // {0x144e42a8e, 0x0}, // not found: Trap check is player and local is always true, fix crash on entertpp::TrapCheckIsPlayerAndHostCallback::ExecCa
        // {0x144e46f45, 0x0}, // not found: Trap check is player and host is always true, fix crash on entertpp::TrapCheckIsPlayerAndHostCallback
        {0x14625fd1a, 0x1409c176a}, // DoesFobGhostPlayer remove mission ID checktpp::gm::player::impl::Player2GameObjectImpl::DoesFobGhostPlayerwith
        // {0x1459b60b5, 0x0}, // not found: Always start fob p2p resolver, ignore exists check (not needed?)tpp::net::Daemon::StarFobP2pNameResolver
        {0x140da58e5, 0x140da5795}, // Always run host damage controller implementationFixes crash on shooting animals (like goats in PITCH BLACK aft
        // {0x146457b68, 0x0}, // not found: always run full CloseSession code, ignore mission code checktpp::gm::tool::`anonymous_namespace'::CloseSession
        {0x14163fcda, 0x14163ea0a}, // add Quiet and Ocelot to staff list in sortie by ignoring tpp::ui::menu::impl::MissionPreparationSystemImpl::Is
        {0x1409cc6c0, 0x1409cd370}, // skip some check that resets player to Snake from Quiet/Ocelottpp::gm::player::impl::Player2GameObjectImpl::Upd
        // {0x149cfba54, 0x0}, // not found: skip check and call FUN_1411b4350 that sets up dual revolvers for Ocelottpp::gm::player::impl::UnrealUpdaterIm
        {0x149f4f17b, 0x14136bd2b}, // always use non-fob function to update cp member statustpp::gm::soldier::impl::Soldier2Impl::UpdateCpMemberStat
        {0x1409c9a13, 0x1409ca6b3}, // always apply opponent (or partner) emblemtpp::gm::player::impl::Player2Impl::SetEmblemTexture
        // {0x149c1758d, 0x0}, // not found: exit motion fixing loop immediatelytpp::gm::player::impl::RideWalkerGearActionImpl::SyncMotionWithWalkerGearMo
        {0x14a62cf4e, 0x141714f2e}, // skip walker gear equip sync handlingtpp::gm::walkergear::impl::ActionCoreImpl::ReceiveEquipInfo
        {0x1417cce2a, 0x1417cc24a}, // Boss Quiet always jumps instead of runningtpp::gm::bossquiet::impl::CombatAiImpl::StepMove
        {0x1417ccd72, 0x1417cc192}, // Boss Quiet always jumps instead of running, patch 2tpp::gm::bossquiet::impl::CombatAiImpl::StepMove
        {0x1417d54f7, 0x1417d4a17}, // ignore host check to always process Boss Quiet damage locallytpp::gm::bossquiet::impl::`anonymous_namespace'::
        // {0x142218770, 0x0}, // not found: override master server url
    };
}

#endif
