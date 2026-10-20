#ifndef HOOK_DYNAMITE_MGSVTPP_PATCHES_1_0_15_4
#define HOOK_DYNAMITE_MGSVTPP_PATCHES_1_0_15_4

#include <cstdint>
#include <map>
#include <vector>

// Patches for game version 1.0.15.4. Key is patch address in 1.0.15.3 (dynamitePatches.cpp), value is the same
// instruction in 1.0.15.4: function matched by identical instructions, instruction found by aligning both versions of
// function code. Code that 1.0.15.3 runs from relocated copies encodes some instructions differently, these patches
// have their own expected and patch bytes. Expected bytes are checked when patch is applied.

namespace Dynamite {
    struct PatchLocation {
        uint64_t address;
        std::vector<signed short> expected{}; // empty: same as 1.0.15.3
        std::vector<signed short> patch{};    // empty: same as 1.0.15.3
    };

    inline constexpr uint64_t mgsvtpp_master_server_url_1_0_15_4_en = 0x142218708;

    inline std::map<uint64_t, PatchLocation> mgsvtpp_patches_1_0_15_4_en{
        {0x140ffa9ff, {0x140ffa25f}}, // Apply damage to player no matter what
        {0x141378209, {0x141376ff9}}, // Attempt to fix damage (not needed?)
        {0x149f57ac7, {0x141373827}}, // Always update action task
        {0x1417a200e, {0x1417a16be}}, // Always respawn player no matter what
        {0x14133d9cb, {0x14133c9ab}}, // Skip sight controller host check, always run host code, ignore IsHost call
        {0x140ebcfc4, {0x140ebcd44}}, // Client always uses host code for SetHostage2Flag lua command
        {0x140887905, {0x140888155}}, // Do not send sneak result (online request) on game over
        {0x1416026ce, {0x14160154e}}, // Do not send sneak result on mission end (fob results screen)
        // Trap check is player and local is always true #2, fix crash on enter; SETZ AL encoded differently
        {0x144e42a62, {0x140587ec3, {0x0f, 0x94, 0xc0}}},
        // Trap check is player and local is always true, fix crash on enter; XOR AL, AL encoded differently
        {0x144e42a8e, {0x140587eef, {0x32, 0xc0}}},
        // Trap check is player and host is always true, fix crash on enter; XOR AL, AL encoded differently
        {0x144e46f45, {0x1405888c6, {0x32, 0xc0}}},
        {0x14625fd1a, {0x1409c176a}}, // DoesFobGhostPlayer remove mission ID check
        // Always start fob p2p resolver, ignore exists check (not needed?); MOV RBX, RCX encoded differently
        {0x1459b60b5,
            {0x1407debf6,
                {0x48, 0x83, 0x79, 0x58, 0x00, 0x48, 0x8b, 0xd9, 0x75, 0x09},
                {0xf2, 0x48, 0x90, 0x48, 0x90, 0x48, 0x8b, 0xd9, 0x48, 0x90}}},
        {0x140da58e5, {0x140da5795}}, // Always run host damage controller implementation
        {0x146457b68, {0x140a1a759}}, // always run full CloseSession code, ignore mission code check
        {0x14163fcda, {0x14163ea0a}}, // add Quiet and Ocelot to staff list in sortie by ignoring
        {0x1409cc6c0, {0x1409cd370}}, // skip some check that resets player to Snake from Quiet/Ocelot
        {0x149cfba54, {0x1412cc76e}}, // skip check and call FUN_1411b4350 that sets up dual revolvers for Ocelot
        {0x149f4f17b, {0x14136bd2b}}, // always use non-fob function to update cp member status
        {0x1409c9a13, {0x1409ca6b3}}, // always apply opponent (or partner) emblem
        {0x149c1758d, {0x1412631c7}}, // exit motion fixing loop immediately
        {0x14a62cf4e, {0x141714f2e}}, // skip walker gear equip sync handling
        {0x1417cce2a, {0x1417cc24a}}, // Boss Quiet always jumps instead of running
        {0x1417ccd72, {0x1417cc192}}, // Boss Quiet always jumps instead of running, patch 2
        {0x1417d54f7, {0x1417d4a17}}, // ignore host check to always process Boss Quiet damage locally
    };
}

#endif
