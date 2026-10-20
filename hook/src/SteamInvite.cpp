#include "SteamInvite.h"

#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
#include <charconv>
#include <cstring>
#include <format>

namespace Dynamite {
    namespace {
        // steam_api64.dll exports, present both in Steamworks SDK used by the game (2015) and in current one
        using SteamClientFunc = void *(*)();
        using CreateInterfaceFunc = void *(*)(const char *version);
        using GetHSteamFunc = int32_t (*)();
        using RegisterCallbackFunc = void (*)(void *callback, int callbackID);

        // interface versions are requested explicitly, so vtable slots below do not depend on game's SDK version;
        // slots are from Steamworks SDK headers isteamclient.h (SteamClient012-020), isteamuser.h, isteamfriends.h
        constexpr auto SteamClientVersion = "SteamClient020";
        constexpr auto SteamUserVersion = "SteamUser023";
        constexpr auto SteamFriendsVersion = "SteamFriends017";

        constexpr int SlotGetISteamUser = 5;
        constexpr int SlotGetISteamFriends = 8;
        constexpr int SlotGetSteamID = 2;
        constexpr int SlotSetRichPresence = 43;
        constexpr int SlotActivateGameOverlayInviteDialogConnectString = 75;

        using GetInterfaceFunc = void *(*)(void *client, int32_t user, int32_t pipe, const char *version);
        // CSteamID is returned through hidden pointer (MSVC, member function returning class)
        using GetSteamIDFunc = uint64_t *(*)(void *user, uint64_t *result);
        using SetRichPresenceFunc = bool (*)(void *friends, const char *key, const char *value);
        using ActivateInviteDialogFunc = void (*)(void *friends, const char *connectString);

        template <typename F> F Slot(void *iface, int slot) { return reinterpret_cast<F>((*static_cast<void ***>(iface))[slot]); }

        constexpr auto ConnectPrefix = "+dynamite_connect";

        // individual Steam account in public universe, same check as in Config
        bool ValidSteamID(uint64_t id) { return id >= 0x0110000100000000 && id <= 0x01100001FFFFFFFF; }

        // CCallbackBase (steam_api_common.h): vtable, flags and id are set by SteamAPI_RegisterCallback
        struct CallbackBase {
            void *const *vtable;
            uint8_t flags;
            int32_t id;
        };

        // GameRichPresenceJoinRequested_t, isteamfriends.h: posted when user joins a friend from friends list or
        // accepts an invite
        struct JoinRequested {
            uint64_t friendSteamID;
            char connect[256];
        };

        constexpr int JoinRequestedID = 300 + 37; // k_iSteamFriendsCallbacks + 37

        std::atomic<uint64_t> joinRequest{0};

        // called by Steam from SteamAPI_RunCallbacks, only stores host id: spdlog logger is single threaded
        void RunJoinRequested(CallbackBase * /*self*/, const JoinRequested *param) {
            char connect[sizeof(param->connect) + 1]{};
            std::memcpy(connect, param->connect, sizeof(param->connect));

            auto host = SteamInvite::ParseConnectString(connect);
            if (host == 0 && ValidSteamID(param->friendSteamID)) {
                host = param->friendSteamID;
            }

            if (host != 0) {
                joinRequest = host;
            }
        }

        int JoinRequestedSize(CallbackBase * /*self*/) { return sizeof(JoinRequested); }

        // CCallbackBase has two Run overloads, their order in vtable differs between compilers; both go here
        void *const joinRequestedVtable[] = {
            reinterpret_cast<void *>(&RunJoinRequested),
            reinterpret_cast<void *>(&RunJoinRequested),
            reinterpret_cast<void *>(&JoinRequestedSize),
        };

        // static storage: Steam keeps the pointer until the game exits
        CallbackBase joinRequestedCallback{joinRequestedVtable, 0, 0};
    }

    bool SteamInvite::Init(bool host) {
        if (initialized) {
            return true;
        }

        const auto notReady = [this](const char *reason) {
            if (!loggedNotReady) {
                spdlog::info("SteamInvite::Init, Steam is not ready: {}", reason);
                loggedNotReady = true;
            }

            return false;
        };

        const auto steamAPI = GetModuleHandleW(L"steam_api64.dll");
        if (steamAPI == nullptr) {
            return notReady("steam_api64.dll is not loaded");
        }

        const auto getUser = reinterpret_cast<GetHSteamFunc>(GetProcAddress(steamAPI, "SteamAPI_GetHSteamUser"));
        const auto getPipe = reinterpret_cast<GetHSteamFunc>(GetProcAddress(steamAPI, "SteamAPI_GetHSteamPipe"));
        const auto registerCallback = reinterpret_cast<RegisterCallbackFunc>(GetProcAddress(steamAPI, "SteamAPI_RegisterCallback"));
        const auto steamClient = reinterpret_cast<SteamClientFunc>(GetProcAddress(steamAPI, "SteamClient"));
        const auto createInterface = reinterpret_cast<CreateInterfaceFunc>(GetProcAddress(steamAPI, "SteamInternal_CreateInterface"));
        if (getUser == nullptr || getPipe == nullptr || registerCallback == nullptr || (steamClient == nullptr && createInterface == nullptr)) {
            spdlog::error("{}, steam_api64.dll does not have required functions, Steam invites disabled", __PRETTY_FUNCTION__);
            initialized = true;
            return false;
        }

        const auto user = getUser();
        const auto pipe = getPipe();
        if (user == 0 || pipe == 0) {
            return notReady("no Steam user");
        }

        void *client = steamClient != nullptr ? steamClient() : createInterface(SteamClientVersion);
        if (client == nullptr) {
            return notReady("no Steam client");
        }

        friends = Slot<GetInterfaceFunc>(client, SlotGetISteamFriends)(client, user, pipe, SteamFriendsVersion);
        if (friends == nullptr) {
            spdlog::error("{}, cannot get {}, Steam invites disabled", __PRETTY_FUNCTION__, SteamFriendsVersion);
            initialized = true;
            return false;
        }

        registerCallback(&joinRequestedCallback, JoinRequestedID);
        initialized = true;

        if (!host) {
            spdlog::info("{}, client, waiting for join requests and invites", __PRETTY_FUNCTION__);
            return true;
        }

        const auto steamUser = Slot<GetInterfaceFunc>(client, SlotGetISteamUser)(client, user, pipe, SteamUserVersion);
        if (steamUser == nullptr) {
            spdlog::error("{}, cannot get {}, Steam invites disabled", __PRETTY_FUNCTION__, SteamUserVersion);
            friends = nullptr;
            return false;
        }

        uint64_t steamID = 0;
        Slot<GetSteamIDFunc>(steamUser, SlotGetSteamID)(steamUser, &steamID);
        if (!ValidSteamID(steamID)) {
            spdlog::error("{}, invalid own Steam ID {}, Steam invites disabled", __PRETTY_FUNCTION__, steamID);
            friends = nullptr;
            return false;
        }

        connectString = ConnectString(steamID);
        const auto setRichPresence = Slot<SetRichPresenceFunc>(friends, SlotSetRichPresence);
        if (!setRichPresence(friends, "connect", connectString.c_str())) {
            spdlog::error("{}, cannot set rich presence, Steam invites disabled", __PRETTY_FUNCTION__);
            friends = nullptr;
            return false;
        }

        setRichPresence(friends, "status", "dynamite co-op host");
        spdlog::info("{}, host, friends can join through Steam: {}", __PRETTY_FUNCTION__, connectString);

        return true;
    }

    bool SteamInvite::Initialized() const { return initialized; }

    bool SteamInvite::OpenInviteDialog() const {
        if (friends == nullptr || connectString.empty()) {
            spdlog::warn("{}, Steam invites are not available (host mode only)", __PRETTY_FUNCTION__);
            return false;
        }

        spdlog::info("{}", __PRETTY_FUNCTION__);
        Slot<ActivateInviteDialogFunc>(friends, SlotActivateGameOverlayInviteDialogConnectString)(friends, connectString.c_str());
        return true;
    }

    uint64_t SteamInvite::TakeJoinRequest() { return joinRequest.exchange(0); }

    void SteamInvite::ReadCommandLine(const char *commandLine) {
        if (commandLine == nullptr) {
            return;
        }

        const auto host = ParseConnectString(commandLine);
        if (host != 0) {
            spdlog::info("{}, join request from command line, host {}", __PRETTY_FUNCTION__, host);
            joinRequest = host;
        }
    }

    uint64_t SteamInvite::ParseConnectString(const char *s) {
        const auto p = std::strstr(s, ConnectPrefix);
        if (p == nullptr) {
            return 0;
        }

        auto begin = p + std::strlen(ConnectPrefix);
        while (*begin == ' ' || *begin == '"') {
            begin++;
        }

        uint64_t id = 0;
        const auto [ptr, ec] = std::from_chars(begin, begin + std::strlen(begin), id);
        if (ec != std::errc() || !ValidSteamID(id)) {
            return 0;
        }

        return id;
    }

    std::string SteamInvite::ConnectString(uint64_t hostSteamID) { return std::format("{} {}", ConnectPrefix, hostSteamID); }
}
