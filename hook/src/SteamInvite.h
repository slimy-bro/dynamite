#ifndef HOOK_STEAMINVITE_H
#define HOOK_STEAMINVITE_H

#include <cstdint>
#include <string>

namespace Dynamite {
    // Invites and joining through Steam overlay.
    // Host sets "connect" rich presence: friends get "Join Game" in Steam friends list and overlay, host can invite
    // them from overlay. Client gets host Steam ID when joining or accepting an invite and connects.
    // Steam interfaces are called directly from game's steam_api64.dll, there are no Steamworks headers in this project.
    class SteamInvite {
      public:
        // must be called after game initialized Steam; false if Steam is not ready yet, try again later
        bool Init(bool host);
        bool Initialized() const;

        // host: opens Steam overlay dialog to invite friends
        bool OpenInviteDialog() const;

        // client: host Steam ID from join request or accepted invite, 0 if there is none
        static uint64_t TakeJoinRequest();

        // client: if game was not running, Steam starts it with connect string in command line
        static void ReadCommandLine(const char *commandLine);

        // host Steam ID from connect string, 0 if string is not a dynamite connect string
        static uint64_t ParseConnectString(const char *s);
        static std::string ConnectString(uint64_t hostSteamID);

      private:
        bool initialized = false;
        bool loggedNotReady = false;
        void *friends = nullptr;
        std::string connectString;
    };
}

#endif // HOOK_STEAMINVITE_H
