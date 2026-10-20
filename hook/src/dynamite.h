#ifndef HOOK_DYNAMITE_H
#define HOOK_DYNAMITE_H

#include "Config.h"
#include "DynamiteCore.h"
#include "DynamiteSyncImpl/DynamiteSyncImpl.h"
#include "Tpp/TppNPCLifeState.h"
#include "Tpp/TppTypes.h"
#include "Version.h"
#include "lua/lua.h"
#include "patch.h"
#include "spdlog/logger.h"
#include "windows.h"

#include <eh.h>
#include <filesystem>
#include <map>
#include <memory>
#include <vector>

namespace Dynamite {
    static const std::filesystem::path logPath = std::filesystem::path("dynamite") / std::filesystem::path("dynamite.log.txt");

    void TerminateHandler();
    inline terminate_function terminate_Original;
    static const std::string logName = "dynamite";
    inline std::map<std::string, uint64_t> addressSet;

    // addresses and patches are valid only for these exe versions
    enum class GameVersion { V1_0_15_3, V1_0_15_4 };
    inline GameVersion gameVersion = GameVersion::V1_0_15_3;

    class Dynamite {
      public:
        Dynamite();
        ~Dynamite();

        void SetupLogger();

        void RebaseAddresses();

        void CreateHooks() const;

        void CreateDebugHooks() const;

        void ReadConfig();

        static bool CheckGameVersion();

        static void CheckAddresses(const std::map<std::string, std::vector<int16_t>> &checks);

        void SetFuncPtrs();

        static void AbortHandler(int signal_number);

        static LONG WINAPI UnhandledExceptionHandler(EXCEPTION_POINTERS * /*ExceptionInfo*/);

        static std::vector<Patch> GetPatches();

        static bool PatchMasterServerURL(const std::string &url);

        DynamiteSyncImpl dynamiteSyncImpl;

        DynamiteCore dynamiteCore;

        Config cfg{};

        std::map<uint32_t, std::string> messageDict;
        std::map<uint64_t, std::string> pathDict;
      private:
        static constexpr uint64_t BaseAddr = 0x140000000;
        struct SupportedGameVersion {
            GameVersion id;
            uint16_t version[4];
        };

        static constexpr SupportedGameVersion SupportedGameVersions[] = {
            {GameVersion::V1_0_15_3, {1, 0, 15, 3}},
            {GameVersion::V1_0_15_4, {1, 0, 15, 4}},
        };
        uint64_t RealBaseAddr = 0;
        HMODULE thisModule{nullptr};
        std::shared_ptr<spdlog::logger> log = nullptr;

    };
}

#endif // HOOK_DYNAMITE_H
