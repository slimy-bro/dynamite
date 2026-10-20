#include "dynamite.h"
#include "windows.h"
#include <algorithm>
#include <eh.h>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>

#include "Config.h"
#include "Messagebox.h"
#include "MinHook.h"
#include "Tpp/TppGameObject.h"
#include "Tpp/TppNPCLifeState.h"
#include "memtag.h"
#include "mgsvtpp_addresses_1_0_15_3_en.h"
#include "mgsvtpp_addresses_1_0_15_4_en.h"
#include "mgsvtpp_func_typedefs.h"
#include "patch.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/spdlog.h"
#include "util.h"

#include "DynamiteHook.h"
#include "DynamiteLua.h"

namespace Dynamite {
    void Dynamite::AbortHandler(int signal_number) {
        auto l = spdlog::get(logName);
        if (l != nullptr) {
            l->error("abort was called");
            l->flush();
        }
    }

    void TerminateHandler() {
        const auto l = spdlog::get(logName);
        if (l != nullptr) {
            l->error("terminate was called");
            l->flush();
        }

        terminate_Original();
    }

    LONG WINAPI Dynamite::UnhandledExceptionHandler(EXCEPTION_POINTERS * /*ExceptionInfo*/) {
        const auto log = spdlog::get(logName);
        if (log != nullptr) {
            log->error("Unhandled exception");
            log->flush();
        }

        // return g_showCrashDialog ? EXCEPTION_CONTINUE_SEARCH : EXCEPTION_EXECUTE_HANDLER;
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void Dynamite::ReadConfig() {
        ConfigValidateResult r{};
        if (!cfg.Read(&r)) {
            spdlog::error(r.Message);
            ShowMessageBox(r.Message.c_str(), "Config error", MB_ICONERROR);
            exit(1);
        }

        cfg.Log();
    }

    // Hooking an exe with different addresses crashes the game on start.
    // Unreadable version is not treated as a mismatch.
    bool Dynamite::CheckGameVersion() {
        const auto toString = [](const uint16_t(&v)[4]) { return std::format("{}.{}.{}.{}", v[0], v[1], v[2], v[3]); };

        uint16_t version[4]{};
        if (!GetExeFileVersion(version)) {
            spdlog::warn("cannot read game version, assuming {}", toString(SupportedGameVersions[0].version));
            gameVersion = SupportedGameVersions[0].id;
            return true;
        }

        spdlog::info("game version {}", toString(version));
        std::string supported;
        for (const auto &v : SupportedGameVersions) {
            if (std::equal(std::begin(version), std::end(version), std::begin(v.version))) {
                gameVersion = v.id;
                return true;
            }

            supported += (supported.empty() ? "" : ", ") + toString(v.version);
        }

        const auto msg = std::format("Your game version is {}, dynamite supports only {}.\n\n"
                                     "dynamite is disabled for this session to prevent a crash.\n\n"
                                     "To play co-op, check for a dynamite update, see "
                                     "https://github.com/unknown321/dynamite/issues/136\n\n"
                                     "To play without dynamite, delete dinput8.dll from the game directory "
                                     "and verify integrity of game files in Steam.",
            toString(version),
            supported);
        spdlog::error(msg);
        ShowMessageBox(msg.c_str(), "Unsupported game version", MB_ICONERROR);

        return false;
    }

    // Disables hooks on addresses that do not have expected code (-1 is any byte).
    void Dynamite::CheckAddresses(const std::map<std::string, std::vector<int16_t>> &checks) {
        for (const auto &[name, expected] : checks) {
            const auto code = reinterpret_cast<const uint8_t *>(addressSet[name]);
            for (size_t i = 0; i < expected.size(); i++) {
                if (expected[i] >= 0 && code[i] != expected[i]) {
                    spdlog::error("{} at {:#x} has unexpected code, hook disabled", name, addressSet[name]);
                    addressSet[name] = 0;
                    break;
                }
            }
        }
    }

    void Dynamite::RebaseAddresses() {
        for (const auto &[name, addr] : addressSet) {
            const uint64_t rebasedAddr = (addr - BaseAddr) + RealBaseAddr;
            addressSet[name] = rebasedAddr;
        }
    }

    void Dynamite::SetupLogger() {
        log = spdlog::basic_logger_st(logName, logPath.string(), true);
        spdlog::set_default_logger(log);
        // using `flush_every` with multithreaded logger will result in application hang during DLL_PROCESS_DETACH
        spdlog::flush_on(spdlog::level::info);
        log->info("starting");
        log->info("dynamite {}", SOFTWARE_VERSION);
    }

    Dynamite::Dynamite() : thisModule{GetModuleHandle(nullptr)} {
        signal(SIGABRT, &AbortHandler);
        terminate_Original = std::set_terminate(TerminateHandler);
        _set_abort_behavior(1, _WRITE_ABORT_MSG);
        SetUnhandledExceptionFilter(UnhandledExceptionHandler);

        SetupLogger();

        // mgo bad
        HMODULE hExe = GetModuleHandle(nullptr);
        WCHAR fullPath[MAX_PATH]{0};
        GetModuleFileNameW(hExe, fullPath, MAX_PATH);
        std::filesystem::path path(fullPath);
        std::wstring exeName = path.filename().c_str();
        if (exeName.find(L"mgo") != std::wstring::npos) {
            return;
        }

        if (!CheckGameVersion()) {
            return;
        }

        MH_Initialize();

        addressSet = gameVersion == GameVersion::V1_0_15_4 ? mgsvtpp_adresses_1_0_15_4_en : mgsvtpp_adresses_1_0_15_3_en;
        RealBaseAddr = (size_t)GetModuleHandle(nullptr);

        RebaseAddresses();
        if (gameVersion == GameVersion::V1_0_15_4) {
            CheckAddresses(mgsvtpp_address_checks_1_0_15_4_en);
        }

        SetFuncPtrs();
        ReadConfig();
        CreateHooks();
        dynamiteCore.WithConfig(&cfg);
    }

    Dynamite::~Dynamite() {
        MH_Uninitialize();
    }


}