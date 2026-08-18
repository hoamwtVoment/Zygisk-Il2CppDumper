#include <cstring>
#include <thread>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cinttypes>
#include "hack.h"
#include "zygisk.hpp"
#include "game.h"
#include "log.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

namespace {

using DlopenFunction = void *(*)(const char *filename, int flags);
using AndroidDlopenExtFunction = void *(*)(const char *filename, int flags,
                                            const void *extension_info);

DlopenFunction original_dlopen = nullptr;
AndroidDlopenExtFunction original_android_dlopen_ext = nullptr;
const char *early_game_data_dir = nullptr;
thread_local bool inside_load_hook = false;

void notify_library_loaded(const char *filename, void *handle) {
    if (handle && filename && early_game_data_dir && strstr(filename, "libyuanshen.so")) {
        hack_on_library_loaded(filename, early_game_data_dir);
    }
}

void *hooked_dlopen(const char *filename, int flags) {
    if (!original_dlopen) {
        return nullptr;
    }
    if (inside_load_hook) {
        return original_dlopen(filename, flags);
    }
    inside_load_hook = true;
    auto *handle = original_dlopen(filename, flags);
    notify_library_loaded(filename, handle);
    inside_load_hook = false;
    return handle;
}

void *hooked_android_dlopen_ext(const char *filename, int flags, const void *extension_info) {
    if (!original_android_dlopen_ext) {
        return nullptr;
    }
    if (inside_load_hook) {
        return original_android_dlopen_ext(filename, flags, extension_info);
    }
    inside_load_hook = true;
    auto *handle = original_android_dlopen_ext(filename, flags, extension_info);
    notify_library_loaded(filename, handle);
    inside_load_hook = false;
    return handle;
}

}

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        auto package_name = env->GetStringUTFChars(args->nice_name, nullptr);
        auto app_data_dir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        preSpecialize(package_name, app_data_dir);
        installEarlyLibraryHooks();
        env->ReleaseStringUTFChars(args->nice_name, package_name);
        env->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
    }

    void postAppSpecialize(const AppSpecializeArgs *) override {
        startHackThread();
    }

private:
    Api *api;
    JNIEnv *env;
    bool enable_hack = false;
    char *game_data_dir = nullptr;
    void *data = nullptr;
    size_t length = 0;
    bool hack_started = false;

    void installEarlyLibraryHooks() {
#if defined(__aarch64__)
        if (!enable_hack) {
            return;
        }
        early_game_data_dir = game_data_dir;
        api->pltHookRegister(".*", "dlopen", reinterpret_cast<void *>(hooked_dlopen),
                             reinterpret_cast<void **>(&original_dlopen));
        api->pltHookRegister(".*", "android_dlopen_ext",
                             reinterpret_cast<void *>(hooked_android_dlopen_ext),
                             reinterpret_cast<void **>(&original_android_dlopen_ext));
        LOGI("early library hooks committed: %s", api->pltHookCommit() ? "yes" : "no");
#endif
    }

    void startHackThread() {
        if (enable_hack && !hack_started) {
            hack_started = true;
            std::thread hack_thread(hack_prepare, game_data_dir, data, length);
            hack_thread.detach();
        }
    }

    void preSpecialize(const char *package_name, const char *app_data_dir) {
        if (strcmp(package_name, GamePackageName) == 0) {
            LOGI("detect game: %s", package_name);
            enable_hack = true;
            game_data_dir = new char[strlen(app_data_dir) + 1];
            strcpy(game_data_dir, app_data_dir);

#if defined(__i386__)
            auto path = "zygisk/armeabi-v7a.so";
#endif
#if defined(__x86_64__)
            auto path = "zygisk/arm64-v8a.so";
#endif
#if defined(__i386__) || defined(__x86_64__)
            int dirfd = api->getModuleDir();
            int fd = openat(dirfd, path, O_RDONLY);
            if (fd != -1) {
                struct stat sb{};
                fstat(fd, &sb);
                length = sb.st_size;
                data = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
                close(fd);
            } else {
                LOGW("Unable to open arm file");
            }
#endif
        } else {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
