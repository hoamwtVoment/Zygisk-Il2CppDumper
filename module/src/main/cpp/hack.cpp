//
// Created by Perfare on 2020/7/4.
//

#include "hack.h"
#include "game.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <linux/unistd.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <vector>

namespace {

std::string status_path(const char *game_data_dir) {
    return std::string(game_data_dir) + "/files/il2cppdumper_status.log";
}

void write_status(const char *game_data_dir, const std::string &message, bool reset = false) {
    std::ofstream stream(status_path(game_data_dir), reset ? std::ios::trunc : std::ios::app);
    if (stream) {
        stream << message << '\n';
    }
    LOGI("%s", message.c_str());
}

#if defined(__aarch64__)

constexpr uintptr_t kGenshin70MetadataLoaderRva = 0x074B8FAC;
constexpr uint32_t kGenshin70MetadataLoaderPrologue[] = {
        0xA9BA7BFD, 0xA9016FFC, 0xA90267FA, 0xA9035FF8,
};

using MetadataLoader = void *(*)(const char *metadata_dir);

void *original_metadata_loader = nullptr;
std::string metadata_dump_dir;
std::atomic_bool metadata_dump_started{false};
std::atomic_bool metadata_hook_installing{false};
std::atomic_bool metadata_hook_installed{false};

std::string pointer_string(const void *value) {
    char buffer[32]{};
    snprintf(buffer, sizeof(buffer), "%p", value);
    return buffer;
}

std::string metadata_source_path(const char *metadata_dir) {
    if (metadata_dir && metadata_dir[0] != '\0') {
        std::string path(metadata_dir);
        if (path.back() != '/') {
            path.push_back('/');
        }
        path += "global-metadata.dat";
        struct stat source_stat{};
        if (stat(path.c_str(), &source_stat) == 0 && source_stat.st_size > 0) {
            return path;
        }
    }

    return std::string("/storage/emulated/0/Android/data/") + GamePackageName +
           "/files/il2cpp/Metadata/global-metadata.dat";
}

bool dump_decrypted_metadata(const void *metadata, const char *metadata_dir) {
    if (!metadata) {
        write_status(metadata_dump_dir.c_str(), "failed: metadata loader returned null");
        return false;
    }

    auto source_path = metadata_source_path(metadata_dir);
    struct stat source_stat{};
    if (stat(source_path.c_str(), &source_stat) != 0 || source_stat.st_size <= 0 ||
        source_stat.st_size > 512LL * 1024 * 1024) {
        write_status(metadata_dump_dir.c_str(), "failed: cannot determine metadata size from " +
                                                   source_path);
        return false;
    }

    const auto metadata_size = static_cast<size_t>(source_stat.st_size);
    const auto *bytes = static_cast<const uint8_t *>(metadata);
    char magic[32]{};
    snprintf(magic, sizeof(magic), "%02X %02X %02X %02X", bytes[0], bytes[1], bytes[2],
             bytes[3]);
    write_status(metadata_dump_dir.c_str(), "metadata decrypted: ptr=" + pointer_string(metadata) +
                                               " size=" + std::to_string(metadata_size) +
                                               " magic=" + magic);

    auto output_path = metadata_dump_dir + "/files/global-metadata-decrypted70.dat";
    int fd = open(output_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (fd == -1) {
        write_status(metadata_dump_dir.c_str(), "failed: cannot create " + output_path +
                                                   " errno=" + std::to_string(errno));
        return false;
    }

    constexpr size_t chunk_size = 1024 * 1024;
    constexpr size_t progress_step = 8 * 1024 * 1024;
    size_t offset = 0;
    size_t next_progress = progress_step;
    while (offset < metadata_size) {
        auto remaining = metadata_size - offset;
        auto requested = remaining < chunk_size ? remaining : chunk_size;
        auto written = write(fd, bytes + offset, requested);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            auto saved_errno = errno;
            close(fd);
            write_status(metadata_dump_dir.c_str(), "failed: metadata write stopped at " +
                                                       std::to_string(offset) + " bytes errno=" +
                                                       std::to_string(saved_errno));
            return false;
        }
        offset += static_cast<size_t>(written);
        if (offset >= next_progress && offset < metadata_size) {
            write_status(metadata_dump_dir.c_str(), "dumping decrypted metadata: " +
                                                       std::to_string(offset / (1024 * 1024)) +
                                                       "/" +
                                                       std::to_string(metadata_size / (1024 * 1024)) +
                                                       " MiB");
            next_progress += progress_step;
        }
    }

    fsync(fd);
    close(fd);
    write_status(metadata_dump_dir.c_str(), "complete: " + output_path + " (" +
                                               std::to_string(metadata_size) + " bytes, magic=" +
                                               magic + ")");
    return true;
}

bool read_self_memory(uintptr_t address, void *buffer, size_t size) {
    iovec local{buffer, size};
    iovec remote{reinterpret_cast<void *>(address), size};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) ==
           static_cast<ssize_t>(size);
}

bool looks_like_metadata_header(const uint8_t *header, size_t metadata_size) {
    uint32_t magic = 0;
    uint32_t version = 0;
    memcpy(&magic, header, sizeof(magic));
    memcpy(&version, header + 4, sizeof(version));
    if (magic != 0xFAB11BAF || version < 20 || version > 40) {
        return false;
    }

    int valid_ranges = 0;
    for (size_t offset = 8; offset + 8 <= 0x80; offset += 8) {
        uint32_t table_offset = 0;
        uint32_t table_size = 0;
        memcpy(&table_offset, header + offset, sizeof(table_offset));
        memcpy(&table_size, header + offset + 4, sizeof(table_size));
        if (table_offset >= 8 && table_offset <= metadata_size &&
            table_size <= metadata_size - table_offset) {
            ++valid_ranges;
        }
    }
    return valid_ranges >= 8;
}

bool scan_runtime_metadata(const char *game_data_dir) {
    metadata_dump_dir = game_data_dir;
    auto source_path = metadata_source_path(nullptr);
    struct stat source_stat{};
    if (stat(source_path.c_str(), &source_stat) != 0 || source_stat.st_size <= 0) {
        write_status(game_data_dir, "runtime scan failed: cannot stat " + source_path);
        return false;
    }
    const auto metadata_size = static_cast<size_t>(source_stat.st_size);
    write_status(game_data_dir, "runtime metadata scan starts in 3 seconds; expected size=" +
                                    std::to_string(metadata_size));
    sleep(3);
    if (metadata_dump_started.load()) {
        write_status(game_data_dir, "runtime metadata scan skipped: decrypt hook already captured buffer");
        return true;
    }

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        write_status(game_data_dir, "runtime scan failed: cannot open /proc/self/maps");
        return false;
    }

    constexpr size_t scan_chunk_size = 4 * 1024 * 1024;
    constexpr size_t maximum_mapping_size = 768ULL * 1024 * 1024;
    std::vector<uint8_t> buffer(scan_chunk_size + 0x100);
    char line[2048]{};
    size_t scanned = 0;
    size_t next_progress = 256ULL * 1024 * 1024;
    int candidate_mappings = 0;

    while (fgets(line, sizeof(line), maps)) {
        unsigned long long map_start_value = 0;
        unsigned long long map_end_value = 0;
        char permissions[5]{};
        char pathname[1024]{};
        int fields = sscanf(line, "%llx-%llx %4s %*s %*s %*s %1023[^\n]",
                            &map_start_value, &map_end_value, permissions, pathname);
        if (fields < 3 || permissions[0] != 'r') {
            continue;
        }
        auto map_start = static_cast<uintptr_t>(map_start_value);
        auto map_end = static_cast<uintptr_t>(map_end_value);
        if (map_end <= map_start) {
            continue;
        }
        auto map_size = static_cast<size_t>(map_end - map_start);
        if (map_size < metadata_size || map_size > maximum_mapping_size) {
            continue;
        }
        if (fields >= 4) {
            const char *path = pathname;
            while (*path == ' ') {
                ++path;
            }
            if (*path == '/') {
                continue;
            }
        }

        ++candidate_mappings;
        size_t map_offset = 0;
        while (map_offset < map_size) {
            auto remaining = map_size - map_offset;
            auto request = remaining < scan_chunk_size ? remaining : scan_chunk_size;
            if (!read_self_memory(map_start + map_offset, buffer.data(), request)) {
                map_offset += request;
                scanned += request;
                continue;
            }

            for (size_t index = 0; index + 0x100 <= request; ++index) {
                if (buffer[index] != 0xAF || buffer[index + 1] != 0x1B ||
                    buffer[index + 2] != 0xB1 || buffer[index + 3] != 0xFA) {
                    continue;
                }
                auto address = map_start + map_offset + index;
                if (metadata_size > map_end - address ||
                    !looks_like_metadata_header(buffer.data() + index, metadata_size)) {
                    continue;
                }

                fclose(maps);
                write_status(game_data_dir, "runtime metadata located at " +
                                                pointer_string(reinterpret_cast<void *>(address)) +
                                                " after scanning " + std::to_string(scanned) +
                                                " bytes");
                if (!metadata_dump_started.exchange(true)) {
                    return dump_decrypted_metadata(reinterpret_cast<void *>(address), nullptr);
                }
                return true;
            }

            auto advance = remaining > request ? request - 0x100 : request;
            map_offset += advance;
            scanned += advance;
            if (scanned >= next_progress) {
                write_status(game_data_dir, "runtime metadata scan progress: " +
                                                std::to_string(scanned / (1024 * 1024)) +
                                                " MiB");
                next_progress += 256ULL * 1024 * 1024;
            }
        }
    }

    fclose(maps);
    write_status(game_data_dir, "runtime metadata scan complete: no standard header found; mappings=" +
                                    std::to_string(candidate_mappings) + " scanned=" +
                                    std::to_string(scanned) + " bytes");
    return false;
}

bool invoke_metadata_loader_for_dump(const char *game_data_dir) {
    if (!original_metadata_loader) {
        write_status(game_data_dir, "active metadata decrypt failed: original loader unavailable");
        return false;
    }

    auto metadata_dir = std::string("/storage/emulated/0/Android/data/") + GamePackageName +
                        "/files/il2cpp/Metadata/";
    write_status(game_data_dir, "actively invoking 7.0 metadata loader: dir=" + metadata_dir);
    auto loader = reinterpret_cast<MetadataLoader>(original_metadata_loader);
    auto *metadata = loader(metadata_dir.c_str());
    if (!metadata) {
        write_status(game_data_dir, "active metadata decrypt failed: loader returned null");
        return false;
    }

    write_status(game_data_dir, "active metadata loader returned: ptr=" +
                                    pointer_string(metadata));
    if (!metadata_dump_started.exchange(true)) {
        return dump_decrypted_metadata(metadata, metadata_dir.c_str());
    }
    return true;
}

void *hooked_metadata_loader(const char *metadata_dir) {
    write_status(metadata_dump_dir.c_str(), "metadata decrypt hook entered: dir=" +
                                               std::string(metadata_dir ? metadata_dir : "<null>"));
    auto *metadata = reinterpret_cast<MetadataLoader>(original_metadata_loader)(metadata_dir);
    if (!metadata_dump_started.exchange(true)) {
        dump_decrypted_metadata(metadata, metadata_dir);
    }
    return metadata;
}

bool install_inline_hook(void *target, void *replacement, void **original) {
    constexpr size_t overwritten_size = sizeof(kGenshin70MetadataLoaderPrologue);
    constexpr size_t trampoline_size = overwritten_size + 16;
    auto *trampoline = static_cast<uint8_t *>(mmap(nullptr, trampoline_size,
                                                    PROT_READ | PROT_WRITE,
                                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (trampoline == MAP_FAILED) {
        return false;
    }

    memcpy(trampoline, target, overwritten_size);
    const uint32_t absolute_jump[] = {0x58000051, 0xD61F0220}; // ldr x17, #8; br x17
    memcpy(trampoline + overwritten_size, absolute_jump, sizeof(absolute_jump));
    auto resume = reinterpret_cast<uintptr_t>(target) + overwritten_size;
    memcpy(trampoline + overwritten_size + sizeof(absolute_jump), &resume, sizeof(resume));
    __builtin___clear_cache(reinterpret_cast<char *>(trampoline),
                            reinterpret_cast<char *>(trampoline + trampoline_size));
    if (mprotect(trampoline, trampoline_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(trampoline, trampoline_size);
        return false;
    }
    *original = trampoline;

    auto page_size = static_cast<uintptr_t>(sysconf(_SC_PAGESIZE));
    auto page = reinterpret_cast<uintptr_t>(target) & ~(page_size - 1);
    if (mprotect(reinterpret_cast<void *>(page), page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        munmap(trampoline, trampoline_size);
        return false;
    }

    uint8_t patch[16]{};
    memcpy(patch, absolute_jump, sizeof(absolute_jump));
    auto replacement_address = reinterpret_cast<uintptr_t>(replacement);
    memcpy(patch + sizeof(absolute_jump), &replacement_address, sizeof(replacement_address));
    memcpy(target, patch, sizeof(patch));
    __builtin___clear_cache(reinterpret_cast<char *>(target),
                            reinterpret_cast<char *>(target) + sizeof(patch));
    mprotect(reinterpret_cast<void *>(page), page_size, PROT_READ | PROT_EXEC);
    return true;
}

bool install_genshin70_metadata_hook(void *handle, const char *game_data_dir) {
    if (metadata_hook_installed.load()) {
        return true;
    }
    bool expected = false;
    if (!metadata_hook_installing.compare_exchange_strong(expected, true)) {
        return metadata_hook_installed.load();
    }

    xdl_info_t info{};
    if (xdl_info(handle, XDL_DI_DLINFO, &info) != 0 || !info.dli_fbase) {
        write_status(game_data_dir, "failed: cannot resolve libyuanshen.so load base");
        metadata_hook_installing.store(false);
        return false;
    }

    auto *target = static_cast<uint8_t *>(info.dli_fbase) + kGenshin70MetadataLoaderRva;
    if (memcmp(target, kGenshin70MetadataLoaderPrologue,
               sizeof(kGenshin70MetadataLoaderPrologue)) != 0) {
        write_status(game_data_dir, "failed: 7.0 metadata loader prologue mismatch at " +
                                        pointer_string(target));
        metadata_hook_installing.store(false);
        return false;
    }

    metadata_dump_dir = game_data_dir;
    original_metadata_loader = target;
    metadata_hook_installed.store(true);
    metadata_hook_installing.store(false);
    write_status(game_data_dir, "7.0 metadata loader resolved without patching: base=" +
                                    pointer_string(info.dli_fbase) + " target=" +
                                    pointer_string(target) + " RVA=0x74B8FAC");
    return true;
}

#endif

}

void hack_start(const char *game_data_dir) {
    constexpr const char *library_candidates[] = {"libil2cpp.so", "libyuanshen.so"};
    write_status(game_data_dir, "module injected; waiting for IL2CPP runtime library", true);
    constexpr int timeout_ms = 1800 * 1000;
    int elapsed_ms = 0;
    int next_status_ms = 30 * 1000;
    while (elapsed_ms < timeout_ms) {
        void *handle = nullptr;
        const char *library_name = nullptr;
        for (const auto candidate : library_candidates) {
            handle = xdl_open(candidate, 0);
            if (handle) {
                library_name = candidate;
                break;
            }
        }
        if (handle) {
            write_status(game_data_dir, std::string(library_name) + " found");
#if defined(__aarch64__)
            if (strcmp(library_name, "libyuanshen.so") == 0) {
                if (!install_genshin70_metadata_hook(handle, game_data_dir)) {
                    write_status(game_data_dir,
                                 "failed: 7.0 metadata loader could not be resolved; stopping");
                    return;
                }
                write_status(game_data_dir,
                             "waiting 3 seconds before active metadata loader invocation");
                sleep(3);
                if (!invoke_metadata_loader_for_dump(game_data_dir)) {
                    write_status(game_data_dir,
                                 "failed: active metadata extraction did not produce an output; "
                                 "runtime memory scan disabled");
                }
                return;
            }
#endif
            write_status(game_data_dir, "resolving IL2CPP APIs");
            if (!il2cpp_api_init(handle)) {
                write_status(game_data_dir, "failed: required IL2CPP APIs are not exported");
                return;
            }
            write_status(game_data_dir, "IL2CPP initialized; dumping classes");
            il2cpp_dump(game_data_dir);
            struct stat dump_stat{};
            auto dump_path = std::string(game_data_dir) + "/files/dump.cs";
            if (stat(dump_path.c_str(), &dump_stat) == 0 && dump_stat.st_size > 0) {
                write_status(game_data_dir, "complete: dump.cs written (" +
                                            std::to_string(dump_stat.st_size) + " bytes)");
            } else {
                write_status(game_data_dir, "failed: dump.cs was not created");
            }
            return;
        }
        int delay_ms = elapsed_ms < 60 * 1000 ? 10 : 1000;
        usleep(delay_ms * 1000);
        elapsed_ms += delay_ms;
        if (elapsed_ms >= next_status_ms) {
            write_status(game_data_dir, "still waiting for IL2CPP runtime library (" +
                                        std::to_string(elapsed_ms / 1000) + " seconds)");
            next_status_ms += 30 * 1000;
        }
    }
    write_status(game_data_dir, "failed: IL2CPP runtime library not loaded after 1800 seconds");
}

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz,
                                                                "currentApplication",
                                                                "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz,
                                                              currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz,
                                                                  "getApplicationInfo",
                                                                  "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application,
                                                                     get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(
                            env->GetObjectClass(application_info), "nativeLibraryDir",
                            "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(
                                application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        LOGI("lib dir %s", path);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    } else {
                        LOGE("nativeLibraryDir not found");
                    }
                } else {
                    LOGE("getApplicationInfo not found");
                }
            } else {
                LOGE("application class not found");
            }
        } else {
            LOGE("currentApplication not found");
        }
    } else {
        LOGE("ActivityThread not found");
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version;
    void *initialize;

    void *(*loadLibrary)(const char *libpath, int flag);

    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);

    void *isSupported;
    void *getAppEnv;
    void *isCompatibleWith;
    void *getSignalHandler;
    void *unloadLibrary;
    void *getError;
    void *isPathSupported;
    void *initAnonymousNamespace;
    void *createNamespace;
    void *linkNamespaces;

    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    //TODO 等待houdini初始化
    sleep(5);

    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart,
                                                                             "JNI_GetCreatedJavaVMs");
    LOGI("JNI_GetCreatedJavaVMs %p", JNI_GetCreatedJavaVMs);
    JavaVM *vms_buf[1];
    JavaVM *vms;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) {
        vms = vms_buf[0];
    } else {
        LOGE("GetCreatedJavaVMs error");
        return false;
    }

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty()) {
        LOGE("GetLibDir error");
        return false;
    }
    if (lib_dir.find("/lib/x86") != std::string::npos) {
        LOGI("no need NativeBridge");
        munmap(data, length);
        return false;
    }

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        LOGI("native bridge: %s", native_bridge.data());
        nb = dlopen(native_bridge.data(), RTLD_NOW);
    }
    if (nb) {
        LOGI("nb %p", nb);
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            LOGI("NativeBridgeLoadLibrary %p", callbacks->loadLibrary);
            LOGI("NativeBridgeLoadLibraryExt %p", callbacks->loadLibraryExt);
            LOGI("NativeBridgeGetTrampoline %p", callbacks->getTrampoline);

            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);
            munmap(data, length);
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            LOGI("arm path %s", path);

            void *arm_handle;
            if (api_level >= 26) {
                arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
            } else {
                arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
            }
            if (arm_handle) {
                LOGI("arm handle %p", arm_handle);
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle,
                                                                                  "JNI_OnLoad",
                                                                                  nullptr, 0);
                LOGI("JNI_OnLoad %p", init);
                init(vms, (void *) game_data_dir);
                return true;
            }
            close(fd);
        }
    }
    return false;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack thread: %d", gettid());
    int api_level = android_get_device_api_level();
    LOGI("api level: %d", api_level);

#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
#endif
        hack_start(game_data_dir);
#if defined(__i386__) || defined(__x86_64__)
    }
#endif
}

#if defined(__arm__) || defined(__aarch64__)

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}

#endif
