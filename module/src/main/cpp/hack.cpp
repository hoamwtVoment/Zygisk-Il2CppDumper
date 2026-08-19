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
#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <set>
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
using MetadataBufferDecoder = int (*)(void *buffer, uint32_t length);
using MetadataCrypto = void (*)(void *context, void *state, void *key, void *output,
                                void *input);
using MetadataWholeTransform = void *(*)(void *buffer, uint32_t length);

void *original_metadata_loader = nullptr;
uintptr_t genshin_module_base = 0;
std::string metadata_dump_dir;
std::atomic_bool metadata_dump_started{false};
std::atomic_bool metadata_hook_installing{false};
std::atomic_bool metadata_hook_installed{false};
MetadataCrypto original_metadata_crypto = nullptr;
MetadataWholeTransform original_metadata_whole_transform = nullptr;
std::atomic_bool metadata_crypto_probe_installed{false};
std::atomic_bool metadata_whole_probe_installed{false};
std::atomic<uint32_t> metadata_crypto_probe_calls{0};
std::atomic<uint32_t> metadata_whole_probe_calls{0};

constexpr uint32_t kMetadataCryptoProbeCapacity = 1024;
constexpr size_t kMetadataCryptoContextSize = 0xE50;
constexpr size_t kMetadataCryptoWorkspaceSize = 0xB00;
struct MetadataCryptoProbeRecord {
    uint32_t magic;
    uint32_t call;
    uintptr_t args[5];
    uint8_t before_x1[0x40];
    uint8_t before_x2[0x40];
    uint8_t before_x3[0x40];
    uint8_t before_x4[0x40];
    uint8_t after_x2[0x40];
    uint8_t after_x3[0x40];
    uint8_t after_x4[0x40];
};
std::array<MetadataCryptoProbeRecord, kMetadataCryptoProbeCapacity>
        metadata_crypto_probe_records{};

struct MetadataCryptoContextProbe {
    uint32_t magic;
    uint32_t version;
    uint32_t captured_calls;
    uint32_t context_size;
    uint32_t workspace_size;
    uint32_t reserved;
    uintptr_t args[5];
    uint8_t context_before[kMetadataCryptoContextSize];
    uint8_t context_after[kMetadataCryptoContextSize];
    uint8_t workspace_before[kMetadataCryptoWorkspaceSize];
    uint8_t workspace_after[kMetadataCryptoWorkspaceSize];
};
MetadataCryptoContextProbe metadata_crypto_context_probe{};

bool install_inline_hook(void *target, void *replacement, void **original);
void dump_metadata_layout_probes(const char *game_data_dir, const void *metadata,
                                 size_t metadata_size);

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
    dump_metadata_layout_probes(metadata_dump_dir.c_str(), metadata, metadata_size);

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

bool dump_runtime_blob(const char *game_data_dir, const char *file_name, uintptr_t address,
                       size_t size) {
    std::vector<uint8_t> data(size);
    if (!read_self_memory(address, data.data(), data.size())) {
        write_status(game_data_dir, std::string("failed: cannot read ") + file_name +
                                        " at " + pointer_string(reinterpret_cast<void *>(address)));
        return false;
    }

    auto output_path = std::string(game_data_dir) + "/files/" + file_name;
    int fd = open(output_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (fd == -1) {
        write_status(game_data_dir, "failed: cannot create " + output_path +
                                        " errno=" + std::to_string(errno));
        return false;
    }

    size_t written_total = 0;
    while (written_total < data.size()) {
        auto written = write(fd, data.data() + written_total, data.size() - written_total);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            close(fd);
            write_status(game_data_dir, "failed: cannot write " + output_path);
            return false;
        }
        written_total += static_cast<size_t>(written);
    }
    fsync(fd);
    close(fd);
    write_status(game_data_dir, "runtime state captured: " + output_path + " (" +
                                    std::to_string(size) + " bytes)");
    return true;
}

bool write_blob_file(const std::string &path, const void *data, size_t size) {
    int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (fd == -1) {
        return false;
    }
    const auto *bytes = static_cast<const uint8_t *>(data);
    size_t written_total = 0;
    while (written_total < size) {
        auto written = write(fd, bytes + written_total, size - written_total);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            close(fd);
            return false;
        }
        written_total += static_cast<size_t>(written);
    }
    fsync(fd);
    close(fd);
    return true;
}

void dump_metadata_layout_probes(const char *game_data_dir, const void *metadata,
                                 size_t metadata_size) {
    const auto *base = static_cast<const uint8_t *>(metadata);
    const auto dump = [&](const char *name, size_t offset, size_t size) {
        if (offset > metadata_size || size > metadata_size - offset) {
            write_status(game_data_dir, std::string("metadata probe skipped: ") + name);
            return;
        }
        std::vector<uint8_t> bytes(size);
        if (!read_self_memory(reinterpret_cast<uintptr_t>(base + offset), bytes.data(), size) ||
            !write_blob_file(std::string(game_data_dir) + "/files/" + name, bytes.data(), size)) {
            write_status(game_data_dir, std::string("metadata probe failed: ") + name);
            return;
        }
        write_status(game_data_dir, std::string("metadata probe written: ") + name +
                                       " (" + std::to_string(size) + " bytes, offset=0x" +
                                       [&] { char b[32]{}; snprintf(b, sizeof(b), "%zX", offset); return std::string(b); }() + ")");
    };

    dump("metadata-buffer-head70.bin", 0, 0x1000);
    dump("metadata-buffer-plus80070.bin", 0x800, 0x1000);
    const size_t tail_size = metadata_size < 0x4000 ? metadata_size : 0x4000;
    dump("metadata-buffer-tail70.bin", metadata_size - tail_size, tail_size);

    constexpr size_t block_stride = 0x4AF40;
    constexpr size_t block_count = 256;
    std::vector<uint8_t> block_heads;
    block_heads.reserve(block_count * 0x40);
    for (size_t i = 0; i < block_count; ++i) {
        const size_t offset = i * block_stride;
        if (offset + 0x40 > metadata_size) {
            break;
        }
        const auto old_size = block_heads.size();
        block_heads.resize(old_size + 0x40);
        if (!read_self_memory(reinterpret_cast<uintptr_t>(base + offset),
                              block_heads.data() + old_size, 0x40)) {
            block_heads.resize(old_size);
            break;
        }
    }
    if (!block_heads.empty() &&
        write_blob_file(std::string(game_data_dir) + "/files/metadata-block-heads70.bin",
                        block_heads.data(), block_heads.size())) {
        write_status(game_data_dir, "metadata probe written: metadata-block-heads70.bin (" +
                                       std::to_string(block_heads.size()) +
                                       " bytes, stride=0x4AF40)");
    }
}

void hooked_metadata_crypto(void *context, void *state, void *key, void *output, void *input) {
    auto original = original_metadata_crypto;
    if (!original) {
        return;
    }
    const auto call = metadata_crypto_probe_calls.fetch_add(1);
    if (call >= kMetadataCryptoProbeCapacity) {
        original(context, state, key, output, input);
        return;
    }

    if (call == 0) {
        metadata_crypto_context_probe.magic = 0x58433747; // G7CX
        metadata_crypto_context_probe.version = 1;
        metadata_crypto_context_probe.context_size = kMetadataCryptoContextSize;
        metadata_crypto_context_probe.workspace_size = kMetadataCryptoWorkspaceSize;
        metadata_crypto_context_probe.args[0] = reinterpret_cast<uintptr_t>(context);
        metadata_crypto_context_probe.args[1] = reinterpret_cast<uintptr_t>(state);
        metadata_crypto_context_probe.args[2] = reinterpret_cast<uintptr_t>(key);
        metadata_crypto_context_probe.args[3] = reinterpret_cast<uintptr_t>(output);
        metadata_crypto_context_probe.args[4] = reinterpret_cast<uintptr_t>(input);
        memcpy(metadata_crypto_context_probe.context_before, context,
               sizeof(metadata_crypto_context_probe.context_before));
        memcpy(metadata_crypto_context_probe.workspace_before, input,
               sizeof(metadata_crypto_context_probe.workspace_before));
    }

    auto &record = metadata_crypto_probe_records[call];
    record.magic = 0x50374347; // G7CP
    record.call = call;
    record.args[0] = reinterpret_cast<uintptr_t>(context);
    record.args[1] = reinterpret_cast<uintptr_t>(state);
    record.args[2] = reinterpret_cast<uintptr_t>(key);
    record.args[3] = reinterpret_cast<uintptr_t>(output);
    record.args[4] = reinterpret_cast<uintptr_t>(input);
    memcpy(record.before_x1, state, sizeof(record.before_x1));
    memcpy(record.before_x2, key, sizeof(record.before_x2));
    memcpy(record.before_x3, output, sizeof(record.before_x3));
    memcpy(record.before_x4, input, sizeof(record.before_x4));

    original(context, state, key, output, input);

    memcpy(record.after_x2, key, sizeof(record.after_x2));
    memcpy(record.after_x3, output, sizeof(record.after_x3));
    memcpy(record.after_x4, input, sizeof(record.after_x4));
    memcpy(metadata_crypto_context_probe.context_after, context,
           sizeof(metadata_crypto_context_probe.context_after));
    memcpy(metadata_crypto_context_probe.workspace_after, input,
           sizeof(metadata_crypto_context_probe.workspace_after));
    metadata_crypto_context_probe.captured_calls = call + 1;
}

void dump_metadata_crypto_probe(const char *game_data_dir) {
    const auto calls = metadata_crypto_probe_calls.load();
    const auto records = calls < kMetadataCryptoProbeCapacity ? calls
                                                               : kMetadataCryptoProbeCapacity;
    const auto path = std::string(game_data_dir) + "/files/metadata-crypto-probe70.bin";
    if (records == 0 ||
        !write_blob_file(path, metadata_crypto_probe_records.data(),
                         records * sizeof(MetadataCryptoProbeRecord))) {
        write_status(game_data_dir, "metadata crypto probe dump failed; calls=" +
                                       std::to_string(calls));
        return;
    }
    write_status(game_data_dir, "metadata crypto probe complete: captured=" +
                                   std::to_string(records) + "/" +
                                   std::to_string(calls) + " calls record_size=" +
                                   std::to_string(sizeof(MetadataCryptoProbeRecord)));

    const auto context_path = std::string(game_data_dir) +
                              "/files/metadata-crypto-context70.bin";
    if (write_blob_file(context_path, &metadata_crypto_context_probe,
                        sizeof(metadata_crypto_context_probe))) {
        write_status(game_data_dir, "metadata crypto context complete: calls=" +
                                       std::to_string(
                                               metadata_crypto_context_probe.captured_calls) +
                                       " size=" +
                                       std::to_string(sizeof(metadata_crypto_context_probe)));
    } else {
        write_status(game_data_dir, "metadata crypto context dump failed");
    }
}

void *hooked_metadata_whole_transform(void *buffer, uint32_t length) {
    auto original = original_metadata_whole_transform;
    if (!original) {
        return nullptr;
    }

    const auto call = metadata_whole_probe_calls.fetch_add(1);
    const auto sample_size = length < 0x1000 ? length : 0x1000;
    std::array<uint8_t, 0x1000> before{};
    if (call < 8 && buffer && sample_size > 0) {
        read_self_memory(reinterpret_cast<uintptr_t>(buffer), before.data(), sample_size);
    }

    auto result = original(buffer, length);
    if (call >= 8 || !buffer || sample_size == 0 || metadata_dump_dir.empty()) {
        return result;
    }

    struct WholeProbeRecord {
        uint32_t magic;
        uint32_t call;
        uintptr_t buffer;
        uint32_t length;
        uint32_t sample_size;
        uintptr_t result;
        uint8_t before[0x1000];
        uint8_t after[0x1000];
    } record{};
    record.magic = 0x57374347; // G7CW
    record.call = call;
    record.buffer = reinterpret_cast<uintptr_t>(buffer);
    record.length = length;
    record.sample_size = sample_size;
    record.result = reinterpret_cast<uintptr_t>(result);
    memcpy(record.before, before.data(), sample_size);
    read_self_memory(reinterpret_cast<uintptr_t>(buffer), record.after, sample_size);

    const auto path = metadata_dump_dir + "/files/metadata-whole-probe70.bin";
    int fd = open(path.c_str(), O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, 0600);
    if (fd != -1) {
        (void)write(fd, &record, sizeof(record));
        close(fd);
    }
    write_status(metadata_dump_dir.c_str(), "metadata whole-transform call=" +
                                             std::to_string(call + 1) + "/8 length=" +
                                             std::to_string(length));
    return result;
}

bool install_metadata_whole_probe(const char *game_data_dir) {
    if (metadata_whole_probe_installed.load()) {
        return true;
    }
    auto target = reinterpret_cast<void *>(genshin_module_base + 0x074B9A68);
    metadata_whole_probe_calls.store(0);
    unlink((metadata_dump_dir + "/files/metadata-whole-probe70.bin").c_str());
    void *trampoline = nullptr;
    if (!install_inline_hook(target, reinterpret_cast<void *>(hooked_metadata_whole_transform),
                             &trampoline)) {
        write_status(game_data_dir,
                     "metadata whole-transform probe hook install failed at RVA 0x74B9A68");
        return false;
    }
    original_metadata_whole_transform = reinterpret_cast<MetadataWholeTransform>(trampoline);
    metadata_whole_probe_installed.store(true);
    write_status(game_data_dir,
                 "metadata whole-transform probe hook installed at RVA 0x74B9A68");
    return true;
}

void run_metadata_whole_transform_probe(const char *game_data_dir, const void *metadata,
                                        const char *metadata_dir) {
    if (!original_metadata_whole_transform || !metadata) {
        write_status(game_data_dir, "active metadata whole-transform skipped: unavailable");
        return;
    }

    const auto source_path = metadata_source_path(metadata_dir);
    struct stat source_stat{};
    if (stat(source_path.c_str(), &source_stat) != 0 || source_stat.st_size <= 0 ||
        source_stat.st_size > 512LL * 1024 * 1024) {
        write_status(game_data_dir, "active metadata whole-transform skipped: invalid size");
        return;
    }
    const auto metadata_size = static_cast<size_t>(source_stat.st_size);
    auto *copy = static_cast<uint8_t *>(mmap(nullptr, metadata_size, PROT_READ | PROT_WRITE,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (copy == MAP_FAILED) {
        write_status(game_data_dir, "active metadata whole-transform failed: mmap errno=" +
                                       std::to_string(errno));
        return;
    }

    write_status(game_data_dir, "actively invoking metadata whole-transform on copy; size=" +
                                   std::to_string(metadata_size));
    memcpy(copy, metadata, metadata_size);
    auto *result = hooked_metadata_whole_transform(copy,
                                                    static_cast<uint32_t>(metadata_size));
    const auto *output = result ? static_cast<const uint8_t *>(result) : copy;
    char magic[32]{};
    snprintf(magic, sizeof(magic), "%02X %02X %02X %02X", output[0], output[1], output[2],
             output[3]);
    const auto output_path = std::string(game_data_dir) +
                             "/files/global-metadata-whole-transform70.dat";
    if (write_blob_file(output_path, output, metadata_size)) {
        write_status(game_data_dir, "metadata whole-transform complete: " + output_path +
                                       " (" + std::to_string(metadata_size) +
                                       " bytes, magic=" + magic + ")");
    } else {
        write_status(game_data_dir, "metadata whole-transform output write failed");
    }
    munmap(copy, metadata_size);
}

bool install_metadata_crypto_probe(const char *game_data_dir) {
    if (metadata_crypto_probe_installed.load()) {
        return true;
    }
    auto target = reinterpret_cast<void *>(genshin_module_base + 0x074B6404);
    metadata_crypto_probe_calls.store(0);
    unlink((metadata_dump_dir + "/files/metadata-crypto-probe70.bin").c_str());
    void *trampoline = nullptr;
    if (!install_inline_hook(target, reinterpret_cast<void *>(hooked_metadata_crypto),
                             &trampoline)) {
        write_status(game_data_dir, "metadata crypto probe hook install failed at RVA 0x74B6404");
        return false;
    }
    original_metadata_crypto = reinterpret_cast<MetadataCrypto>(trampoline);
    metadata_crypto_probe_installed.store(true);
    write_status(game_data_dir, "metadata crypto probe hook installed at RVA 0x74B6404");
    return true;
}

void capture_metadata_runtime_state(const char *game_data_dir, const char *phase) {
    if (!genshin_module_base || !original_metadata_loader) {
        write_status(game_data_dir, "runtime state capture skipped: module base unavailable");
        return;
    }

    const auto state_name = std::string("metadata-runtime-state-") + phase + "70.bin";
    const auto keys_name = std::string("metadata-runtime-keys-") + phase + "70.bin";
    dump_runtime_blob(game_data_dir, state_name.c_str(),
                      genshin_module_base + 0x15260000, 0x3000);
    dump_runtime_blob(game_data_dir, keys_name.c_str(),
                      genshin_module_base + 0x14A4B000, 0x3000);
    write_status(game_data_dir, std::string("runtime state pair captured: ") + phase);
}

struct RuntimeHeapRegion {
    uintptr_t begin;
    size_t size;
};

struct RuntimeReadableRegion {
    uintptr_t begin;
    uintptr_t end;
    bool writable;
    bool executable;
};

struct RuntimeClassCandidate {
    std::string name;
    uintptr_t address;
    uintptr_t name_address;
};

std::vector<RuntimeHeapRegion> collect_runtime_heap_regions();

#pragma pack(push, 1)
struct RuntimeClassDumpHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t candidate_count;
    uint32_t class_snapshot_size;
    uint32_t pointer_snapshot_size;
    uint32_t reserved;
    uintptr_t module_base;
};

struct RuntimeClassDumpRecord {
    uint32_t magic;
    uint32_t record_size;
    char name[48];
    uintptr_t class_address;
    uintptr_t name_address;
    uint32_t class_data_size;
    uint32_t pointer_count;
};

struct RuntimePointerDumpRecord {
    uint32_t magic;
    uint32_t source_offset;
    uintptr_t source_address;
    uintptr_t target_address;
    uint32_t data_size;
    uint8_t depth;
    uint8_t writable;
    uint8_t executable;
    uint8_t reserved;
};

struct RuntimeMethodDumpHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t record_count;
    uint32_t record_size;
    uintptr_t module_base;
    uint64_t scanned_bytes;
};

struct RuntimeMethodDumpRecord {
    uintptr_t record_address;
    uintptr_t class_address;
    uintptr_t code_address;
    uintptr_t invoker_address;
    uint32_t token;
    uint32_t reserved;
    uint64_t flags;
    uint64_t auxiliary;
    char class_name[96];
};
#pragma pack(pop)

std::vector<RuntimeReadableRegion> collect_runtime_readable_regions() {
    std::vector<RuntimeReadableRegion> regions;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        return regions;
    }

    char line[2048]{};
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long begin_value = 0;
        unsigned long long end_value = 0;
        char permissions[5]{};
        if (sscanf(line, "%llx-%llx %4s", &begin_value, &end_value, permissions) < 3 ||
            permissions[0] != 'r' || end_value <= begin_value) {
            continue;
        }
        regions.push_back({static_cast<uintptr_t>(begin_value),
                           static_cast<uintptr_t>(end_value), permissions[1] == 'w',
                           permissions[2] == 'x'});
    }
    fclose(maps);
    return regions;
}

const RuntimeReadableRegion *find_runtime_region(
        const std::vector<RuntimeReadableRegion> &regions, uintptr_t address) {
    const auto iterator = std::upper_bound(
            regions.begin(), regions.end(), address,
            [](uintptr_t value, const RuntimeReadableRegion &region) {
                return value < region.begin;
            });
    if (iterator == regions.begin()) {
        return nullptr;
    }
    const auto &region = *(iterator - 1);
    return address >= region.begin && address < region.end ? &region : nullptr;
}

bool is_focus_runtime_class(const std::string &name) {
    return name == "Miscs" || name == "VCHumanoidMove" ||
           name == "ActorAbilityPlugin" || name == "EntityActor" ||
           name == "SafeFloat";
}

bool resolve_runtime_class_name(uintptr_t class_key, std::string &name) {
    if (class_key < 0x28) {
        return false;
    }
    const auto class_address = class_key - 0x28;
    uintptr_t name_address = 0;
    if (!read_self_memory(class_address + 0x40, &name_address, sizeof(name_address)) ||
        !name_address) {
        return false;
    }

    std::array<char, 96> buffer{};
    if (!read_self_memory(name_address, buffer.data(), buffer.size())) {
        return false;
    }
    size_t length = 0;
    while (length < buffer.size() && buffer[length] >= 0x20 && buffer[length] <= 0x7E) {
        ++length;
    }
    if (length < 2 || length == buffer.size() || buffer[length] != '\0') {
        return false;
    }
    name.assign(buffer.data(), length);
    return true;
}

bool is_runtime_class_object(const RuntimeClassCandidate &candidate,
                             const std::vector<RuntimeReadableRegion> &regions) {
    std::array<uint8_t, 0x130> data{};
    if (!read_self_memory(candidate.address, data.data(), data.size())) {
        return false;
    }
    uintptr_t code = 0;
    uintptr_t method_info = 0;
    memcpy(&code, data.data() + 0xF8, sizeof(code));
    memcpy(&method_info, data.data() + 0x100, sizeof(method_info));
    const auto *code_region = find_runtime_region(regions, code);
    if (!code_region || !code_region->executable || !method_info) {
        return false;
    }

    std::array<uint64_t, 7> method{};
    if (!read_self_memory(method_info, method.data(), sizeof(method))) {
        return false;
    }
    return method[0] == candidate.address + 0x28 && method[1] == code &&
           method[4] == 0xFFFFFFFFULL;
}

void dump_all_runtime_methods(const char *game_data_dir,
                              const std::vector<RuntimeClassCandidate> &candidates) {
    constexpr size_t chunk_size = 4 * 1024 * 1024;
    constexpr size_t method_size = 0x38;
    const auto readable_regions = collect_runtime_readable_regions();
    const auto heap_regions = collect_runtime_heap_regions();

    std::set<std::pair<uintptr_t, size_t>> selected_ranges;
    for (const auto &candidate : candidates) {
        if (!is_runtime_class_object(candidate, readable_regions)) {
            continue;
        }
        for (const auto &region : heap_regions) {
            if (candidate.address >= region.begin &&
                candidate.address < region.begin + region.size) {
                selected_ranges.emplace(region.begin, region.size);
                write_status(game_data_dir, "runtime method scan seed: class=" +
                                                candidate.name + " address=" +
                                                pointer_string(reinterpret_cast<void *>(
                                                        candidate.address)) +
                                                " region=" +
                                                pointer_string(reinterpret_cast<void *>(
                                                        region.begin)) +
                                                " size=" +
                                                std::to_string(region.size / (1024 * 1024)) +
                                                " MiB");
                break;
            }
        }
    }
    if (selected_ranges.empty()) {
        write_status(game_data_dir,
                     "runtime method scan failed: no validated class allocation region");
        return;
    }

    uint64_t total_size = 0;
    for (const auto &[begin, size] : selected_ranges) {
        (void)begin;
        total_size += size;
    }
    write_status(game_data_dir, "runtime method scan started: regions=" +
                                    std::to_string(selected_ranges.size()) + " readable=" +
                                    std::to_string(total_size / (1024 * 1024)) + " MiB");

    std::vector<RuntimeMethodDumpRecord> methods;
    std::map<uintptr_t, std::string> class_names;
    std::set<uintptr_t> rejected_classes;
    std::vector<uint8_t> buffer(chunk_size + method_size);
    uint64_t scanned = 0;
    uint64_t next_progress = 16ULL * 1024 * 1024;
    for (const auto &[region_begin, region_size] : selected_ranges) {
        for (size_t offset = 0; offset < region_size; offset += chunk_size) {
            const auto primary = std::min(chunk_size, region_size - offset);
            const auto request = std::min(primary + method_size - 1,
                                          region_size - offset);
            if (!read_self_memory(region_begin + offset, buffer.data(), request)) {
                scanned += primary;
                continue;
            }
            for (size_t index = 0; index + method_size <= request && index < primary;
                 index += sizeof(uintptr_t)) {
                uint64_t fields[7]{};
                memcpy(fields, buffer.data() + index, sizeof(fields));
                const auto *code_region = find_runtime_region(readable_regions, fields[1]);
                const auto *invoker_region = find_runtime_region(readable_regions, fields[2]);
                if (!code_region || !code_region->executable || !invoker_region ||
                    !invoker_region->executable || fields[3] == 0 ||
                    fields[3] > 0xFFFFFF || fields[4] != 0xFFFFFFFFULL ||
                    (fields[0] & 7) != 0) {
                    continue;
                }

                auto class_iterator = class_names.find(fields[0]);
                if (class_iterator == class_names.end()) {
                    if (rejected_classes.count(fields[0]) != 0) {
                        continue;
                    }
                    std::string class_name;
                    if (!resolve_runtime_class_name(fields[0], class_name)) {
                        rejected_classes.insert(fields[0]);
                        continue;
                    }
                    class_iterator = class_names.emplace(fields[0], std::move(class_name)).first;
                }

                RuntimeMethodDumpRecord record{};
                record.record_address = region_begin + offset + index;
                record.class_address = fields[0] - 0x28;
                record.code_address = fields[1];
                record.invoker_address = fields[2];
                record.token = static_cast<uint32_t>(fields[3]);
                record.flags = fields[5];
                record.auxiliary = fields[6];
                strncpy(record.class_name, class_iterator->second.c_str(),
                        sizeof(record.class_name) - 1);
                methods.push_back(record);
            }
            scanned += primary;
            if (scanned >= next_progress) {
                write_status(game_data_dir, "runtime method scan progress: " +
                                                std::to_string(scanned / (1024 * 1024)) +
                                                "/" +
                                                std::to_string(total_size / (1024 * 1024)) +
                                                " MiB methods=" +
                                                std::to_string(methods.size()) +
                                                " classes=" +
                                                std::to_string(class_names.size()));
                next_progress += 16ULL * 1024 * 1024;
            }
        }
    }

    std::sort(methods.begin(), methods.end(), [](const auto &left, const auto &right) {
        return left.record_address < right.record_address;
    });
    methods.erase(std::unique(methods.begin(), methods.end(),
                              [](const auto &left, const auto &right) {
                                  return left.record_address == right.record_address;
                              }),
                  methods.end());

    const auto binary_path = std::string(game_data_dir) +
                             "/files/runtime-all-methods70.bin";
    RuntimeMethodDumpHeader header{0x4D374147, 1,
                                   static_cast<uint32_t>(methods.size()),
                                   static_cast<uint32_t>(sizeof(RuntimeMethodDumpRecord)),
                                   genshin_module_base, scanned}; // GA7M
    std::ofstream binary(binary_path, std::ios::binary | std::ios::trunc);
    if (!binary) {
        write_status(game_data_dir,
                     "runtime method scan failed: cannot create binary output");
        return;
    }
    binary.write(reinterpret_cast<const char *>(&header), sizeof(header));
    if (!methods.empty()) {
        binary.write(reinterpret_cast<const char *>(methods.data()),
                     methods.size() * sizeof(RuntimeMethodDumpRecord));
    }
    binary.flush();

    const auto csv_path = std::string(game_data_dir) +
                          "/files/runtime-all-methods70.csv";
    std::ofstream csv(csv_path, std::ios::trunc);
    if (csv) {
        csv << "record_address,class_address,class_name,token,code_rva,invoker_rva,flags,auxiliary\n";
        for (const auto &method : methods) {
            csv << "0x" << std::hex << method.record_address << ",0x"
                << method.class_address << ',' << method.class_name << ",0x"
                << method.token << ",0x" << method.code_address - genshin_module_base
                << ",0x" << method.invoker_address - genshin_module_base << ",0x"
                << method.flags << ",0x" << method.auxiliary << std::dec << '\n';
        }
        csv.flush();
    }
    write_status(game_data_dir, "runtime method scan complete: methods=" +
                                    std::to_string(methods.size()) + " classes=" +
                                    std::to_string(class_names.size()) + " binary=" +
                                    binary_path + " csv=" + csv_path);
}

void dump_runtime_class_records(const char *game_data_dir,
                                std::vector<RuntimeClassCandidate> candidates) {
    constexpr size_t class_snapshot_size = 0x400;
    constexpr size_t pointer_snapshot_size = 0x800;
    constexpr size_t maximum_pointer_snapshots = 512;

    std::sort(candidates.begin(), candidates.end(),
              [](const auto &left, const auto &right) {
                  if (left.name != right.name) {
                      return left.name < right.name;
                  }
                  return left.address < right.address;
              });
    candidates.erase(std::unique(candidates.begin(), candidates.end(),
                                 [](const auto &left, const auto &right) {
                                     return left.name == right.name &&
                                            left.address == right.address;
                                 }),
                     candidates.end());

    const auto regions = collect_runtime_readable_regions();
    const auto binary_path = std::string(game_data_dir) +
                             "/files/runtime-class-records70.bin";
    const auto index_path = std::string(game_data_dir) +
                            "/files/runtime-class-records70.txt";
    std::ofstream binary(binary_path, std::ios::binary | std::ios::trunc);
    std::ofstream index(index_path, std::ios::trunc);
    if (!binary || !index) {
        write_status(game_data_dir,
                     "runtime class probe failed: cannot create output files");
        return;
    }

    RuntimeClassDumpHeader header{0x52433747, 1, 0,
                                  static_cast<uint32_t>(class_snapshot_size),
                                  static_cast<uint32_t>(pointer_snapshot_size), 0,
                                  genshin_module_base}; // G7CR
    binary.write(reinterpret_cast<const char *>(&header), sizeof(header));
    index << "runtime class/method-table probe 7.0\n";
    index << "module_base=0x" << std::hex << genshin_module_base << std::dec << '\n';

    uint32_t written_candidates = 0;
    for (const auto &candidate : candidates) {
        std::array<uint8_t, class_snapshot_size> class_data{};
        const auto *class_region = find_runtime_region(regions, candidate.address);
        if (!class_region || class_region->end - candidate.address < class_data.size() ||
            !read_self_memory(candidate.address, class_data.data(), class_data.size())) {
            continue;
        }

        struct PointerSnapshot {
            RuntimePointerDumpRecord record;
            std::vector<uint8_t> data;
        };
        std::vector<PointerSnapshot> pointers;
        std::set<uintptr_t> captured_targets;
        const auto capture_pointer = [&](uint8_t depth, uintptr_t source_address,
                                         uint32_t source_offset, uintptr_t target,
                                         size_t maximum_size) {
            if (pointers.size() >= maximum_pointer_snapshots) {
                return;
            }
            const auto *target_region = find_runtime_region(regions, target);
            if (!target_region || target_region->end - target < 0x20 ||
                !captured_targets.insert(target).second) {
                return;
            }
            const auto data_size = static_cast<size_t>(std::min<uintptr_t>(
                    maximum_size, target_region->end - target));
            PointerSnapshot snapshot{};
            snapshot.record = {0x50523747, source_offset, source_address, target,
                               static_cast<uint32_t>(data_size), depth,
                               static_cast<uint8_t>(target_region->writable),
                               static_cast<uint8_t>(target_region->executable), 0}; // G7RP
            snapshot.data.resize(data_size);
            if (!read_self_memory(target, snapshot.data.data(), snapshot.data.size())) {
                captured_targets.erase(target);
                return;
            }
            pointers.push_back(std::move(snapshot));
        };

        for (size_t offset = 0;
             offset + sizeof(uintptr_t) <= class_data.size() &&
             pointers.size() < maximum_pointer_snapshots;
             offset += sizeof(uintptr_t)) {
            uintptr_t target = 0;
            memcpy(&target, class_data.data() + offset, sizeof(target));
            capture_pointer(1, candidate.address + offset,
                            static_cast<uint32_t>(offset), target,
                            pointer_snapshot_size);
        }

        struct NestedPointer {
            uintptr_t source_address;
            uint32_t source_offset;
            uintptr_t target;
        };
        std::vector<NestedPointer> nested_pointers;
        const auto first_level_count = pointers.size();
        for (size_t pointer_index = 0; pointer_index < first_level_count;
             ++pointer_index) {
            const auto &pointer = pointers[pointer_index];
            for (size_t offset = 0; offset + sizeof(uintptr_t) <= pointer.data.size();
                 offset += sizeof(uintptr_t)) {
                uintptr_t target = 0;
                memcpy(&target, pointer.data.data() + offset, sizeof(target));
                const auto *target_region = find_runtime_region(regions, target);
                if (!target_region || (!target_region->executable && (target & 7) != 0)) {
                    continue;
                }
                nested_pointers.push_back(
                        {pointer.record.target_address + offset,
                         static_cast<uint32_t>(offset), target});
            }
        }
        for (const auto &nested : nested_pointers) {
            if (pointers.size() >= maximum_pointer_snapshots) {
                break;
            }
            capture_pointer(2, nested.source_address, nested.source_offset, nested.target,
                            pointer_snapshot_size);
        }

        const auto second_level_end = pointers.size();
        std::vector<NestedPointer> leaf_pointers;
        for (size_t pointer_index = first_level_count;
             pointer_index < second_level_end; ++pointer_index) {
            const auto &pointer = pointers[pointer_index];
            for (size_t offset = 0; offset + sizeof(uintptr_t) <= pointer.data.size();
                 offset += sizeof(uintptr_t)) {
                uintptr_t target = 0;
                memcpy(&target, pointer.data.data() + offset, sizeof(target));
                const auto *target_region = find_runtime_region(regions, target);
                if (!target_region) {
                    continue;
                }

                bool capture = target_region->executable;
                if (!capture && target_region->end - target >= 4) {
                    std::array<uint8_t, 0x80> string_probe{};
                    const auto probe_size = static_cast<size_t>(std::min<uintptr_t>(
                            string_probe.size(), target_region->end - target));
                    if (read_self_memory(target, string_probe.data(), probe_size)) {
                        size_t length = 0;
                        while (length < probe_size && string_probe[length] >= 0x20 &&
                               string_probe[length] <= 0x7E) {
                            ++length;
                        }
                        capture = length >= 2 && length < probe_size &&
                                  string_probe[length] == 0;
                    }
                }
                if (capture) {
                    leaf_pointers.push_back(
                            {pointer.record.target_address + offset,
                             static_cast<uint32_t>(offset), target});
                }
            }
        }
        for (const auto &leaf : leaf_pointers) {
            if (pointers.size() >= maximum_pointer_snapshots) {
                break;
            }
            capture_pointer(3, leaf.source_address, leaf.source_offset, leaf.target, 0x100);
        }

        RuntimeClassDumpRecord record{};
        record.magic = 0x43433747; // G7CC
        strncpy(record.name, candidate.name.c_str(), sizeof(record.name) - 1);
        record.class_address = candidate.address;
        record.name_address = candidate.name_address;
        record.class_data_size = class_data.size();
        record.pointer_count = pointers.size();
        record.record_size = sizeof(record) + class_data.size();
        for (const auto &pointer : pointers) {
            record.record_size += sizeof(pointer.record) + pointer.data.size();
        }
        binary.write(reinterpret_cast<const char *>(&record), sizeof(record));
        binary.write(reinterpret_cast<const char *>(class_data.data()), class_data.size());
        index << "CLASS name=" << candidate.name << " address=0x" << std::hex
              << candidate.address << " name_address=0x" << candidate.name_address
              << std::dec << " pointers=" << pointers.size() << '\n';
        for (const auto &pointer : pointers) {
            binary.write(reinterpret_cast<const char *>(&pointer.record),
                         sizeof(pointer.record));
            binary.write(reinterpret_cast<const char *>(pointer.data.data()),
                         pointer.data.size());
            index << "  PTR source=+0x" << std::hex << pointer.record.source_offset
                  << " source_address=0x" << pointer.record.source_address
                  << " target=0x" << pointer.record.target_address << std::dec
                  << " size=" << pointer.record.data_size
                  << " depth=" << static_cast<int>(pointer.record.depth)
                  << " writable=" << static_cast<int>(pointer.record.writable)
                  << " executable=" << static_cast<int>(pointer.record.executable) << '\n';
        }
        ++written_candidates;
    }

    header.candidate_count = written_candidates;
    binary.seekp(0);
    binary.write(reinterpret_cast<const char *>(&header), sizeof(header));
    binary.flush();
    index.flush();
    write_status(game_data_dir, "runtime class probe complete: classes=" +
                                    std::to_string(written_candidates) +
                                    " binary=" + binary_path + " index=" + index_path);
}

std::vector<RuntimeHeapRegion> collect_runtime_heap_regions() {
    std::vector<RuntimeHeapRegion> regions;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        return regions;
    }

    char line[2048]{};
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long begin_value = 0;
        unsigned long long end_value = 0;
        char permissions[5]{};
        char pathname[1024]{};
        const int fields = sscanf(line, "%llx-%llx %4s %*s %*s %*s %1023[^\n]",
                                  &begin_value, &end_value, permissions, pathname);
        if (fields < 3 || permissions[0] != 'r' || permissions[1] != 'w' ||
            permissions[3] != 'p' || end_value <= begin_value) {
            continue;
        }

        const char *path = fields >= 4 ? pathname : "";
        while (*path == ' ') {
            ++path;
        }
        if (*path != '\0' && strncmp(path, "[anon:", 6) != 0 &&
            strcmp(path, "[heap]") != 0) {
            continue;
        }

        const auto size = static_cast<size_t>(end_value - begin_value);
        if (size < 0x1000 || size > 256ULL * 1024 * 1024) {
            continue;
        }
        regions.push_back({static_cast<uintptr_t>(begin_value), size});
    }
    fclose(maps);
    return regions;
}

void probe_runtime_target_names(const char *game_data_dir) {
    constexpr const char *targets[] = {
            "Miscs", "VCHumanoidMove", "ActorAbilityPlugin", "LCBaseCombat",
            "BaseEntity", "CheckTargetAttackable", "NotifyLandVelocity",
            "HanlderModifierThinkTimerUp", "GetPos", "GetPropValue", "SafeFloat",
            "Avatar", "EntityActor", "Ability", "Hurt", "Damage", "ChangeHp",
    };
    constexpr size_t chunk_size = 4 * 1024 * 1024;
    constexpr size_t maximum_hits_per_name = 64;
    constexpr size_t maximum_xrefs = 512;

    const auto regions = collect_runtime_heap_regions();
    size_t total_size = 0;
    for (const auto &region : regions) {
        total_size += region.size;
    }
    write_status(game_data_dir, "runtime name probe started: mappings=" +
                                    std::to_string(regions.size()) + " readable=" +
                                    std::to_string(total_size / (1024 * 1024)) + " MiB");

    std::map<std::string, std::vector<uintptr_t>> name_hits;
    std::vector<uint8_t> buffer(chunk_size + 64);
    size_t scanned = 0;
    size_t next_progress = 128ULL * 1024 * 1024;
    for (const auto &region : regions) {
        for (size_t offset = 0; offset < region.size; offset += chunk_size) {
            const auto primary = std::min(chunk_size, region.size - offset);
            const auto request = std::min(primary + 63, region.size - offset);
            if (!read_self_memory(region.begin + offset, buffer.data(), request)) {
                scanned += primary;
                continue;
            }
            for (const char *target : targets) {
                const size_t length = strlen(target);
                auto *cursor = buffer.data();
                auto *end = buffer.data() + request;
                while (cursor + length < end) {
                    auto *hit = static_cast<uint8_t *>(
                            memmem(cursor, static_cast<size_t>(end - cursor), target, length));
                    if (!hit) {
                        break;
                    }
                    const auto local_offset = static_cast<size_t>(hit - buffer.data());
                    if (local_offset < primary && hit[length] == '\0') {
                        auto &hits = name_hits[target];
                        if (hits.size() < maximum_hits_per_name) {
                            hits.push_back(region.begin + offset + local_offset);
                        }
                    }
                    cursor = hit + 1;
                }
            }
            scanned += primary;
            if (scanned >= next_progress) {
                write_status(game_data_dir, "runtime name probe progress: " +
                                                std::to_string(scanned / (1024 * 1024)) + "/" +
                                                std::to_string(total_size / (1024 * 1024)) +
                                                " MiB");
                next_progress += 128ULL * 1024 * 1024;
            }
        }
    }

    std::map<uintptr_t, std::string> targets_by_address;
    size_t total_name_hits = 0;
    for (const auto &[name, hits] : name_hits) {
        total_name_hits += hits.size();
        for (auto hit : hits) {
            targets_by_address.emplace(hit, name);
        }
    }
    write_status(game_data_dir, "runtime name probe strings complete: names=" +
                                    std::to_string(name_hits.size()) + " hits=" +
                                    std::to_string(total_name_hits));

    const auto output_path = std::string(game_data_dir) + "/files/runtime-name-xrefs70.txt";
    std::ofstream output(output_path, std::ios::trunc);
    if (!output) {
        write_status(game_data_dir, "runtime name probe failed: cannot create output");
        return;
    }
    output << "runtime target name/xref probe 7.0\n";
    output << "regions=" << regions.size() << " bytes=" << total_size << '\n';
    for (const auto &[name, hits] : name_hits) {
        output << "NAME " << name << " count=" << hits.size() << '\n';
        for (auto hit : hits) {
            output << "  string=0x" << std::hex << hit << std::dec << '\n';
        }
    }

    size_t xref_count = 0;
    std::vector<RuntimeClassCandidate> class_candidates;
    if (!targets_by_address.empty()) {
        for (const auto &region : regions) {
            for (size_t offset = 0; offset < region.size && xref_count < maximum_xrefs;
                 offset += chunk_size) {
                const auto request = std::min(chunk_size, region.size - offset);
                if (!read_self_memory(region.begin + offset, buffer.data(), request)) {
                    continue;
                }
                for (size_t index = 0; index + sizeof(uintptr_t) <= request;
                     index += sizeof(uintptr_t)) {
                    uintptr_t value = 0;
                    memcpy(&value, buffer.data() + index, sizeof(value));
                    const auto target = targets_by_address.find(value);
                    if (target == targets_by_address.end()) {
                        continue;
                    }

                    const auto xref = region.begin + offset + index;
                    if (is_focus_runtime_class(target->second) && xref >= 0x40) {
                        const auto class_address = xref - 0x40;
                        std::array<uint8_t, 0x100> class_header{};
                        uintptr_t verified_name = 0;
                        if (read_self_memory(class_address, class_header.data(),
                                             class_header.size())) {
                            memcpy(&verified_name, class_header.data() + 0x40,
                                   sizeof(verified_name));
                            uint32_t type_index = 0;
                            uint32_t repeated_type_index = 0;
                            memcpy(&type_index, class_header.data() + 0x78,
                                   sizeof(type_index));
                            memcpy(&repeated_type_index, class_header.data() + 0xA8,
                                   sizeof(repeated_type_index));
                            if (verified_name == value && type_index != 0 &&
                                type_index == repeated_type_index) {
                                class_candidates.push_back(
                                        {target->second, class_address, value});
                            }
                        }
                    }
                    output << "XREF name=" << target->second << " string=0x" << std::hex
                           << value << " at=0x" << xref << std::dec << '\n';
                    std::array<uint8_t, 0x100> context{};
                    const auto context_begin = xref >= 0x40 ? xref - 0x40 : xref;
                    if (read_self_memory(context_begin, context.data(), context.size())) {
                        output << "  context=0x" << std::hex << context_begin << ':';
                        for (auto byte : context) {
                            char encoded[3]{};
                            snprintf(encoded, sizeof(encoded), "%02x", byte);
                            output << encoded;
                        }
                        output << std::dec << '\n';
                    }
                    if (++xref_count == maximum_xrefs) {
                        break;
                    }
                }
            }
            if (xref_count == maximum_xrefs) {
                break;
            }
        }
    }
    output.close();
    write_status(game_data_dir, "runtime name probe complete: xrefs=" +
                                    std::to_string(xref_count) + " output=" + output_path);
    write_status(game_data_dir, "runtime class probe starts: candidates=" +
                                    std::to_string(class_candidates.size()));
    dump_runtime_class_records(game_data_dir, class_candidates);
    dump_all_runtime_methods(game_data_dir, class_candidates);
}

void probe_metadata_buffer_decoder(const char *game_data_dir, const void *metadata) {
    constexpr uintptr_t decoder_rva = 0x074B8990;
    constexpr size_t probe_size = 0x1000;
    std::vector<uint8_t> probe(probe_size);
    if (!read_self_memory(reinterpret_cast<uintptr_t>(metadata), probe.data(), probe.size())) {
        write_status(game_data_dir, "metadata decoder probe failed: cannot copy source header");
        return;
    }

    auto decoder = reinterpret_cast<MetadataBufferDecoder>(genshin_module_base + decoder_rva);
    auto result = decoder(probe.data(), static_cast<uint32_t>(probe.size()));
    char magic[32]{};
    snprintf(magic, sizeof(magic), "%02X %02X %02X %02X", probe[0], probe[1], probe[2],
             probe[3]);
    write_status(game_data_dir, "metadata decoder RVA 0x74B8990 result=" +
                                    std::to_string(result) + " magic=" + magic);
    dump_runtime_blob(game_data_dir, "metadata-header-probe70.bin",
                      reinterpret_cast<uintptr_t>(probe.data()), probe.size());
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
    capture_metadata_runtime_state(game_data_dir, "before");
    auto loader = reinterpret_cast<MetadataLoader>(original_metadata_loader);
    auto *metadata = loader(metadata_dir.c_str());
    if (!metadata) {
        write_status(game_data_dir, "active metadata decrypt failed: loader returned null");
        return false;
    }

    write_status(game_data_dir, "active metadata loader returned: ptr=" +
                                    pointer_string(metadata));
    dump_metadata_crypto_probe(game_data_dir);
    capture_metadata_runtime_state(game_data_dir, "after");
    if (!metadata_dump_started.exchange(true)) {
        const auto dumped = dump_decrypted_metadata(metadata, metadata_dir.c_str());
        if (!dumped) {
            return false;
        }
        for (int remaining = 30; remaining > 0; remaining -= 10) {
            write_status(game_data_dir, "runtime name probe starts in " +
                                            std::to_string(remaining) + " seconds");
            sleep(10);
        }
        probe_runtime_target_names(game_data_dir);
        return true;
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
    genshin_module_base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    original_metadata_loader = target;
    metadata_hook_installed.store(true);
    metadata_hook_installing.store(false);
    write_status(game_data_dir, "7.0 metadata loader resolved without patching: base=" +
                                    pointer_string(info.dli_fbase) + " target=" +
                                    pointer_string(target) + " RVA=0x74B8FAC");
    install_metadata_crypto_probe(game_data_dir);
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
