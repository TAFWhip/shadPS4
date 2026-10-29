// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "common/alignment.h"
#include "common/logging/log.h"
#include "core/libraries/libs.h"
#include "libc_internal_mspace.h"

namespace Libraries::LibcInternal {

namespace {

constexpr u64 DefaultAlignment = 16;
constexpr u64 HeaderSize = 0x100;
constexpr s32 ORBIS_LIBC_ENOMEM = 12;
constexpr s32 ORBIS_LIBC_EINVAL = 22;

struct Allocation {
    u64 block_start;
    u64 size;
};

class Mspace {
public:
    Mspace(std::string name_, u64 begin_, u64 end_, void* owned_)
        : name{std::move(name_)}, begin{begin_}, end{end_}, owned{owned_} {
        const u64 first = Common::AlignUp(begin + HeaderSize, DefaultAlignment);
        if (first < end) {
            free_blocks.emplace(first, end - first);
        }
    }

    ~Mspace() {
        if (owned) {
            std::free(owned);
        }
    }

    void* Allocate(u64 size, u64 alignment) {
        std::scoped_lock lk{mutex};
        if (alignment < DefaultAlignment) {
            alignment = DefaultAlignment;
        }
        if ((alignment & (alignment - 1)) != 0) {
            return nullptr;
        }
        const u64 requested = size;
        size = Common::AlignUp(std::max<u64>(size, 1), DefaultAlignment);

        for (auto it = free_blocks.begin(); it != free_blocks.end(); ++it) {
            const u64 block_begin = it->first;
            const u64 block_end = it->first + it->second;
            const u64 aligned = Common::AlignUp(block_begin, alignment);
            if (aligned < block_begin || aligned + size > block_end) {
                continue;
            }
            free_blocks.erase(it);
            if (aligned > block_begin) {
                free_blocks.emplace(block_begin, aligned - block_begin);
            }
            if (aligned + size < block_end) {
                free_blocks.emplace(aligned + size, block_end - (aligned + size));
            }
            allocations.emplace(aligned, Allocation{aligned, size});
            in_use += size;
            return reinterpret_cast<void*>(aligned);
        }
        LOG_WARNING(Lib_LibcInternal, "mspace '{}' out of memory (request {:#x}, in use {:#x})",
                    name, requested, in_use);
        return nullptr;
    }

    bool Free(void* ptr) {
        std::scoped_lock lk{mutex};
        const auto it = allocations.find(reinterpret_cast<u64>(ptr));
        if (it == allocations.end()) {
            return false;
        }
        u64 start = it->second.block_start;
        u64 size = it->second.size;
        in_use -= size;
        allocations.erase(it);

        auto next = free_blocks.lower_bound(start);
        if (next != free_blocks.end() && start + size == next->first) {
            size += next->second;
            next = free_blocks.erase(next);
        }
        if (next != free_blocks.begin()) {
            auto prev = std::prev(next);
            if (prev->first + prev->second == start) {
                start = prev->first;
                size += prev->second;
                free_blocks.erase(prev);
            }
        }
        free_blocks.emplace(start, size);
        return true;
    }

    u64 UsableSize(const void* ptr) {
        std::scoped_lock lk{mutex};
        const auto it = allocations.find(reinterpret_cast<u64>(ptr));
        return it == allocations.end() ? 0 : it->second.size;
    }

    bool Contains(const void* ptr) const {
        const u64 addr = reinterpret_cast<u64>(ptr);
        return addr >= begin && addr < end;
    }

    bool IsEmpty() {
        std::scoped_lock lk{mutex};
        return allocations.empty();
    }

    const std::string name;

private:
    std::mutex mutex;
    u64 begin;
    u64 end;
    void* owned;
    u64 in_use = 0;
    std::map<u64, u64> free_blocks;
    std::unordered_map<u64, Allocation> allocations;
};

std::mutex g_mspaces_mutex;
std::unordered_map<u64, std::unique_ptr<Mspace>> g_mspaces;

Mspace* GetMspace(void* handle) {
    std::scoped_lock lk{g_mspaces_mutex};
    const auto it = g_mspaces.find(reinterpret_cast<u64>(handle));
    return it == g_mspaces.end() ? nullptr : it->second.get();
}

Mspace* FindOwner(const void* ptr) {
    std::scoped_lock lk{g_mspaces_mutex};
    for (auto& [handle, mspace] : g_mspaces) {
        if (mspace->Contains(ptr)) {
            return mspace.get();
        }
    }
    return nullptr;
}

} // Anonymous namespace

void* PS4_SYSV_ABI sceLibcMspaceCreate(const char* name, void* base, u64 capacity, u32 flag) {
    const std::string mspace_name = name ? name : "";
    LOG_INFO(Lib_LibcInternal, "called, name = '{}', base = {}, capacity = {:#x}, flag = {:#x}",
             mspace_name, base, capacity, flag);
    if (capacity <= HeaderSize) {
        return nullptr;
    }

    void* owned = nullptr;
    if (base == nullptr) {
        owned = std::malloc(capacity);
        if (owned == nullptr) {
            return nullptr;
        }
        base = owned;
    }

    const u64 begin = reinterpret_cast<u64>(base);
    auto mspace = std::make_unique<Mspace>(mspace_name, begin, begin + capacity, owned);

    std::scoped_lock lk{g_mspaces_mutex};
    g_mspaces[begin] = std::move(mspace);
    return base;
}

s32 PS4_SYSV_ABI sceLibcMspaceDestroy(void* msp) {
    LOG_INFO(Lib_LibcInternal, "called, msp = {}", msp);
    std::scoped_lock lk{g_mspaces_mutex};
    if (g_mspaces.erase(reinterpret_cast<u64>(msp)) == 0) {
        return -1;
    }
    return 0;
}

void* PS4_SYSV_ABI sceLibcMspaceMalloc(void* msp, u64 size) {
    auto* mspace = GetMspace(msp);
    if (!mspace) {
        LOG_ERROR(Lib_LibcInternal, "unknown mspace {}", msp);
        return nullptr;
    }
    return mspace->Allocate(size, DefaultAlignment);
}

void* PS4_SYSV_ABI sceLibcMspaceMemalign(void* msp, u64 boundary, u64 size) {
    auto* mspace = GetMspace(msp);
    if (!mspace) {
        LOG_ERROR(Lib_LibcInternal, "unknown mspace {}", msp);
        return nullptr;
    }
    return mspace->Allocate(size, boundary);
}

void* PS4_SYSV_ABI sceLibcMspaceAlignedAlloc(void* msp, u64 alignment, u64 size) {
    return sceLibcMspaceMemalign(msp, alignment, size);
}

s32 PS4_SYSV_ABI sceLibcMspacePosixMemalign(void* msp, void** ptr, u64 boundary, u64 size) {
    if (!ptr || boundary == 0 || (boundary & (boundary - 1)) != 0 ||
        (boundary % sizeof(void*)) != 0) {
        return ORBIS_LIBC_EINVAL;
    }
    void* result = sceLibcMspaceMemalign(msp, boundary, size);
    if (!result) {
        return ORBIS_LIBC_ENOMEM;
    }
    *ptr = result;
    return 0;
}

void* PS4_SYSV_ABI sceLibcMspaceCalloc(void* msp, u64 count, u64 size) {
    if (size != 0 && count > UINT64_MAX / size) {
        return nullptr;
    }
    void* ptr = sceLibcMspaceMalloc(msp, count * size);
    if (ptr) {
        std::memset(ptr, 0, count * size);
    }
    return ptr;
}

s32 PS4_SYSV_ABI sceLibcMspaceFree(void* msp, void* ptr) {
    if (!ptr) {
        return 0;
    }
    auto* mspace = GetMspace(msp);
    if (!mspace || !mspace->Free(ptr)) {
        auto* owner = FindOwner(ptr);
        if (!owner || !owner->Free(ptr)) {
            LOG_ERROR(Lib_LibcInternal, "invalid free of {} (mspace {})", ptr, msp);
            return -1;
        }
    }
    return 0;
}

void* PS4_SYSV_ABI sceLibcMspaceRealloc(void* msp, void* ptr, u64 size) {
    if (!ptr) {
        return sceLibcMspaceMalloc(msp, size);
    }
    if (size == 0) {
        sceLibcMspaceFree(msp, ptr);
        return nullptr;
    }
    auto* owner = FindOwner(ptr);
    const u64 old_size = owner ? owner->UsableSize(ptr) : 0;
    if (old_size >= size) {
        return ptr;
    }
    void* new_ptr = sceLibcMspaceMalloc(msp, size);
    if (!new_ptr) {
        return nullptr;
    }
    std::memcpy(new_ptr, ptr, std::min(old_size, size));
    sceLibcMspaceFree(msp, ptr);
    return new_ptr;
}

u64 PS4_SYSV_ABI sceLibcMspaceMallocUsableSize(void* ptr) {
    auto* owner = FindOwner(ptr);
    return owner ? owner->UsableSize(ptr) : 0;
}

s32 PS4_SYSV_ABI sceLibcMspaceIsHeapEmpty(void* msp) {
    auto* mspace = GetMspace(msp);
    return mspace && mspace->IsEmpty() ? 1 : 0;
}

void RegisterlibSceLibcInternalMspace(Core::Loader::SymbolsResolver* sym) {
    LIB_FUNCTION("-hn1tcVHq5Q", "libSceLibcInternal", 1, "libSceLibcInternal", sceLibcMspaceCreate);
    LIB_FUNCTION("W6SiVSiCDtI", "libSceLibcInternal", 1, "libSceLibcInternal",
                 sceLibcMspaceDestroy);
    LIB_FUNCTION("OJjm-QOIHlI", "libSceLibcInternal", 1, "libSceLibcInternal", sceLibcMspaceMalloc);
    LIB_FUNCTION("Vla-Z+eXlxo", "libSceLibcInternal", 1, "libSceLibcInternal", sceLibcMspaceFree);
    LIB_FUNCTION("LYo3GhIlB38", "libSceLibcInternal", 1, "libSceLibcInternal", sceLibcMspaceCalloc);
    LIB_FUNCTION("gigoVHZvVPE", "libSceLibcInternal", 1, "libSceLibcInternal",
                 sceLibcMspaceRealloc);
    LIB_FUNCTION("iF1iQHzxBJU", "libSceLibcInternal", 1, "libSceLibcInternal",
                 sceLibcMspaceMemalign);
    LIB_FUNCTION("ljkqMcC4-mk", "libSceLibcInternal", 1, "libSceLibcInternal",
                 sceLibcMspaceAlignedAlloc);
    LIB_FUNCTION("qWESlyXMI3E", "libSceLibcInternal", 1, "libSceLibcInternal",
                 sceLibcMspacePosixMemalign);
    LIB_FUNCTION("fEoW6BJsPt4", "libSceLibcInternal", 1, "libSceLibcInternal",
                 sceLibcMspaceMallocUsableSize);
    LIB_FUNCTION("pzUa7KEoydw", "libSceLibcInternal", 1, "libSceLibcInternal",
                 sceLibcMspaceIsHeapEmpty);
}

} // namespace Libraries::LibcInternal
