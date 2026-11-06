#pragma once

#include "dxbc-checksum.h"

namespace dwmShaders {

struct Region {
    DWORD offset, size;
    std::array<Digest, modeCount> hash;
};
struct Edit {
    DWORD offset;
    std::array<Byte, selectableCount> value;
};
struct Plan {
    std::vector<Region> regions;
    std::vector<Edit> edits;
};

struct ShaderSignature {
    DWORD size;
    Digest hash;
    std::array<DWORD, 4> curveOffsets;
};
#include "tray-patch-plan.h"

template<class T>
T read(const Byte* bytes) {
    T value;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

IMAGE_SECTION_HEADER readOnlyData(const std::vector<Byte>& disk) {
    auto invalid = [] { fail(L"Invalid x64 dwmcore.dll image layout", ERROR_BAD_EXE_FORMAT); };
    if (disk.size() < sizeof(IMAGE_DOS_HEADER)) invalid();
    const auto dos = read<IMAGE_DOS_HEADER>(disk.data());
    const size_t ntOffset = static_cast<size_t>(dos.e_lfanew);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || ntOffset > disk.size() ||
        sizeof(IMAGE_NT_HEADERS64) > disk.size() - ntOffset) invalid();
    const auto nt = read<IMAGE_NT_HEADERS64>(disk.data() + ntOffset);
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)) invalid();
    const size_t table = ntOffset + sizeof(IMAGE_NT_HEADERS64);
    if (nt.FileHeader.NumberOfSections > (disk.size() - table) / sizeof(IMAGE_SECTION_HEADER)) invalid();
    IMAGE_SECTION_HEADER data{};
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        const auto section = read<IMAGE_SECTION_HEADER>(disk.data() + table + i * sizeof(IMAGE_SECTION_HEADER));
        if (std::memcmp(section.Name, ".rdata", 7) != 0 || section.Name[7] != 0) continue;
        constexpr DWORD flags = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
        if (data.SizeOfRawData || (section.Characteristics & flags) != IMAGE_SCN_MEM_READ ||
            !section.SizeOfRawData || section.PointerToRawData > disk.size() ||
            section.SizeOfRawData > disk.size() - section.PointerToRawData ||
            section.VirtualAddress > nt.OptionalHeader.SizeOfImage ||
            section.Misc.VirtualSize > nt.OptionalHeader.SizeOfImage - section.VirtualAddress) invalid();
        data = section;
    }
    if (!data.SizeOfRawData || !data.Misc.VirtualSize) invalid();
    return data;
}

bool validChecksum(const Byte* blob, size_t size) {
    const auto checksum = dxbcChecksum(blob, size);
    return std::memcmp(blob + 4, checksum.data(), sizeof(checksum)) == 0;
}

void refreshChecksum(Byte* blob, size_t size) {
    const auto checksum = dxbcChecksum(blob, size);
    std::memcpy(blob + 4, checksum.data(), sizeof(checksum));
}

void patchCurve(Byte* blob, const ShaderSignature& shader, float gamma) {
    constexpr std::array<float, 4> original{2.4f, 0.04045f, 0.055f, 0.94786733f};
    const std::array<float, 4> replacement{gamma, 0.0f, 0.0f, 1.0f};
    for (size_t i = 0; i < original.size(); ++i) {
        const auto offset = shader.curveOffsets[i];
        const float expected[]{original[i], original[i], original[i], 0.0f};
        if (offset > shader.size || sizeof(expected) > shader.size - offset ||
            std::memcmp(blob + offset, expected, sizeof(expected)) != 0)
            fail(L"Unexpected SDR shader constants", ERROR_INVALID_DATA);
        const float curve[]{replacement[i], replacement[i], replacement[i]};
        std::memcpy(blob + offset, curve, sizeof(curve));
    }
    refreshChecksum(blob, shader.size);
}

struct Target {
    DWORD offset;
    size_t signature;
};

// A library contains consecutive LIBF parts with a LIBH table at the end.
// The start and length of a candidate shader must come from its LIBF entry.
std::vector<Target> matchLibrary(const Byte* blob, DWORD size, const Sha256& sha) {
    const DWORD count = read<DWORD>(blob + 28);
    if (count < 2 || count > (size - 32) / sizeof(DWORD)) return {};
    DWORD next = 32 + count * sizeof(DWORD);
    std::vector<Target> matches;
    for (DWORD i = 0; i < count; ++i) {
        const DWORD part = read<DWORD>(blob + 32 + i * sizeof(DWORD));
        if (part != next || size - part < 8) return {};
        const DWORD length = read<DWORD>(blob + part + 4);
        const DWORD payload = part + 8;
        if (length > size - payload) return {};
        next = payload + length;
        if (i == count - 1) {
            if (std::memcmp(blob + part, "LIBH", 4) != 0 || next != size) return {};
            break;
        }
        if (std::memcmp(blob + part, "LIBF", 4) != 0) return {};
        for (size_t j = 0; j < ARRAYSIZE(shaders); ++j) {
            const auto& shader = shaders[j];
            if (length == shader.size && sha(blob + payload, length) == shader.hash) {
                matches.push_back({payload, j});
                break;
            }
        }
    }
    return matches;
}

Plan locate(const std::vector<Byte>& disk, const Sha256& sha) {
    const auto section = readOnlyData(disk);
    const auto* data = disk.data() + section.PointerToRawData;
    const DWORD length = (std::min)(section.SizeOfRawData, section.Misc.VirtualSize);
    constexpr float gamma[]{2.2f, 2.4f, 1.0f, 2.6f};
    static_assert(ARRAYSIZE(gamma) == modeCount - 1);
    std::array<bool, ARRAYSIZE(shaders)> seen{};
    Plan plan;
    for (DWORD offset = 0; length - offset >= 32; ++offset) {
        const auto* blob = data + offset;
        if (std::memcmp(blob, "DXBC", 4) != 0 || read<DWORD>(blob + 20) != 1) continue;
        const DWORD size = read<DWORD>(blob + 24);
        if (size < 32 || size > length - offset) continue;
        const auto matches = matchLibrary(blob, size, sha);
        if (matches.empty()) continue;
        if (!validChecksum(blob, size)) fail(L"Invalid DWM shader library checksum", ERROR_INVALID_DATA);
        for (const auto& target : matches) {
            if (seen[target.signature]) fail(L"Ambiguous DWM SDR shader matches", ERROR_INVALID_DATA);
            seen[target.signature] = true;
        }
        const DWORD rva = section.VirtualAddress + offset;
        Region region{rva, size, {}};
        region.hash[0] = sha(blob, size);
        std::array<std::vector<Byte>, selectableCount - 1> variants;
        for (size_t i = 0; i < ARRAYSIZE(gamma); ++i) {
            std::vector<Byte> patched(blob, blob + size);
            for (const auto& target : matches)
                patchCurve(patched.data() + target.offset, shaders[target.signature], gamma[i]);
            refreshChecksum(patched.data(), size);
            region.hash[i + 1] = sha(patched);
            if (i < variants.size()) variants[i] = std::move(patched);
        }
        plan.regions.push_back(region);
        for (DWORD i = 0; i < size; ++i) {
            Edit edit{rva + i, {blob[i], variants[0][i], variants[1][i], variants[2][i]}};
            if (edit.value[0] != edit.value[1] || edit.value[0] != edit.value[2] || edit.value[0] != edit.value[3])
                plan.edits.push_back(edit);
        }
        offset += size - 1;
    }
    if (std::find(seen.begin(), seen.end(), false) != seen.end())
        fail(L"Could not find all six verified SDR shaders in dwmcore.dll", ERROR_REVISION_MISMATCH);
    return plan;
}

} // namespace dwmShaders
