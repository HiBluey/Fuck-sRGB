#pragma once

#include <array>
#include <cstdint>
#include <cstring>

using DxbcChecksum = std::array<std::uint32_t, 4>;

// MD5 compression (RFC 1321) with the DXBC retail checksum's final block layout.
inline DxbcChecksum dxbcChecksum(const Byte* data, size_t size) {
    constexpr std::uint32_t constants[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };
    constexpr unsigned rotations[] = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};
    DxbcChecksum state{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    auto compress = [&](const Byte* block) {
        std::uint32_t words[16];
        std::memcpy(words, block, sizeof(words)); // DXBC and the supported x64 target are little-endian.
        auto [a, b, c, d] = state;
        for (unsigned step = 0; step < 64; ++step) {
            std::uint32_t mix;
            unsigned word;
            if (step < 16) {
                mix = (b & c) | (~b & d);
                word = step;
            } else if (step < 32) {
                mix = (d & b) | (~d & c);
                word = (5 * step + 1) % 16;
            } else if (step < 48) {
                mix = b ^ c ^ d;
                word = (3 * step + 5) % 16;
            } else {
                mix = c ^ (b | ~d);
                word = (7 * step) % 16;
            }
            const auto sum = a + mix + constants[step] + words[word];
            const unsigned shift = rotations[(step / 16) * 4 + step % 4];
            a = d;
            d = c;
            c = b;
            b += (sum << shift) | (sum >> (32 - shift));
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    };
    constexpr size_t headerPrefix = 20;
    data += headerPrefix;
    size -= headerPrefix;
    const auto bits = static_cast<std::uint32_t>(size * 8);
    while (size >= 64) {
        compress(data);
        data += 64;
        size -= 64;
    }
    std::array<Byte, 64> tail{};
    if (size >= 56) {
        std::memcpy(tail.data(), data, size);
        tail[size] = 0x80;
        compress(tail.data());
        tail.fill(0);
    } else {
        std::memcpy(tail.data() + 4, data, size);
        tail[size + 4] = 0x80;
    }
    const std::uint32_t endMarker = (bits >> 2) | 1;
    std::memcpy(tail.data(), &bits, sizeof(bits));
    std::memcpy(tail.data() + 60, &endMarker, sizeof(endMarker));
    compress(tail.data());
    return state;
}
