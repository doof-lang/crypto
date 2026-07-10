#include "doof_crypto.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdlib.h>
#include <string>
#include <utility>
#include <vector>

namespace doof_crypto {

namespace {

constexpr std::size_t kSha1BlockSize = 64u;
constexpr std::size_t kSha256BlockSize = 64u;
constexpr char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kBase64UrlAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr std::array<uint32_t, 64> kSha256Table = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

constexpr std::array<uint32_t, 8> kSha256InitialState = {
    0x6a09e667u,
    0xbb67ae85u,
    0x3c6ef372u,
    0xa54ff53au,
    0x510e527fu,
    0x9b05688cu,
    0x1f83d9abu,
    0x5be0cd19u,
};

constexpr std::array<uint32_t, 5> kSha1InitialState = {
    0x67452301u,
    0xefcdab89u,
    0x98badcfeu,
    0x10325476u,
    0xc3d2e1f0u,
};

uint32_t rotate_left(uint32_t value, uint32_t amount) {
    return (value << amount) | (value >> (32u - amount));
}

uint32_t rotate_right(uint32_t value, uint32_t amount) {
    return (value >> amount) | (value << (32u - amount));
}

uint32_t choose(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t big_sigma0(uint32_t x) {
    return rotate_right(x, 2u) ^ rotate_right(x, 13u) ^ rotate_right(x, 22u);
}

uint32_t big_sigma1(uint32_t x) {
    return rotate_right(x, 6u) ^ rotate_right(x, 11u) ^ rotate_right(x, 25u);
}

uint32_t small_sigma0(uint32_t x) {
    return rotate_right(x, 7u) ^ rotate_right(x, 18u) ^ (x >> 3u);
}

uint32_t small_sigma1(uint32_t x) {
    return rotate_right(x, 17u) ^ rotate_right(x, 19u) ^ (x >> 10u);
}

int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

int base64_value(char ch, bool url_safe) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return 26 + (ch - 'a');
    }
    if (ch >= '0' && ch <= '9') {
        return 52 + (ch - '0');
    }
    if (url_safe) {
        if (ch == '-') {
            return 62;
        }
        if (ch == '_') {
            return 63;
        }
    } else {
        if (ch == '+') {
            return 62;
        }
        if (ch == '/') {
            return 63;
        }
    }
    return -1;
}

[[noreturn]] void panic_argument(const std::string& message) {
    doof::panic("crypto " + message);
}

std::shared_ptr<std::vector<uint8_t>> bytes_from_string(const std::string& text) {
    return std::make_shared<std::vector<uint8_t>>(text.begin(), text.end());
}

void secure_zero(std::vector<uint8_t>& data) {
    volatile uint8_t* cursor = data.data();
    for (std::size_t index = 0; index < data.size(); ++index) {
        cursor[index] = 0u;
    }
}

void consume_sha1_block(std::array<uint32_t, 5>& state, const uint8_t* block) {
    std::array<uint32_t, 80> schedule {};

    for (std::size_t word = 0; word < 16u; ++word) {
        const std::size_t index = word * 4u;
        schedule[word] =
            (static_cast<uint32_t>(block[index]) << 24u) |
            (static_cast<uint32_t>(block[index + 1u]) << 16u) |
            (static_cast<uint32_t>(block[index + 2u]) << 8u) |
            static_cast<uint32_t>(block[index + 3u]);
    }

    for (std::size_t word = 16u; word < 80u; ++word) {
        schedule[word] = rotate_left(
            schedule[word - 3u] ^ schedule[word - 8u] ^ schedule[word - 14u] ^ schedule[word - 16u],
            1u
        );
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];

    for (std::size_t round = 0; round < 80u; ++round) {
        uint32_t f = 0u;
        uint32_t k = 0u;

        if (round < 20u) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999u;
        } else if (round < 40u) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (round < 60u) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }

        const uint32_t temp = rotate_left(a, 5u) + f + e + k + schedule[round];
        e = d;
        d = c;
        c = rotate_left(b, 30u);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void consume_block(std::array<uint32_t, 8>& state, const uint8_t* block) {
    std::array<uint32_t, 64> schedule {};

    for (std::size_t word = 0; word < 16u; ++word) {
        const std::size_t index = word * 4u;
        schedule[word] =
            (static_cast<uint32_t>(block[index]) << 24u) |
            (static_cast<uint32_t>(block[index + 1u]) << 16u) |
            (static_cast<uint32_t>(block[index + 2u]) << 8u) |
            static_cast<uint32_t>(block[index + 3u]);
    }

    for (std::size_t word = 16u; word < 64u; ++word) {
        schedule[word] = small_sigma1(schedule[word - 2u]) + schedule[word - 7u] +
            small_sigma0(schedule[word - 15u]) + schedule[word - 16u];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (std::size_t round = 0; round < 64u; ++round) {
        const uint32_t temp1 = h + big_sigma1(e) + choose(e, f, g) + kSha256Table[round] + schedule[round];
        const uint32_t temp2 = big_sigma0(a) + majority(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

std::shared_ptr<std::vector<uint8_t>> digest_from_state(const std::array<uint32_t, 8>& state) {
    auto digest = std::make_shared<std::vector<uint8_t>>();
    digest->reserve(32u);
    for (uint32_t word : state) {
        digest->push_back(static_cast<uint8_t>((word >> 24u) & 0xffu));
        digest->push_back(static_cast<uint8_t>((word >> 16u) & 0xffu));
        digest->push_back(static_cast<uint8_t>((word >> 8u) & 0xffu));
        digest->push_back(static_cast<uint8_t>(word & 0xffu));
    }
    return digest;
}

std::shared_ptr<std::vector<uint8_t>> digest_from_sha1_state(const std::array<uint32_t, 5>& state) {
    auto digest = std::make_shared<std::vector<uint8_t>>();
    digest->reserve(20u);
    for (uint32_t word : state) {
        digest->push_back(static_cast<uint8_t>((word >> 24u) & 0xffu));
        digest->push_back(static_cast<uint8_t>((word >> 16u) & 0xffu));
        digest->push_back(static_cast<uint8_t>((word >> 8u) & 0xffu));
        digest->push_back(static_cast<uint8_t>(word & 0xffu));
    }
    return digest;
}

std::shared_ptr<std::vector<uint8_t>> sha1_digest(const std::shared_ptr<std::vector<uint8_t>>& data) {
    std::array<uint32_t, 5> state = kSha1InitialState;
    std::vector<uint8_t> buffer;
    if (data && !data->empty()) {
        buffer.insert(buffer.end(), data->begin(), data->end());
    }

    const uint64_t total_bytes = static_cast<uint64_t>(buffer.size());
    buffer.push_back(0x80u);
    while ((buffer.size() % kSha1BlockSize) != 56u) {
        buffer.push_back(0u);
    }

    const uint64_t bit_length = total_bytes * 8u;
    for (int shift = 56; shift >= 0; shift -= 8) {
        buffer.push_back(static_cast<uint8_t>((bit_length >> shift) & 0xffu));
    }

    for (std::size_t offset = 0; offset < buffer.size(); offset += kSha1BlockSize) {
        consume_sha1_block(state, buffer.data() + offset);
    }

    return digest_from_sha1_state(state);
}

std::string encode_base64_impl(const std::shared_ptr<std::vector<uint8_t>>& data, const char* alphabet, bool include_padding) {
    if (!data || data->empty()) {
        return "";
    }

    std::string encoded;
    encoded.reserve(((data->size() + 2u) / 3u) * 4u);

    for (std::size_t offset = 0; offset < data->size(); offset += 3u) {
        const std::size_t remaining = data->size() - offset;
        const uint32_t block =
            (static_cast<uint32_t>((*data)[offset]) << 16u) |
            (static_cast<uint32_t>(remaining > 1u ? (*data)[offset + 1u] : 0u) << 8u) |
            static_cast<uint32_t>(remaining > 2u ? (*data)[offset + 2u] : 0u);

        encoded.push_back(alphabet[(block >> 18u) & 0x3fu]);
        encoded.push_back(alphabet[(block >> 12u) & 0x3fu]);

        if (remaining > 1u) {
            encoded.push_back(alphabet[(block >> 6u) & 0x3fu]);
        } else if (include_padding) {
            encoded.push_back('=');
        }

        if (remaining > 2u) {
            encoded.push_back(alphabet[block & 0x3fu]);
        } else if (include_padding) {
            encoded.push_back('=');
        }
    }

    return encoded;
}

doof::Result<std::shared_ptr<std::vector<uint8_t>>, std::string> decode_base64_impl(const std::string& text, bool url_safe) {
    for (std::size_t index = 0; index < text.size(); ++index) {
        const char ch = text[index];
        if (ch == '=') {
            continue;
        }
        if (base64_value(ch, url_safe) < 0) {
            return doof::Failure<std::string>{"Base64 text contains a non-base64 character at position " + std::to_string(index)};
        }
    }

    std::string normalized = text;
    const std::size_t first_padding = normalized.find('=');
    if (first_padding != std::string::npos) {
        for (std::size_t index = first_padding; index < normalized.size(); ++index) {
            if (normalized[index] != '=') {
                return doof::Failure<std::string>{"Base64 padding may only appear at the end"};
            }
        }
        if ((normalized.size() % 4u) != 0u) {
            return doof::Failure<std::string>{"Base64 text has invalid padding"};
        }
    } else {
        const std::size_t remainder = normalized.size() % 4u;
        if (remainder == 1u) {
            return doof::Failure<std::string>{"Base64 text has an invalid length"};
        }
        if (remainder > 0u) {
            normalized.append(4u - remainder, '=');
        }
    }

    auto decoded = std::make_shared<std::vector<uint8_t>>();
    decoded->reserve((normalized.size() / 4u) * 3u);

    for (std::size_t offset = 0; offset < normalized.size(); offset += 4u) {
        const char c0 = normalized[offset];
        const char c1 = normalized[offset + 1u];
        const char c2 = normalized[offset + 2u];
        const char c3 = normalized[offset + 3u];

        if (c0 == '=' || c1 == '=') {
            return doof::Failure<std::string>{"Base64 text has invalid padding"};
        }

        const int v0 = base64_value(c0, url_safe);
        const int v1 = base64_value(c1, url_safe);
        const int v2 = c2 == '=' ? 0 : base64_value(c2, url_safe);
        const int v3 = c3 == '=' ? 0 : base64_value(c3, url_safe);
        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
            return doof::Failure<std::string>{"Base64 text contains a non-base64 character"};
        }

        const int padding = (c2 == '=' ? 1 : 0) + (c3 == '=' ? 1 : 0);
        if (padding == 1 && c3 != '=') {
            return doof::Failure<std::string>{"Base64 text has invalid padding"};
        }
        if (padding == 2 && c2 != '=') {
            return doof::Failure<std::string>{"Base64 text has invalid padding"};
        }
        if (padding > 2) {
            return doof::Failure<std::string>{"Base64 text has invalid padding"};
        }
        if (padding > 0 && offset + 4u != normalized.size()) {
            return doof::Failure<std::string>{"Base64 padding may only appear at the end"};
        }
        if (padding == 1 && (v2 & 0x03) != 0) {
            return doof::Failure<std::string>{"Base64 text has invalid trailing bits"};
        }
        if (padding == 2 && (v1 & 0x0f) != 0) {
            return doof::Failure<std::string>{"Base64 text has invalid trailing bits"};
        }

        const uint32_t block =
            (static_cast<uint32_t>(v0) << 18u) |
            (static_cast<uint32_t>(v1) << 12u) |
            (static_cast<uint32_t>(v2) << 6u) |
            static_cast<uint32_t>(v3);

        decoded->push_back(static_cast<uint8_t>((block >> 16u) & 0xffu));
        if (c2 != '=') {
            decoded->push_back(static_cast<uint8_t>((block >> 8u) & 0xffu));
        }
        if (c3 != '=') {
            decoded->push_back(static_cast<uint8_t>(block & 0xffu));
        }
    }

    return doof::Success<std::shared_ptr<std::vector<uint8_t>>>{decoded};
}

}  // namespace

SecretBytes::SecretBytes(std::vector<uint8_t> data)
    : data_(std::move(data)) {
}

std::shared_ptr<SecretBytes> SecretBytes::random(int32_t length) {
    if (length < 0) {
        panic_argument("secret byte length must not be negative");
    }

    std::vector<uint8_t> bytes(static_cast<std::size_t>(length));
    if (length > 0) {
        ::arc4random_buf(bytes.data(), bytes.size());
    }
    return std::shared_ptr<SecretBytes>(new SecretBytes(std::move(bytes)));
}

std::shared_ptr<SecretBytes> SecretBytes::steal(const std::shared_ptr<std::vector<uint8_t>>& data) {
    std::vector<uint8_t> stolen;
    if (data && !data->empty()) {
        stolen.assign(data->begin(), data->end());
        secure_zero(*data);
    }
    return std::shared_ptr<SecretBytes>(new SecretBytes(std::move(stolen)));
}

SecretBytes::~SecretBytes() {
    wipe();
}

void SecretBytes::wipe() {
    secure_zero(data_);
}

std::shared_ptr<std::vector<uint8_t>> SecretBytes::bytes() {
    return std::make_shared<std::vector<uint8_t>>(data_.begin(), data_.end());
}

int32_t SecretBytes::length() {
    if (data_.size() > static_cast<std::size_t>(std::numeric_limits<int32_t>::max())) {
        panic_argument("secret byte length exceeds int range");
    }
    return static_cast<int32_t>(data_.size());
}

const std::vector<uint8_t>& SecretBytes::unsafe_bytes() const {
    return data_;
}

NativeSha256Hasher::NativeSha256Hasher()
    : state_(kSha256InitialState), total_bytes_(0u), finished_(false) {
    buffer_.reserve(64u);
}

std::shared_ptr<NativeSha256Hasher> NativeSha256Hasher::create() {
    return std::shared_ptr<NativeSha256Hasher>(new NativeSha256Hasher());
}

void NativeSha256Hasher::update(const std::shared_ptr<std::vector<uint8_t>>& data) {
    if (finished_) {
        panic_argument("sha256 hasher cannot accept updates after finish()");
    }
    if (!data || data->empty()) {
        return;
    }
    if (static_cast<uint64_t>(data->size()) > std::numeric_limits<uint64_t>::max() - total_bytes_) {
        panic_argument("sha256 input is too large");
    }

    total_bytes_ += static_cast<uint64_t>(data->size());
    const uint8_t* current = data->data();
    std::size_t remaining = data->size();

    if (!buffer_.empty()) {
        const std::size_t needed = 64u - buffer_.size();
        const std::size_t take = remaining < needed ? remaining : needed;
        buffer_.insert(buffer_.end(), current, current + take);
        current += take;
        remaining -= take;

        if (buffer_.size() == 64u) {
            consume_block(state_, buffer_.data());
            buffer_.clear();
        }
    }

    while (remaining >= 64u) {
        consume_block(state_, current);
        current += 64u;
        remaining -= 64u;
    }

    if (remaining > 0u) {
        buffer_.insert(buffer_.end(), current, current + remaining);
    }
}

std::shared_ptr<std::vector<uint8_t>> NativeSha256Hasher::finish() {
    if (finished_) {
        return digest_;
    }

    buffer_.push_back(0x80u);
    while ((buffer_.size() % 64u) != 56u) {
        buffer_.push_back(0u);
    }

    const uint64_t bit_length = total_bytes_ * 8u;
    for (int shift = 56; shift >= 0; shift -= 8) {
        buffer_.push_back(static_cast<uint8_t>((bit_length >> shift) & 0xffu));
    }

    for (std::size_t offset = 0; offset < buffer_.size(); offset += 64u) {
        consume_block(state_, buffer_.data() + offset);
    }

    digest_ = digest_from_state(state_);
    buffer_.clear();
    finished_ = true;
    return digest_;
}

std::shared_ptr<std::vector<uint8_t>> sha256_bytes(const std::shared_ptr<std::vector<uint8_t>>& data) {
    auto hasher = NativeSha256Hasher::create();
    hasher->update(data);
    return hasher->finish();
}

std::shared_ptr<std::vector<uint8_t>> sha1_bytes(const std::shared_ptr<std::vector<uint8_t>>& data) {
    return sha1_digest(data);
}

std::shared_ptr<std::vector<uint8_t>> sha1_utf8(const std::string& text) {
    return sha1_digest(bytes_from_string(text));
}

std::shared_ptr<std::vector<uint8_t>> sha256_utf8(const std::string& text) {
    auto hasher = NativeSha256Hasher::create();
    hasher->update(bytes_from_string(text));
    return hasher->finish();
}

std::shared_ptr<std::vector<uint8_t>> hmac_sha256(
    const std::shared_ptr<SecretBytes>& key,
    const std::shared_ptr<std::vector<uint8_t>>& data
) {
    const std::vector<uint8_t>* key_bytes = key ? &key->unsafe_bytes() : nullptr;
    std::vector<uint8_t> key_block(kSha256BlockSize, 0u);
    if (key_bytes && !key_bytes->empty()) {
        if (key_bytes->size() > kSha256BlockSize) {
            const auto key_copy = std::make_shared<std::vector<uint8_t>>(key_bytes->begin(), key_bytes->end());
            const auto hashed_key = sha256_bytes(key_copy);
            std::copy(hashed_key->begin(), hashed_key->end(), key_block.begin());
            secure_zero(*key_copy);
        } else {
            std::copy(key_bytes->begin(), key_bytes->end(), key_block.begin());
        }
    }

    auto inner_pad = std::make_shared<std::vector<uint8_t>>(kSha256BlockSize);
    auto outer_pad = std::make_shared<std::vector<uint8_t>>(kSha256BlockSize);
    for (std::size_t index = 0; index < kSha256BlockSize; ++index) {
        (*inner_pad)[index] = static_cast<uint8_t>(key_block[index] ^ 0x36u);
        (*outer_pad)[index] = static_cast<uint8_t>(key_block[index] ^ 0x5cu);
    }

    auto inner = NativeSha256Hasher::create();
    inner->update(inner_pad);
    inner->update(data);
    const auto inner_digest = inner->finish();

    auto outer = NativeSha256Hasher::create();
    outer->update(outer_pad);
    outer->update(inner_digest);
    auto digest = outer->finish();

    secure_zero(key_block);
    secure_zero(*inner_pad);
    secure_zero(*outer_pad);
    return digest;
}

bool timing_safe_equal(
    const std::shared_ptr<std::vector<uint8_t>>& a,
    const std::shared_ptr<std::vector<uint8_t>>& b
) {
    const std::size_t a_size = a ? a->size() : 0u;
    const std::size_t b_size = b ? b->size() : 0u;
    const std::size_t max_size = std::max(a_size, b_size);

    uint8_t diff = static_cast<uint8_t>(a_size ^ b_size);
    for (std::size_t index = 0; index < max_size; ++index) {
        const uint8_t a_byte = index < a_size ? (*a)[index] : 0u;
        const uint8_t b_byte = index < b_size ? (*b)[index] : 0u;
        diff = static_cast<uint8_t>(diff | (a_byte ^ b_byte));
    }

    return diff == 0u;
}

std::string encode_base64(const std::shared_ptr<std::vector<uint8_t>>& data) {
    return encode_base64_impl(data, kBase64Alphabet, true);
}

doof::Result<std::shared_ptr<std::vector<uint8_t>>, std::string> decode_base64(const std::string& text) {
    return decode_base64_impl(text, false);
}

std::string encode_base64_url(const std::shared_ptr<std::vector<uint8_t>>& data) {
    return encode_base64_impl(data, kBase64UrlAlphabet, false);
}

doof::Result<std::shared_ptr<std::vector<uint8_t>>, std::string> decode_base64_url(const std::string& text) {
    return decode_base64_impl(text, true);
}

std::shared_ptr<std::vector<uint8_t>> random_bytes(int32_t length) {
    if (length < 0) {
        panic_argument("random byte length must not be negative");
    }

    auto bytes = std::make_shared<std::vector<uint8_t>>(static_cast<std::size_t>(length));
    if (length > 0) {
        ::arc4random_buf(bytes->data(), bytes->size());
    }
    return bytes;
}

std::string uuid_v4() {
    auto bytes = random_bytes(16);
    (*bytes)[6] = static_cast<uint8_t>(((*bytes)[6] & 0x0fu) | 0x40u);
    (*bytes)[8] = static_cast<uint8_t>(((*bytes)[8] & 0x3fu) | 0x80u);

    const std::string hex = encode_hex(bytes);
    return hex.substr(0u, 8u) + "-" + hex.substr(8u, 4u) + "-" + hex.substr(12u, 4u) + "-" +
        hex.substr(16u, 4u) + "-" + hex.substr(20u, 12u);
}

std::string encode_hex(const std::shared_ptr<std::vector<uint8_t>>& data) {
    static constexpr char kHexDigits[] = "0123456789abcdef";

    if (!data || data->empty()) {
        return "";
    }

    std::string encoded;
    encoded.reserve(data->size() * 2u);
    for (uint8_t value : *data) {
        encoded.push_back(kHexDigits[(value >> 4u) & 0x0fu]);
        encoded.push_back(kHexDigits[value & 0x0fu]);
    }
    return encoded;
}

doof::Result<std::shared_ptr<std::vector<uint8_t>>, std::string> decode_hex(const std::string& text) {
    if ((text.size() % 2u) != 0u) {
        return doof::Failure<std::string>{"Hex text must have an even number of characters"};
    }

    auto decoded = std::make_shared<std::vector<uint8_t>>();
    decoded->reserve(text.size() / 2u);

    for (std::size_t index = 0; index < text.size(); index += 2u) {
        const int high = hex_value(text[index]);
        const int low = hex_value(text[index + 1u]);
        if (high < 0 || low < 0) {
            return doof::Failure<std::string>{"Hex text contains a non-hex character at position " + std::to_string(index)};
        }

        decoded->push_back(static_cast<uint8_t>((high << 4) | low));
    }

    return doof::Success<std::shared_ptr<std::vector<uint8_t>>>{decoded};
}

}  // namespace doof_crypto
