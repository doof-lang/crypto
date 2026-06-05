#pragma once

#include "doof_runtime.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace doof_crypto {

class SecretBytes {
public:
	static std::shared_ptr<SecretBytes> random(int32_t length);
	static std::shared_ptr<SecretBytes> steal(const std::shared_ptr<std::vector<uint8_t>>& data);

	~SecretBytes();

	void wipe();
	std::shared_ptr<std::vector<uint8_t>> bytes();
	int32_t length();

	const std::vector<uint8_t>& unsafe_bytes() const;

private:
	explicit SecretBytes(std::vector<uint8_t> data);

	std::vector<uint8_t> data_;
};

class NativeSha256Hasher {
public:
	static std::shared_ptr<NativeSha256Hasher> create();

	void update(const std::shared_ptr<std::vector<uint8_t>>& data);
	std::shared_ptr<std::vector<uint8_t>> finish();

private:
	NativeSha256Hasher();

	std::array<uint32_t, 8> state_;
	std::vector<uint8_t> buffer_;
	uint64_t total_bytes_;
	bool finished_;
	std::shared_ptr<std::vector<uint8_t>> digest_;
};

template <typename StreamLike>
std::shared_ptr<std::vector<uint8_t>> stream_to_sha256(const std::shared_ptr<StreamLike>& source) {
	auto hasher = NativeSha256Hasher::create();
	while (true) {
		if (!source->next()) {
			return hasher->finish();
		}
		const auto chunk = source->value();
		hasher->update(chunk);
	}
}

template <typename... StreamLikes>
std::shared_ptr<std::vector<uint8_t>> stream_to_sha256(const std::variant<std::shared_ptr<StreamLikes>...>& source) {
	return std::visit(
		[](const auto& concrete) {
			return stream_to_sha256(concrete);
		},
		source
	);
}

std::shared_ptr<std::vector<uint8_t>> sha1_bytes(const std::shared_ptr<std::vector<uint8_t>>& data);
std::shared_ptr<std::vector<uint8_t>> sha1_utf8(const std::string& text);
std::shared_ptr<std::vector<uint8_t>> sha256_bytes(const std::shared_ptr<std::vector<uint8_t>>& data);
std::shared_ptr<std::vector<uint8_t>> sha256_utf8(const std::string& text);
std::shared_ptr<std::vector<uint8_t>> hmac_sha256(
	const std::shared_ptr<SecretBytes>& key,
	const std::shared_ptr<std::vector<uint8_t>>& data
);
bool timing_safe_equal(
	const std::shared_ptr<std::vector<uint8_t>>& a,
	const std::shared_ptr<std::vector<uint8_t>>& b
);
std::string encode_base64(const std::shared_ptr<std::vector<uint8_t>>& data);
doof::Result<std::shared_ptr<std::vector<uint8_t>>, std::string> decode_base64(const std::string& text);
std::string encode_base64_url(const std::shared_ptr<std::vector<uint8_t>>& data);
doof::Result<std::shared_ptr<std::vector<uint8_t>>, std::string> decode_base64_url(const std::string& text);
std::shared_ptr<std::vector<uint8_t>> random_bytes(int32_t length);
std::string uuid_v4();
std::string encode_hex(const std::shared_ptr<std::vector<uint8_t>>& data);
doof::Result<std::shared_ptr<std::vector<uint8_t>>, std::string> decode_hex(const std::string& text);

}  // namespace doof_crypto
