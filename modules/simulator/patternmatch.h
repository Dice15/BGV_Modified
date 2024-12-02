#pragma once
#include <vector>
#include <string>

enum class integer_matching_type : int8_t {
	hash_rotation_in_bgv,
	hash_primitive_root_in_bgv,
	hash_primitive_root_in_ckks
};

class PatternMatch {
public:
	std::pair<double_t, std::vector<int64_t>> integer_matching(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern, const integer_matching_type matching_type);

private:
	std::pair<std::vector<int64_t>, std::vector<int64_t>> convert_integer_data(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern);

	std::string sha256(const std::string& str);

	void integer_hash_rotation(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int64_t>& matched);

	void integer_hash_primitive_root_in_bgv(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int64_t>& matched);

	void integer_hash_primitive_root_in_ckks(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int64_t>& matched);
};