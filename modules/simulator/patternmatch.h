#pragma once
#include <vector>
#include <string>

enum class matching_type : int8_t {
	kmp,
	binary,
	hyper_sphere,
	primitive_root,
	binary_secure_masking,
	hyper_sphere_secure_masking,
	primitive_root_secure_masking,
};

class PatternMatching {
public:
	PatternMatching(
		const fhe::sec_level_t sec_level, const uint64_t poly_modulus_degree, const uint64_t plain_modulus_bit_size, const std::vector<int32_t> coeff_modulus_bit_sizes);

	std::tuple< std::map<std::string, uint64_t>, std::vector<int64_t>, std::map<std::string, double_t>> matching(
		const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, const matching_type type, const bool use_security_mask);

private:
	void hash_sha256(
		const std::string& input, std::string& output);

	void data_preprocessing_common(
		const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, std::set<int64_t>& char_set);

	void data_preprocessing_for_binary(
		const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, std::vector<int64_t>& new_text, std::vector<int64_t>& new_pattern);

	void data_preprocessing_for_hyper_sphere(
		const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, std::vector<std::vector<int64_t>>& new_text, std::vector<std::vector<int64_t>>& new_pattern, uint64_t& point_dimension, uint64_t& radius_square);

	void data_preprocessing_for_primitive_root(
		const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, std::vector<int64_t>& new_text, std::vector<int64_t>& new_pattern);

	void kmp(
		std::vector<int64_t> text, std::vector<int64_t> pattern, std::map<std::string, uint64_t>& matching_info, std::vector<int64_t>& matched, std::map<std::string, double_t>& times);

	void binary(
		std::vector<int64_t> text, std::vector<int64_t> pattern, std::map<std::string, uint64_t>& matching_info, std::vector<int64_t>& matched, std::map<std::string, double_t>& times);

	void hyper_sphere(
		std::vector<int64_t> text, std::vector<int64_t> pattern, std::map<std::string, uint64_t>& matching_info, std::vector<int64_t>& matched, std::map<std::string, double_t>& times);

	void primitive_root(
		std::vector<int64_t> text, std::vector<int64_t> pattern, std::map<std::string, uint64_t>& matching_info, std::vector<int64_t>& matched, std::map<std::string, double_t>& times);

	fhe::sec_level_t sec_level_;

	uint64_t poly_modulus_degree_;

	uint64_t plain_modulus_bit_size_;

	std::vector<int32_t> coeff_modulus_bit_sizes_;
};