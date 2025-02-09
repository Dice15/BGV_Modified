#include "seal/seal.h"
#include "../fhe/fhebuilder.h"
#include "../fhe/fhe.h"
#include "../random/RandomGenerator.h"
#include "patternmatch.h"
#include <openssl/sha.h>
#include <stdexcept>
#include <unordered_map>
#include <set>
#include <map>
#include <chrono>
#include <cmath>
#include <intrin.h>

PatternMatching::PatternMatching(
    const fhe::sec_level_t sec_level, const uint64_t poly_modulus_degree, const uint64_t plain_modulus_bit_size, const std::vector<int32_t> coeff_modulus_bit_sizes)
    :sec_level_(sec_level), poly_modulus_degree_(poly_modulus_degree), plain_modulus_bit_size_(plain_modulus_bit_size), coeff_modulus_bit_sizes_(coeff_modulus_bit_sizes) {}

std::tuple< std::map<std::string, uint64_t>, std::vector<int64_t>, std::map<std::string, double_t>> PatternMatching::matching(
    const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, const matching_type type, const bool use_security_mask)
{
    std::map<std::string, uint64_t> matching_info;
    std::vector<int64_t> matched;
    std::map<std::string, double_t> times;

    switch (type)
    {
    case matching_type::kmp: {
        kmp(text, pattern, matching_info, matched, times);
        break;
    }
    case matching_type::binary: {
        binary(text, pattern, matching_info, matched, times);
        break;
    }
    case matching_type::hyper_sphere: {
        hyper_sphere(text, pattern, matching_info, matched, times);
        break;
    }
    case matching_type::primitive_root: {
        primitive_root(text, pattern, matching_info, matched, times);
        break;
    }
    default:
        throw std::invalid_argument("Unsupported matching type");
    }

    return { matching_info, matched, times };
}

void PatternMatching::hash_sha256(
    const std::string& input, std::string& output)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;

    for (int32_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int32_t)hash[i];
    }

    output = ss.str();
}

void PatternMatching::data_preprocessing_common(
    const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, std::set<int64_t>& char_set)
{
    for (const int64_t& t : text)
    {
        char_set.insert(t);
    }

    for (const int64_t& p : pattern)
    {
        char_set.insert(p);
    }

    std::set<int64_t> available_char_set_size = { 4, 10, 128, 256 };

    if (available_char_set_size.find(char_set.size()) == available_char_set_size.end())
    {
        throw std::invalid_argument("Unsupported charset size. Supported sizes are 4, 10, 128, and 256.");
    }
}

void PatternMatching::data_preprocessing_for_binary(
    const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, std::vector<int64_t>& new_text, std::vector<int64_t>& new_pattern)
{
    std::set<int64_t> char_set;

    data_preprocessing_common(text, pattern, char_set);

    std::map<int64_t, int64_t> mapping;

    for (const int64_t& e : char_set)
    {
        mapping.insert({ e, mapping.size() });
    }

    size_t bit_size = std::ceil(std::log2(char_set.size()));

    new_text.reserve(text.size() * bit_size);

    for (const int64_t& t : text)
    {
        int64_t v = mapping[t];

        for (size_t bit = static_cast<size_t>(1) << (bit_size - 1); bit > 0; bit >>= 1)
        {
            new_text.push_back((v & bit) ? 1 : -1);
        }
    }

    new_pattern.reserve(pattern.size() * bit_size);

    for (const int64_t& p : pattern)
    {
        int64_t v = mapping[p];

        for (size_t bit = static_cast<size_t>(1) << (bit_size - 1); bit > 0; bit >>= 1)
        {
            new_pattern.push_back((v & bit) ? 1 : -1);
        }
    }
}

void PatternMatching::data_preprocessing_for_hyper_sphere(
    const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, std::vector<std::vector<int64_t>>& new_text, std::vector<std::vector<int64_t>>& new_pattern, uint64_t& point_dimension, uint64_t& radius_square)
{
    std::set<int64_t> char_set;

    data_preprocessing_common(text, pattern, char_set);

    std::map<int64_t, int64_t> mapping;

    for (const int64_t& e : char_set)
    {
        mapping.insert({ e, mapping.size() });
    }

    std::vector<std::vector<int64_t>> points;

    switch (char_set.size())
    {
    case 4:
    {
        point_dimension = 2;
        radius_square = 2;
        points = { {1, 1}, {1, -1}, {-1, 1}, {-1, -1} };
        break;
    }
    case 10:
    {
        point_dimension = 3;
        radius_square = 6;
        points = { {1, 1, 2}, {1, 1, -2}, {1, -1, 2}, {1, -1, -2}, {-1, 1, 2}, {-1, 1, -2}, {-1, -1, 2}, {-1, -1, -2}, {1, 2, 1}, {1, 2, -1} };
        break;
    }
    case 128:
    {
        point_dimension = 4;
        radius_square = 15;
        points = {
            {1, 1, 2, 3}, {1, 1, 2, -3}, {1, 1, -2, 3}, {1, 1, -2, -3}, {1, -1, 2, 3}, {1, -1, 2, -3}, {1, -1, -2, 3}, {1, -1, -2, -3},
            {-1, 1, 2, 3}, {-1, 1, 2, -3}, {-1, 1, -2, 3}, {-1, 1, -2, -3}, {-1, -1, 2, 3}, {-1, -1, 2, -3}, {-1, -1, -2, 3}, {-1, -1, -2, -3},

            {1, 1, 3, 2}, {1, 1, 3, -2}, {1, 1, -3, 2}, {1, 1, -3, -2}, {1, -1, 3, 2}, {1, -1, 3, -2}, {1, -1, -3, 2}, {1, -1, -3, -2},
            {-1, 1, 3, 2}, {-1, 1, 3, -2}, {-1, 1, -3, 2}, {-1, 1, -3, -2}, {-1, -1, 3, 2}, {-1, -1, 3, -2}, {-1, -1, -3, 2}, {-1, -1, -3, -2},

            {1, 2, 1, 3}, {1, 2, 1, -3}, {1, 2, -1, 3}, {1, 2, -1, -3}, {1, -2, 1, 3}, {1, -2, 1, -3}, {1, -2, -1, 3}, {1, -2, -1, -3},
            {-1, 2, 1, 3}, {-1, 2, 1, -3}, {-1, 2, -1, 3}, {-1, 2, -1, -3}, {-1, -2, 1, 3}, {-1, -2, 1, -3}, {-1, -2, -1, 3}, {-1, -2, -1, -3},

            {1, 2, 3, 1}, {1, 2, 3, -1}, {1, 2, -3, 1}, {1, 2, -3, -1}, {1, -2, 3, 1}, {1, -2, 3, -1}, {1, -2, -3, 1}, {1, -2, -3, -1},
            {-1, 2, 3, 1}, {-1, 2, 3, -1}, {-1, 2, -3, 1}, {-1, 2, -3, -1}, {-1, -2, 3, 1}, {-1, -2, 3, -1}, {-1, -2, -3, 1}, {-1, -2, -3, -1},

            {1, 3, 1, 2}, {1, 3, 1, -2}, {1, 3, -1, 2}, {1, 3, -1, -2}, {1, -3, 1, 2}, {1, -3, 1, -2}, {1, -3, -1, 2}, {1, -3, -1, -2},
            {-1, 3, 1, 2}, {-1, 3, 1, -2}, {-1, 3, -1, 2}, {-1, 3, -1, -2}, {-1, -3, 1, 2}, {-1, -3, 1, -2}, {-1, -3, -1, 2}, {-1, -3, -1, -2},

            {1, 3, 2, 1}, {1, 3, 2, -1}, {1, 3, -2, 1}, {1, 3, -2, -1}, {1, -3, 2, 1}, {1, -3, 2, -1}, {1, -3, -2, 1}, {1, -3, -2, -1},
            {-1, 3, 2, 1}, {-1, 3, 2, -1}, {-1, 3, -2, 1}, {-1, 3, -2, -1}, {-1, -3, 2, 1}, {-1, -3, 2, -1}, {-1, -3, -2, 1}, {-1, -3, -2, -1},

            {2, 1, 1, 3}, {2, 1, 1, -3}, {2, 1, -1, 3}, {2, 1, -1, -3}, {2, -1, 1, 3}, {2, -1, 1, -3}, {2, -1, -1, 3}, {2, -1, -1, -3},
            {-2, 1, 1, 3}, {-2, 1, 1, -3}, {-2, 1, -1, 3}, {-2, 1, -1, -3}, {-2, -1, 1, 3}, {-2, -1, 1, -3}, {-2, -1, -1, 3}, {-2, -1, -1, -3},

            {2, 1, 3, 1}, {2, 1, 3, -1}, {2, 1, -3, 1}, {2, 1, -3, -1}, {2, -1, 3, 1}, {2, -1, 3, -1}, {2, -1, -3, 1}, {2, -1, -3, -1},
            {-2, 1, 3, 1}, {-2, 1, 3, -1}, {-2, 1, -3, 1}, {-2, 1, -3, -1}, {-2, -1, 3, 1}, {-2, -1, 3, -1}, {-2, -1, -3, 1}, {-2, -1, -3, -1}
        };
        break;
    }
    case 256:
    {
        point_dimension = 5;
        radius_square = 11;
        points = {
            {1, 1, 1, 2, 2},   {1, 1, 1, 2, -2},  {1, 1, 1, -2, 2},  {1, 1, 1, -2, -2}, {1, 1, -1, 2, 2},  {1, 1, -1, 2, -2}, {1, 1, -1, -2, 2}, {1, 1, -1, -2, -2},
            {1, -1, 1, 2, 2},  {1, -1, 1, 2, -2}, {1, -1, 1, -2, 2}, {1, -1, 1, -2, -2}, {1, -1, -1, 2, 2}, {1, -1, -1, 2, -2}, {1, -1, -1, -2, 2}, {1, -1, -1, -2, -2},

            {-1, 1, 1, 2, 2},  {-1, 1, 1, 2, -2}, {-1, 1, 1, -2, 2}, {-1, 1, 1, -2, -2}, {-1, 1, -1, 2, 2}, {-1, 1, -1, 2, -2}, {-1, 1, -1, -2, 2}, {-1, 1, -1, -2, -2},
            {-1, -1, 1, 2, 2}, {-1, -1, 1, 2, -2}, {-1, -1, 1, -2, 2}, {-1, -1, 1, -2, -2}, {-1, -1, -1, 2, 2},{-1, -1, -1, 2, -2}, {-1, -1, -1, -2, 2}, {-1, -1, -1, -2, -2},

            {1, 1, 2, 1, 2},   {1, 1, 2, 1, -2},  {1, 1, 2, -1, 2},  {1, 1, 2, -1, -2}, {1, 1, -2, 1, 2},  {1, 1, -2, 1, -2}, {1, 1, -2, -1, 2}, {1, 1, -2, -1, -2},
            {1, -1, 2, 1, 2},  {1, -1, 2, 1, -2}, {1, -1, 2, -1, 2}, {1, -1, 2, -1, -2}, {1, -1, -2, 1, 2}, {1, -1, -2, 1, -2}, {1, -1, -2, -1, 2}, {1, -1, -2, -1, -2},

            {-1, 1, 2, 1, 2},  {-1, 1, 2, 1, -2}, {-1, 1, 2, -1, 2}, {-1, 1, 2, -1, -2}, {-1, 1, -2, 1, 2}, {-1, 1, -2, 1, -2}, {-1, 1, -2, -1, 2}, {-1, 1, -2, -1, -2},
            {-1, -1, 2, 1, 2}, {-1, -1, 2, 1, -2}, {-1, -1, 2, -1, 2}, {-1, -1, 2, -1, -2}, {-1, -1, -2, 1, 2}, {-1, -1, -2, 1, -2}, {-1, -1, -2, -1, 2}, {-1, -1, -2, -1, -2},

            {1, 1, 2, 2, 1},   {1, 1, 2, 2, -1},  {1, 1, 2, -2, 1},  {1, 1, 2, -2, -1}, {1, 1, -2, 2, 1},  {1, 1, -2, 2, -1}, {1, 1, -2, -2, 1}, {1, 1, -2, -2, -1},
            {1, -1, 2, 2, 1},  {1, -1, 2, 2, -1}, {1, -1, 2, -2, 1}, {1, -1, 2, -2, -1}, {1, -1, -2, 2, 1}, {1, -1, -2, 2, -1}, {1, -1, -2, -2, 1}, {1, -1, -2, -2, -1},

            {-1, 1, 2, 2, 1},  {-1, 1, 2, 2, -1}, {-1, 1, 2, -2, 1}, {-1, 1, 2, -2, -1}, {-1, 1, -2, 2, 1}, {-1, 1, -2, 2, -1}, {-1, 1, -2, -2, 1}, {-1, 1, -2, -2, -1},
            {-1, -1, 2, 2, 1}, {-1, -1, 2, 2, -1}, {-1, -1, 2, -2, 1}, {-1, -1, 2, -2, -1}, {-1, -1, -2, 2, 1}, {-1, -1, -2, 2, -1}, {-1, -1, -2, -2, 1}, {-1, -1, -2, -2, -1},

            {1, 2, 1, 1, 2},   {1, 2, 1, 1, -2},  {1, 2, 1, -1, 2},  {1, 2, 1, -1, -2}, {1, 2, -1, 1, 2},  {1, 2, -1, 1, -2}, {1, 2, -1, -1, 2}, {1, 2, -1, -1, -2},
            {1, -2, 1, 1, 2},  {1, -2, 1, 1, -2}, {1, -2, 1, -1, 2}, {1, -2, 1, -1, -2}, {1, -2, -1, 1, 2}, {1, -2, -1, 1, -2}, {1, -2, -1, -1, 2}, {1, -2, -1, -1, -2},

            {-1, 2, 1, 1, 2},  {-1, 2, 1, 1, -2}, {-1, 2, 1, -1, 2}, {-1, 2, 1, -1, -2}, {-1, 2, -1, 1, 2}, {-1, 2, -1, 1, -2}, {-1, 2, -1, -1, 2}, {-1, 2, -1, -1, -2},
            {-1, -2, 1, 1, 2}, {-1, -2, 1, 1, -2}, {-1, -2, 1, -1, 2}, {-1, -2, 1, -1, -2}, {-1, -2, -1, 1, 2}, {-1, -2, -1, 1, -2}, {-1, -2, -1, -1, 2}, {-1, -2, -1, -1, -2},

            {1, 2, 1, 2, 1},   {1, 2, 1, 2, -1},  {1, 2, 1, -2, 1},  {1, 2, 1, -2, -1}, {1, 2, -1, 2, 1},  {1, 2, -1, 2, -1}, {1, 2, -1, -2, 1}, {1, 2, -1, -2, -1},
            {1, -2, 1, 2, 1},  {1, -2, 1, 2, -1}, {1, -2, 1, -2, 1}, {1, -2, 1, -2, -1}, {1, -2, -1, 2, 1}, {1, -2, -1, 2, -1}, {1, -2, -1, -2, 1}, {1, -2, -1, -2, -1},

            {-1, 2, 1, 2, 1},  {-1, 2, 1, 2, -1}, {-1, 2, 1, -2, 1}, {-1, 2, 1, -2, -1}, {-1, 2, -1, 2, 1}, {-1, 2, -1, 2, -1}, {-1, 2, -1, -2, 1}, {-1, 2, -1, -2, -1},
            {-1, -2, 1, 2, 1}, {-1, -2, 1, 2, -1}, {-1, -2, 1, -2, 1}, {-1, -2, 1, -2, -1}, {-1, -2, -1, 2, 1}, {-1, -2, -1, 2, -1}, {-1, -2, -1, -2, 1}, {-1, -2, -1, -2, -1},

            {1, 2, 2, 1, 1},   {1, 2, 2, 1, -1},  {1, 2, 2, -1, 1},  {1, 2, 2, -1, -1}, {1, 2, -2, 1, 1},  {1, 2, -2, 1, -1}, {1, 2, -2, -1, 1}, {1, 2, -2, -1, -1},
            {1, -2, 2, 1, 1},  {1, -2, 2, 1, -1}, {1, -2, 2, -1, 1}, {1, -2, 2, -1, -1}, {1, -2, -2, 1, 1}, {1, -2, -2, 1, -1}, {1, -2, -2, -1, 1}, {1, -2, -2, -1, -1},

            {-1, 2, 2, 1, 1},  {-1, 2, 2, 1, -1}, { -1, 2, 2, -1, 1}, {-1, 2, 2, -1, -1}, {-1, 2, -2, 1, 1}, {-1, 2, -2, 1, -1}, {-1, 2, -2, -1, 1}, {-1, 2, -2, -1, -1},
            {-1, -2, 2, 1, 1}, {-1, -2, 2, 1, -1}, {-1, -2, 2, -1, 1}, {-1, -2, 2, -1, -1}, {-1, -2, -2, 1, 1}, {-1, -2, -2, 1, -1}, {-1, -2, -2, -1, 1}, {-1, -2, -2, -1, -1},

            {2, 1, 1, 1, 2},   {2, 1, 1, 1, -2},  {2, 1, 1, -1, 2},  {2, 1, 1, -1, -2}, {2, 1, -1, 1, 2},  {2, 1, -1, 1, -2}, {2, 1, -1, -1, 2}, {2, 1, -1, -1, -2},
            {2, -1, 1, 1, 2},  {2, -1, 1, 1, -2}, {2, -1, 1, -1, 2}, {2, -1, 1, -1, -2}, {2, -1, -1, 1, 2}, {2, -1, -1, 1, -2}, {2, -1, -1, -1, 2}, {2, -1, -1, -1, -2},

            {-2, 1, 1, 1, 2},  {-2, 1, 1, 1, -2}, {-2, 1, 1, -1, 2}, {-2, 1, 1, -1, -2}, {-2, 1, -1, 1, 2}, {-2, 1, -1, 1, -2}, {-2, 1, -1, -1, 2}, {-2, 1, -1, -1, -2},
            {-2, -1, 1, 1, 2}, {-2, -1, 1, 1, -2}, {-2, -1, 1, -1, 2}, {-2, -1, 1, -1, -2}, {-2, -1, -1, 1, 2}, {-2, -1, -1, 1, -2}, {-2, -1, -1, -1, 2}, {-2, -1, -1, -1, -2},

            {2, 1, 1, 2, 1},   {2, 1, 1, 2, -1},  {2, 1, 1, -2, 1},  {2, 1, 1, -2, -1}, {2, 1, -1, 2, 1},  {2, 1, -1, 2, -1}, {2, 1, -1, -2, 1}, {2, 1, -1, -2, -1},
            {2, -1, 1, 2, 1},  {2, -1, 1, 2, -1}, {2, -1, 1, -2, 1}, {2, -1, 1, -2, -1}, {2, -1, -1, 2, 1}, {2, -1, -1, 2, -1}, {2, -1, -1, -2, 1}, {2, -1, -1, -2, -1},

            {-2, 1, 1, 2, 1},  {-2, 1, 1, 2, -1}, {-2, 1, 1, -2, 1}, {-2, 1, 1, -2, -1}, {-2, 1, -1, 2, 1}, {-2, 1, -1, 2, -1}, {-2, 1, -1, -2, 1}, {-2, 1, -1, -2, -1},
            {-2, -1, 1, 2, 1}, {-2, -1, 1, 2, -1}, {-2, -1, 1, -2, 1}, {-2, -1, 1, -2, -1}, {-2, -1, -1, 2, 1}, {-2, -1, -1, 2, -1}, {-2, -1, -1, -2, 1}, {-2, -1, -1, -2, -1}
        };
        break;
    }
    default:
        throw std::invalid_argument("Unsupported charset size. Supported sizes are 4, 10, 128, and 256.");
    }

    new_text.assign(point_dimension, std::vector<int64_t>());
    new_pattern.assign(point_dimension, std::vector<int64_t>());

    for (int64_t d = 0; d < point_dimension; d++)
    {
        new_text[d].reserve(text.size());
        new_pattern[d].reserve(pattern.size());
    }

    for (int64_t i = 0; i < text.size(); i++)
    {
        const auto& point = points[mapping[text[i]]];

        for (int64_t d = 0; d < point_dimension; d++)
        {
            new_text[d].push_back(point[d]);
        }
    }

    for (int64_t i = 0; i < pattern.size(); i++)
    {
        const auto& point = points[mapping[pattern[i]]];

        for (int64_t d = 0; d < point_dimension; d++)
        {
            new_pattern[d].push_back(point[d]);
        }
    }
}

void PatternMatching::data_preprocessing_for_primitive_root(
    const std::vector<int64_t>& text, const std::vector<int64_t>& pattern, std::vector<int64_t>& new_text, std::vector<int64_t>& new_pattern)
{
    std::set<int64_t> char_set;

    data_preprocessing_common(text, pattern, char_set);

    std::map<int64_t, int64_t> mapping;

    for (const int64_t& e : char_set)
    {
        mapping.insert({ e, mapping.size() });
    }

    seal::Modulus plain_modulus = seal::PlainModulus::Batching(poly_modulus_degree_, plain_modulus_bit_size_);

    uint64_t prime = plain_modulus.value();

    uint64_t n = static_cast<uint64_t>(1) << static_cast<uint64_t>(ceil(log2(char_set.size())));

    uint64_t root = 2;

    seal::util::try_primitive_root(n, plain_modulus, root);

    std::vector<uint64_t> root_powers;

    root_powers.reserve(n);

    auto mul_mod_safe = [](uint64_t a, uint64_t b, uint64_t modulus)
    {
        uint64_t high = 0ULL;
        uint64_t low = _umul128(a, b, &high);

        uint64_t remainder = 0ULL;
        _udiv128(high, low, modulus, &remainder);

        return remainder;
    };

    uint64_t power = 1;

    while (root_powers.size() < n)
    {
        root_powers.push_back(power);
        power = mul_mod_safe(power, root, prime);
    }

    new_text.reserve(text.size());

    for (const int64_t& t : text)
    {
        int64_t v = mapping[t];
        new_text.push_back(root_powers[v]);
    }

    new_pattern.reserve(pattern.size());

    for (const int64_t& p : pattern)
    {
        int64_t v = mapping[p];
        new_pattern.push_back(root_powers[(n - v) % n]);
    }
}

void PatternMatching::kmp(
    std::vector<int64_t> text, std::vector<int64_t> pattern, std::map<std::string, uint64_t>& matching_info, std::vector<int64_t>& matched, std::map<std::string, double_t>& times)
{
    // matching type
    matching_info.insert({ "matching type", static_cast<uint64_t>(matching_type::kmp) });


    // timer
    std::chrono::steady_clock::time_point timer_start;
    std::chrono::steady_clock::time_point timer_end;

    matching_info.insert({ "text size", text.size() });
    matching_info.insert({ "pattern size", pattern.size() });


    // preprocessing
    timer_start = std::chrono::steady_clock::now();

    std::vector<int64_t> lps(pattern.size(), 0);
    if (!pattern.empty())
    {
        int64_t len = 0;
        int64_t i = 1;
        while (i < static_cast<int64_t>(pattern.size()))
        {
            if (pattern[i] == pattern[len])
            {
                len++;
                lps[i] = len;
                i++;
            }
            else
            {
                if (len != 0)
                {
                    len = lps[len - 1];
                }
                else
                {
                    lps[i] = 0;
                    i++;
                }
            }
        }
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "preprocessing", static_cast<double_t>(std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count()) });


    // pattern matching
    timer_start = std::chrono::steady_clock::now();

    int64_t i = 0;
    int64_t j = 0;
    while (i < static_cast<int64_t>(text.size()))
    {
        if (pattern[j] == text[i])
        {
            i++;
            j++;
        }
        if (j == static_cast<int64_t>(pattern.size()))
        {
            matched.push_back(i - j);
            j = lps[j - 1];
        }
        else if (i < static_cast<int64_t>(text.size()) && pattern[j] != text[i])
        {
            if (j != 0)
            {
                j = lps[j - 1];
            }
            else
            {
                i++;
            }
        }
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "pattern matching", static_cast<double_t>(std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count()) });


    // total time
    double_t total_time = 0;
    for (const auto& [process, time] : times)
    {
        total_time += time;
    }
    times.insert({ "total time", total_time });
}

void PatternMatching::binary(
    std::vector<int64_t> text, std::vector<int64_t> pattern, std::map<std::string, uint64_t>& matching_info, std::vector<int64_t>& matched, std::map<std::string, double_t>& times)
{
    // matching type
    matching_info.insert({ "matching type", static_cast<uint64_t>(matching_type::binary) });


    // timer
    std::chrono::steady_clock::time_point timer_start;
    std::chrono::steady_clock::time_point timer_end;


    // create bgv
    fhe::FHE& bgv = fhe::FHEBuilder()
        .sec_level(sec_level_)
        .mul_mode(fhe::mul_mode_t::convolution)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_integer_scheme(fhe::int_scheme_t::bgv, poly_modulus_degree_, plain_modulus_bit_size_, coeff_modulus_bit_sizes_);

    matching_info.insert({ "n", poly_modulus_degree_ });
    matching_info.insert({ "q", bgv.total_coeff_modulus_bit() });
    matching_info.insert({ "t", bgv.plain_modulus() });
    matching_info.insert({ "text size", text.size() });
    matching_info.insert({ "pattern size", pattern.size() });


    // preprocessing
    timer_start = std::chrono::steady_clock::now();

    std::vector<int64_t> T;
    std::vector<int64_t> P;

    data_preprocessing_for_binary(text, pattern, T, P);
    std::reverse(P.begin(), P.end());

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "preprocessing", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // encode and encryption
    timer_start = std::chrono::steady_clock::now();

    uint64_t slot_count = bgv.slot_count();

    seal::Plaintext T_plain;
    std::vector<seal::Ciphertext> T_ciphers;

    seal::Plaintext P_plain;
    seal::Ciphertext P_cipher;

    for (int64_t i = 0, j = -1; j < static_cast<int64_t>(T.size()) - 1; i = i + static_cast<int64_t>(slot_count) - static_cast<int64_t>(P.size()) + 1)
    {
        j = std::min(static_cast<int64_t>(T.size()) - 1, i + static_cast<int64_t>(slot_count) - 1);

        std::vector<int64_t> T_small(T.begin() + i, T.begin() + j + 1);

        bgv.encode(T_small, T_plain);

        T_ciphers.push_back(bgv.encrypt(T_plain));
    }

    bgv.encode(P, P_plain);
    bgv.encrypt(P_plain, P_cipher);

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "encode and encryption", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // pattern matching
    timer_start = std::chrono::steady_clock::now();

    std::vector<seal::Ciphertext> R_ciphers;

    for (const auto& T_cipher : T_ciphers)
    {
        R_ciphers.push_back(bgv.multiply(T_cipher, P_cipher));
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "pattern matching", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // decryption and decode
    timer_start = std::chrono::steady_clock::now();

    uint64_t bit_size = P.size() / pattern.size();

    seal::Plaintext R_plain;
    std::vector<int64_t> R;

    R.reserve(R_ciphers.size() * slot_count);

    for (int64_t i = 0, j = 0; j < static_cast<int64_t>(R_ciphers.size()); i = i + static_cast<int64_t>(slot_count) - static_cast<int64_t>(P.size()) + 1, j++)
    {
        std::vector<int64_t> R_small;

        bgv.decrypt(R_ciphers[j], R_plain);

        bgv.decode(R_plain, R_small);

        for (int64_t k = (i == 0 ? 0 : static_cast<int64_t>(P.size()) - 1); k < static_cast<int64_t>(slot_count); k++)
        {
            R.push_back(R_small[k]);
        }
    }

    R.resize(T.size());

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "decryption and decode", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // result interpretation
    timer_start = std::chrono::steady_clock::now();

    for (int64_t i = static_cast<int64_t>(P.size()) - 1; i < R.size(); i += static_cast<int64_t>(bit_size))
    {
        if (R[i] == static_cast<int64_t>(P.size()))
        {
            matched.push_back((i / static_cast<int64_t>(bit_size)) - static_cast<int64_t>(pattern.size()) + 1);
        }
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "result interpretation", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // total time
    double_t total_time = 0;
    for (const auto& [process, time] : times)
    {
        total_time += time;
    }
    times.insert({ "total time", total_time });
}

void PatternMatching::hyper_sphere(
    std::vector<int64_t> text, std::vector<int64_t> pattern, std::map<std::string, uint64_t>& matching_info, std::vector<int64_t>& matched, std::map<std::string, double_t>& times)
{
    // matching type
    matching_info.insert({ "matching type", static_cast<uint64_t>(matching_type::hyper_sphere) });


    // timer
    std::chrono::steady_clock::time_point timer_start;
    std::chrono::steady_clock::time_point timer_end;


    // create bgv
    fhe::FHE& bgv = fhe::FHEBuilder()
        .sec_level(sec_level_)
        .mul_mode(fhe::mul_mode_t::convolution)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_integer_scheme(fhe::int_scheme_t::bgv, poly_modulus_degree_, plain_modulus_bit_size_, coeff_modulus_bit_sizes_);

    matching_info.insert({ "n", poly_modulus_degree_ });
    matching_info.insert({ "q", bgv.total_coeff_modulus_bit() });
    matching_info.insert({ "t", bgv.plain_modulus() });
    matching_info.insert({ "text size", text.size() });
    matching_info.insert({ "pattern size", pattern.size() });


    // preprocessing
    timer_start = std::chrono::steady_clock::now();

    std::vector<std::vector<int64_t>> T_point;
    std::vector<std::vector<int64_t>> P_point;
    uint64_t point_dimension = 0;
    uint64_t radius_square = 0;

    data_preprocessing_for_hyper_sphere(text, pattern, T_point, P_point, point_dimension, radius_square);

    for (size_t d = 0; d < point_dimension; d++)
    {
        std::reverse(P_point[d].begin(), P_point[d].end());
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "preprocessing", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // encode and encryption
    timer_start = std::chrono::steady_clock::now();

    uint64_t slot_count = bgv.slot_count();

    seal::Plaintext T_plain;
    std::vector<std::vector<seal::Ciphertext>> T_point_ciphers(point_dimension, std::vector<seal::Ciphertext>());

    seal::Plaintext P_plain;
    std::vector<seal::Ciphertext> P_point_ciphers(point_dimension, seal::Ciphertext());

    for (size_t d = 0; d < point_dimension; d++)
    {
        for (int64_t i = 0, j = -1; j < static_cast<int64_t>(T_point[d].size()) - 1; i = i + static_cast<int64_t>(slot_count) - static_cast<int64_t>(P_point[d].size()) + 1)
        {
            j = std::min(static_cast<int64_t>(T_point[d].size()) - 1, i + static_cast<int64_t>(slot_count) - 1);

            std::vector<int64_t> T_small(T_point[d].begin() + i, T_point[d].begin() + j + 1);

            bgv.encode(T_small, T_plain);

            T_point_ciphers[d].push_back(bgv.encrypt(T_plain));
        }

        bgv.encode(P_point[d], P_plain);
        bgv.encrypt(P_plain, P_point_ciphers[d]);
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "encode and encryption", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // pattern matching
    timer_start = std::chrono::steady_clock::now();

    std::vector<seal::Ciphertext> R_ciphers;

    for (size_t d = 0; d < point_dimension; d++)
    {
        for (const auto& T_point_cipher : T_point_ciphers[d])
        {
            if (d == 0)
            {
                R_ciphers.push_back(bgv.multiply(T_point_cipher, P_point_ciphers[d]));
            }
            else
            {
                bgv.add(R_ciphers.back(), bgv.multiply(T_point_cipher, P_point_ciphers[d]), R_ciphers.back());
            }
        }
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "pattern matching", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // decryption and decode
    timer_start = std::chrono::steady_clock::now();

    seal::Plaintext R_plain;
    std::vector<int64_t> R;

    R.reserve(R_ciphers.size() * slot_count);

    for (int64_t i = 0, j = 0; j < static_cast<int64_t>(R_ciphers.size()); i = i + static_cast<int64_t>(slot_count) - static_cast<int64_t>(pattern.size()) + 1, j++)
    {
        std::vector<int64_t> R_small;

        bgv.decrypt(R_ciphers[j], R_plain);

        bgv.decode(R_plain, R_small);

        for (int64_t k = (i == 0 ? 0 : static_cast<int64_t>(pattern.size()) - 1); k < static_cast<int64_t>(slot_count); k++)
        {
            R.push_back(R_small[k]);
        }
    }

    R.resize(text.size());

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "decryption and decode", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // result interpretation
    timer_start = std::chrono::steady_clock::now();

    for (int64_t i = static_cast<int64_t>(pattern.size()) - 1; i < R.size(); i++)
    {
        if (R[i] == static_cast<int64_t>(pattern.size()) * radius_square)
        {
            matched.push_back(i - static_cast<int64_t>(pattern.size()) + 1);
        }
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "result interpretation", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // total time
    double_t total_time = 0;
    for (const auto& [process, time] : times)
    {
        total_time += time;
    }
    times.insert({ "total time", total_time });
}

void PatternMatching::primitive_root(
    std::vector<int64_t> text, std::vector<int64_t> pattern, std::map<std::string, uint64_t>& matching_info, std::vector<int64_t>& matched, std::map<std::string, double_t>& times)
{
    // matching type
    matching_info.insert({ "matching type", static_cast<uint64_t>(matching_type::primitive_root) });


    // timer
    std::chrono::steady_clock::time_point timer_start;
    std::chrono::steady_clock::time_point timer_end;


    // create bgv
    fhe::FHE& bgv = fhe::FHEBuilder()
        .sec_level(sec_level_)
        .mul_mode(fhe::mul_mode_t::convolution)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_integer_scheme(fhe::int_scheme_t::bgv, poly_modulus_degree_, plain_modulus_bit_size_, coeff_modulus_bit_sizes_);

    matching_info.insert({ "n", poly_modulus_degree_ });
    matching_info.insert({ "q", bgv.total_coeff_modulus_bit() });
    matching_info.insert({ "t", bgv.plain_modulus() });
    matching_info.insert({ "text size", text.size() });
    matching_info.insert({ "pattern size", pattern.size() });


    // preprocessing
    timer_start = std::chrono::steady_clock::now();

    std::vector<int64_t> T;
    std::vector<int64_t> P;

    data_preprocessing_for_primitive_root(text, pattern, T, P);
    std::reverse(P.begin(), P.end());

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "preprocessing", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // encode and encryption
    timer_start = std::chrono::steady_clock::now();

    uint64_t slot_count = bgv.slot_count();

    seal::Plaintext T_plain;
    std::vector<seal::Ciphertext> T_ciphers;

    seal::Plaintext P_plain;
    seal::Ciphertext P_cipher;

    for (int64_t i = 0, j = -1; j < static_cast<int64_t>(T.size()) - 1; i = i + static_cast<int64_t>(slot_count) - static_cast<int64_t>(P.size()) + 1)
    {
        j = std::min(static_cast<int64_t>(T.size()) - 1, i + static_cast<int64_t>(slot_count) - 1);

        std::vector<int64_t> T_small(T.begin() + i, T.begin() + j + 1);

        bgv.encode(T_small, T_plain);

        T_ciphers.push_back(bgv.encrypt(T_plain));
    }

    bgv.encode(P, P_plain);
    bgv.encrypt(P_plain, P_cipher);

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "encode and encryption", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // pattern matching
    timer_start = std::chrono::steady_clock::now();

    std::vector<seal::Ciphertext> R_ciphers;

    for (const auto& T_cipher : T_ciphers)
    {
        R_ciphers.push_back(bgv.multiply(T_cipher, P_cipher));
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "pattern matching", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // decryption and decode
    timer_start = std::chrono::steady_clock::now();

    seal::Plaintext R_plain;
    std::vector<int64_t> R;

    R.reserve(R_ciphers.size() * slot_count);

    for (int64_t i = 0, j = 0; j < static_cast<int64_t>(R_ciphers.size()); i = i + static_cast<int64_t>(slot_count) - static_cast<int64_t>(P.size()) + 1, j++)
    {
        std::vector<int64_t> R_small;

        bgv.decrypt(R_ciphers[j], R_plain);

        bgv.decode(R_plain, R_small);

        for (int64_t k = (i == 0 ? 0 : static_cast<int64_t>(P.size()) - 1); k < static_cast<int64_t>(slot_count); k++)
        {
            R.push_back(R_small[k]);
        }
    }

    R.resize(T.size());

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "decryption and decode", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // result interpretation
    timer_start = std::chrono::steady_clock::now();

    for (int64_t i = static_cast<int64_t>(P.size()) - 1; i < R.size(); i++)
    {
        if (R[i] == static_cast<int64_t>(P.size()))
        {
            matched.push_back(i - static_cast<int64_t>(pattern.size()) + 1);
        }
    }

    timer_end = std::chrono::steady_clock::now();
    times.insert({ "result interpretation", std::chrono::duration_cast<std::chrono::milliseconds>(timer_end - timer_start).count() });


    // total time
    double_t total_time = 0;
    for (const auto& [process, time] : times)
    {
        total_time += time;
    }
    times.insert({ "total time", total_time });
}