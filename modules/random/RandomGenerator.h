#pragma once

#include <random>
#include <vector>
#include <set>
#include <cstdint>

class RandomGenerator {
public:
    RandomGenerator();

    int64_t get_integer(int64_t lower, int64_t upper, bool non_zero = false);

    int64_t get_integer(std::vector<int64_t> elements, std::vector<uint64_t> weights = {});

    std::vector<int64_t> get_integer_vector(int64_t lower, int64_t upper, size_t vector_size, bool non_zero = false);

    std::vector<int64_t> get_integer_vector(std::vector<int64_t> elements, size_t vector_size, std::vector<uint64_t> weights = {});

    std::set<int64_t> get_integer_set(int64_t lower, int64_t upper, size_t set_size, bool non_zero = false);

private:
    std::mt19937 random_generator_;

    std::vector<double> validate_and_scale_weights(std::vector<uint64_t> weights, size_t elements_size);
};