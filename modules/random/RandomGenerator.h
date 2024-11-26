#pragma once
#include <random>
#include <vector>
#include <set>
#include <type_traits>

class RandomGenerator {
public:
    RandomGenerator();

    // Get a single integer with optional weights
    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        T get_integer(T lower, T upper, const std::vector<double_t>& weights = {});

    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        T get_integer(const std::vector<T>& elements, const std::vector<double_t>& weights = {});

    // Get a vector of integers with optional weights
    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        std::vector<T> get_integer_vector(T lower, T upper, int vector_size, const std::vector<double_t>& weights = {});

    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        std::vector<T> get_integer_vector(const std::vector<T>& elements, int vector_size, const std::vector<double_t>& weights = {});

    // Get a set of unique integers with optional weights
    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        std::set<T> get_integer_set(T lower, T upper, int set_size, const std::vector<double_t>& weights = {});

    // Generate a random weight vector of specified length
    std::vector<double_t> get_random_weights(int size);

private:
    std::mt19937 random_generator_;

    // Helper function to validate weights
    void validate_weights(const std::vector<double_t>& weights, size_t elements_size);
};