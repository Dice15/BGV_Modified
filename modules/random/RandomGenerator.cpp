#include "RandomGenerator.h"
#include <ctime>
#include <algorithm>
#include <numeric>
#include <stdexcept>

// Constructor
RandomGenerator::RandomGenerator() {
    random_generator_ = std::mt19937(static_cast<unsigned int>(std::time(nullptr)));
}

// Helper function to validate weights
void RandomGenerator::validate_weights(const std::vector<double_t>& weights, size_t elements_size) {
    if (!weights.empty()) {
        if (weights.size() != elements_size) {
            throw std::invalid_argument("Weights size does not match elements size.");
        }
        double sum = std::accumulate(weights.begin(), weights.end(), 0.0);
        if (std::abs(sum - 1.0) > 1e-6) {
            throw std::invalid_argument("Weights must sum to 1.");
        }
        for (const auto& w : weights) {
            if (w < 0.0) {
                throw std::invalid_argument("Weights must be non-negative.");
            }
        }
    }
}

// Generate random weight vector
std::vector<double_t> RandomGenerator::get_random_weights(int size) {
    if (size <= 0) {
        throw std::invalid_argument("Length must be positive.");
    }
    std::vector<double> weights(size);
    std::uniform_real_distribution<double_t> dist(0.0, 1.0);
    double sum = 0.0;
    for (auto& w : weights) {
        w = dist(random_generator_);
        sum += w;
    }
    // Normalize the weights to sum to 1
    for (auto& w : weights) {
        w /= sum;
    }
    return weights;
}

// Template Implementations

template<typename T, typename>
T RandomGenerator::get_integer(T lower, T upper, const std::vector<double_t>& weights) {
    if (weights.empty()) {
        // Uniform distribution
        return std::uniform_int_distribution<T>(lower, upper)(random_generator_);
    }
    else {
        // Weighted distribution
        std::vector<T> elements;
        for (T val = lower; val <= upper; ++val) {
            elements.push_back(val);
            if (val == upper) break; // Prevent overflow for signed types
        }
        validate_weights(weights, elements.size());
        std::discrete_distribution<size_t> dist(weights.begin(), weights.end());
        return elements[dist(random_generator_)];
    }
}

template<typename T, typename>
T RandomGenerator::get_integer(const std::vector<T>& elements, const std::vector<double_t>& weights) {
    if (elements.empty()) {
        throw std::invalid_argument("Elements vector is empty.");
    }
    if (weights.empty()) {
        // Uniform distribution
        std::uniform_int_distribution<size_t> dist(0, elements.size() - 1);
        return elements[dist(random_generator_)];
    }
    else {
        validate_weights(weights, elements.size());
        std::discrete_distribution<size_t> dist(weights.begin(), weights.end());
        return elements[dist(random_generator_)];
    }
}

template<typename T, typename>
std::vector<T> RandomGenerator::get_integer_vector(T lower, T upper, int vector_size, const std::vector<double_t>& weights) {
    std::vector<T> result;
    result.reserve(vector_size);
    if (weights.empty()) {
        // Uniform distribution
        std::uniform_int_distribution<T> dist(lower, upper);
        for (int i = 0; i < vector_size; ++i) {
            result.push_back(dist(random_generator_));
        }
    }
    else {
        // Weighted distribution
        std::vector<T> elements;
        for (T val = lower; val <= upper; ++val) {
            elements.push_back(val);
            if (val == upper) break; // Prevent overflow
        }
        validate_weights(weights, elements.size());
        std::discrete_distribution<size_t> dist(weights.begin(), weights.end());
        for (int i = 0; i < vector_size; ++i) {
            result.push_back(elements[dist(random_generator_)]);
        }
    }
    return result;
}

template<typename T, typename>
std::vector<T> RandomGenerator::get_integer_vector(const std::vector<T>& elements, int vector_size, const std::vector<double_t>& weights) {
    if (elements.empty()) {
        throw std::invalid_argument("Elements vector is empty.");
    }
    std::vector<T> result;
    result.reserve(vector_size);
    if (weights.empty()) {
        // Uniform distribution
        std::uniform_int_distribution<size_t> dist(0, elements.size() - 1);
        for (int i = 0; i < vector_size; ++i) {
            result.push_back(elements[dist(random_generator_)]);
        }
    }
    else {
        validate_weights(weights, elements.size());
        std::discrete_distribution<size_t> dist(weights.begin(), weights.end());
        for (int i = 0; i < vector_size; ++i) {
            result.push_back(elements[dist(random_generator_)]);
        }
    }
    return result;
}

template<typename T, typename>
std::set<T> RandomGenerator::get_integer_set(T lower, T upper, int set_size, const std::vector<double_t>& weights) {
    std::set<T> result_set;
    if (weights.empty()) {
        // Uniform distribution
        std::uniform_int_distribution<T> dist(lower, upper);
        while (result_set.size() < static_cast<size_t>(set_size)) {
            result_set.insert(dist(random_generator_));
        }
    }
    else {
        // Weighted distribution
        std::vector<T> elements;
        for (T val = lower; val <= upper; ++val) {
            elements.push_back(val);
            if (val == upper) break; // Prevent overflow
        }
        validate_weights(weights, elements.size());
        std::discrete_distribution<size_t> dist(weights.begin(), weights.end());
        while (result_set.size() < static_cast<size_t>(set_size)) {
            result_set.insert(elements[dist(random_generator_)]);
        }
    }
    return result_set;
}

// Explicit template instantiation
template int16_t RandomGenerator::get_integer<int16_t>(int16_t, int16_t, const std::vector<double_t>&);
template int32_t RandomGenerator::get_integer<int32_t>(int32_t, int32_t, const std::vector<double_t>&);
template int64_t RandomGenerator::get_integer<int64_t>(int64_t, int64_t, const std::vector<double_t>&);

template int16_t RandomGenerator::get_integer<int16_t>(const std::vector<int16_t>&, const std::vector<double_t>&);
template int32_t RandomGenerator::get_integer<int32_t>(const std::vector<int32_t>&, const std::vector<double_t>&);
template int64_t RandomGenerator::get_integer<int64_t>(const std::vector<int64_t>&, const std::vector<double_t>&);

template std::vector<int16_t> RandomGenerator::get_integer_vector<int16_t>(int16_t, int16_t, int, const std::vector<double_t>&);
template std::vector<int32_t> RandomGenerator::get_integer_vector<int32_t>(int32_t, int32_t, int, const std::vector<double_t>&);
template std::vector<int64_t> RandomGenerator::get_integer_vector<int64_t>(int64_t, int64_t, int, const std::vector<double_t>&);

template std::vector<int16_t> RandomGenerator::get_integer_vector<int16_t>(const std::vector<int16_t>&, int, const std::vector<double_t>&);
template std::vector<int32_t> RandomGenerator::get_integer_vector<int32_t>(const std::vector<int32_t>&, int, const std::vector<double_t>&);
template std::vector<int64_t> RandomGenerator::get_integer_vector<int64_t>(const std::vector<int64_t>&, int, const std::vector<double_t>&);

template std::set<int16_t> RandomGenerator::get_integer_set<int16_t>(int16_t, int16_t, int, const std::vector<double_t>&);
template std::set<int32_t> RandomGenerator::get_integer_set<int32_t>(int32_t, int32_t, int, const std::vector<double_t>&);
template std::set<int64_t> RandomGenerator::get_integer_set<int64_t>(int64_t, int64_t, int, const std::vector<double_t>&);