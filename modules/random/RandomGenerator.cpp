#include "RandomGenerator.h"
#include <ctime>
#include <algorithm>
#include <numeric>
#include <stdexcept>

RandomGenerator::RandomGenerator() 
{
    random_generator_ = std::mt19937(static_cast<unsigned int>(std::time(nullptr)));
}

std::vector<double_t> RandomGenerator::validate_and_scale_weights(std::vector<uint64_t> weights, size_t elements_size)
{
    if (weights.size() != elements_size) 
    {
        throw std::invalid_argument("Weights size does not match elements size.");
    }

    double_t sum = 0.0;

    for (auto w : weights) 
    {
        sum += static_cast<double>(w);
    }

    if (sum <= 0.0) 
    {
        throw std::invalid_argument("Sum of weights must be positive.");
    }

    std::vector<double_t> normalized;
    normalized.reserve(weights.size());

    for (auto w : weights) 
    {
        normalized.push_back(static_cast<double_t>(w) / sum);
    }

    return normalized;
}

int64_t RandomGenerator::get_integer(int64_t lower, int64_t upper, bool non_zero)
{
    if (lower > upper)
    {
        throw std::invalid_argument("Lower bound is greater than upper bound.");
    }

    if (non_zero)
    {
        bool has_nonzero = false;

        if (lower <= 0 && upper >= 0)
        {
            if (lower < 0 || upper > 0)
            {
                has_nonzero = true;
            }
        }
        else
        {
            has_nonzero = true;
        }

        if (!has_nonzero)
        {
            throw std::invalid_argument("No non-zero value in the given range.");
        }

        std::uniform_int_distribution<int64_t> dist(lower, upper);

        int64_t value = 0;

        while (value == 0)
        {
            value = dist(random_generator_);
        }

        return value;
    }
    else
    {
        std::uniform_int_distribution<int64_t> dist(lower, upper);

        return dist(random_generator_);
    }
}

int64_t RandomGenerator::get_integer(std::vector<int64_t> elements, std::vector<uint64_t> weights) 
{
    if (elements.empty()) 
    {
        throw std::invalid_argument("Elements vector is empty.");
    }

    if (weights.empty()) 
    {
        std::uniform_int_distribution<size_t> dist(0, elements.size() - 1);
        return elements[dist(random_generator_)];
    }

    else 
    {
        auto normalized_weights = validate_and_scale_weights(weights, elements.size());

        std::discrete_distribution<size_t> dist(normalized_weights.begin(), normalized_weights.end());

        return elements[dist(random_generator_)];
    }
}

std::vector<int64_t> RandomGenerator::get_integer_vector(int64_t lower, int64_t upper, size_t vector_size, bool non_zero)
{
    std::vector<int64_t> result;

    result.reserve(vector_size);

    for (int i = 0; i < vector_size; ++i) 
    {
        result.push_back(get_integer(lower, upper, non_zero));
    }

    return result;
}

std::vector<int64_t> RandomGenerator::get_integer_vector(std::vector<int64_t> elements, size_t vector_size, std::vector<uint64_t> weights)
{
    if (elements.empty()) 
    {
        throw std::invalid_argument("Elements vector is empty.");
    }

    std::vector<int64_t> result;
    result.reserve(vector_size);

    if (weights.empty())
    {
        std::uniform_int_distribution<size_t> dist(0, elements.size() - 1);

        for (int i = 0; i < vector_size; ++i)
        {
            result.push_back(elements[dist(random_generator_)]);
        }
    }
    else 
    {
        auto normalized_weights = validate_and_scale_weights(weights, elements.size());

        std::discrete_distribution<size_t> dist(normalized_weights.begin(), normalized_weights.end());

        for (int i = 0; i < vector_size; ++i)
        {
            result.push_back(elements[dist(random_generator_)]);
        }
    }

    return result;
}

std::set<int64_t> RandomGenerator::get_integer_set(int64_t lower, int64_t upper, size_t set_size, bool non_zero)
{
    if (lower > upper) 
    {
        throw std::invalid_argument("Lower bound is greater than upper bound.");
    }

    int64_t total_values = (upper - lower + 1);

    if (non_zero && (lower <= 0 && upper >= 0)) 
    {
        total_values -= 1; // 0 Á¦¿Ü
    }

    if (total_values < set_size)
    {
        throw std::invalid_argument("Range does not contain enough unique values.");
    }

    std::set<int64_t> result;

    if (non_zero)
    {
        while (result.size() < static_cast<size_t>(set_size)) 
        {
            int64_t value = get_integer(lower, upper, true);
            result.insert(value);
        }
    }
    else
    {
        std::uniform_int_distribution<int64_t> dist(lower, upper);
        while (result.size() < static_cast<size_t>(set_size)) {
            result.insert(dist(random_generator_));
        }
    }

    return result;
}