#pragma once

#include <cstdint>

namespace fheprac
{
    uint64_t mod(uint64_t a, uint64_t modulus);

    void add_safe(uint64_t a, uint64_t b, uint64_t& low, uint64_t& high);

    uint64_t add_mod_safe(uint64_t a, uint64_t b, uint64_t modulus);

    void mul_safe(uint64_t a, uint64_t b, uint64_t& low, uint64_t& high);

    uint64_t mul_mod_safe(uint64_t a, uint64_t b, uint64_t modulus);

    void div_safe(uint64_t high, uint64_t low, uint64_t divisor, uint64_t& quotient, uint64_t& remainder);

    uint64_t div_mod_safe(uint64_t high, uint64_t low, uint64_t divisor, uint64_t mod);

    uint64_t negate_mod_safe(uint64_t a, uint64_t modulus);
}