#include "safeoperation.h"
#include <intrin.h>

namespace fheprac
{
    uint64_t mod(uint64_t a, uint64_t modulus)
    {
        return a % modulus;
    }

    void add_safe(uint64_t a, uint64_t b, uint64_t& low, uint64_t& high)
    {
        low = a + b;
        bool carry = (low < a);
        high = carry ? 1ULL : 0ULL;
    }

    uint64_t add_mod_safe(uint64_t a, uint64_t b, uint64_t modulus)
    {
        uint64_t low = a + b;
        bool carry = (low < a);
        uint64_t high = carry ? 1ULL : 0ULL;

        uint64_t remainder = 0ULL;
        _udiv128(high, low, modulus, &remainder);

        return remainder;
    }

    void mul_safe(uint64_t a, uint64_t b, uint64_t& low, uint64_t& high)
    {
        low = _umul128(a, b, &high);
    }

    uint64_t mul_mod_safe(uint64_t a, uint64_t b, uint64_t modulus)
    {
        uint64_t high = 0ULL;
        uint64_t low = _umul128(a, b, &high);

        uint64_t remainder = 0ULL;
        _udiv128(high, low, modulus, &remainder);

        return remainder;
    }

    void div_safe(uint64_t high, uint64_t low, uint64_t divisor, uint64_t& quotient, uint64_t& remainder)
    {
        quotient = _udiv128(high, low, divisor, &remainder);
    }

    uint64_t div_mod_safe(uint64_t high, uint64_t low, uint64_t divisor, uint64_t modulus)
    {
        uint64_t remainder = 0ULL;
        uint64_t quotient = _udiv128(high, low, divisor, &remainder);

        return mod(quotient, modulus);
    }

    uint64_t negate_mod_safe(uint64_t a, uint64_t modulus)
    {
        return modulus - mod(a, modulus);
    }
}