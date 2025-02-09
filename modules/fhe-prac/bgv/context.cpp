#include "context.h"
#include <stdexcept>

namespace fheprac
{
    Context::Context(const uint64_t poly_modulus_degree, const uint64_t plain_modulus_bit_size, const uint64_t depth)
    {
        if (poly_modulus_degree == 0 || (poly_modulus_degree & (poly_modulus_degree - 1)) != 0) 
        {
            throw std::invalid_argument("The poly modulus degree must be a power of 2");
        }

        if (plain_modulus_bit_size < 2)
        {
            throw std::invalid_argument("The plain modulus bit size must be at least 2.");
        }

        if (depth < 1)
        {
            throw std::invalid_argument("The depth must be at least 1.");
        }

        poly_modulus_degree_ = poly_modulus_degree;

        plain_modulus_ = get_p(poly_modulus_degree, plain_modulus_bit_size);

        depth_ = depth;

        // 모듈러스 체인을 기반으로 파라미터 생성.
        for (const auto& q : create_modulus_chain())
        {
            params_.push_back(EncryptionParameters(q, params_.size(), (params_.size() + depth_ - 1) % depth_));
        }
    }

    uint64_t Context::poly_modulus_degree() const
    {
        return poly_modulus_degree_;
    }

    uint64_t Context::plain_modulus_value() const
    {
        return plain_modulus_;
    }

    uint64_t Context::depth() const
    {
        return depth_;
    }

    uint64_t Context::slot_count() const
    {
        return poly_modulus_degree_;
    }

    EncryptionParameters Context::first_param() const
    {
        return params_.back();
    }

    EncryptionParameters Context::last_param() const
    {
        return params_.front();
    }

    EncryptionParameters Context::param(const uint64_t index) const
    {
        return params_[index];
    }

    uint64_t Context::get_p(const uint64_t factor, const uint64_t bit_size) const
    {
        // (2^bit_size - 1) / factor * factor + 1 부터 factor를 빼면서 소수를 찾음.
        uint64_t candidate = ((static_cast<uint64_t>(1) << bit_size) - 1) / factor * factor + 1;
        uint64_t lower_bound = static_cast<uint64_t>(1) << (bit_size - 1);
        bool found = false;

        while (candidate > lower_bound)
        {
            seal::Modulus new_mod(candidate);

            if (new_mod.is_prime())
            {
                found = true;
                break;
            }

            candidate -= factor;
        }

        if (found == false)
        {
            throw std::logic_error("failed to find enough qualifying primes");
        }

        return candidate;
    }

    uint64_t Context::get_q(const uint64_t factor, const uint64_t lower_bound) const
    {
        // (2^bit_size - 1) / factor * factor + 1 부터 factor를 더하면서 소수를 찾음.
        uint64_t candidate = ((lower_bound + factor) / factor) * factor + 1;
        uint64_t upper_bound = static_cast<uint64_t>(1) << (64 - 1);
        bool found = false;

        while (candidate < upper_bound)
        {
            seal::Modulus new_mod(candidate);

            if (new_mod.is_prime())
            {
                found = true;
                break;
            }

            candidate += factor;
        }

        if (found == false)
        {
            throw std::logic_error("failed to find enough qualifying primes");
        }

        return candidate;
    }

    std::vector<uint64_t> Context::create_modulus_chain() const
    {
        uint64_t depth = depth_;
        uint64_t p = plain_modulus_;
        uint64_t d = poly_modulus_degree_;

        // 최대 누적 오차 (X는 표준편자가 3.2인 가우시안 분포에서 뽑은 값이다. 따라서 X는 10으로 계산한다.)
        // 연산 하지 않은 경우: 약 p * (X^2*d + X^2*d + X) + m
        // 곱셈 연산을 한 경우: 약 p^2 * (4*X^4*d^3 + 4*X^3*d^2 + 5*X^2*d + 2*X) + m^2
        // 
        // Modulus switching의 closest 이동으로 인한 증가 값. (이때, mod switch 횟수를 고려하여 depth - 1를 곱한다.)
        // (p / 2) * d * (10 * d) * (depth - 1)
        // 
        // 
        // 따라서 p대비 q의 크기를 (p^2 * (4*X^4*d^3 + 4*X^3*d^2 + 5*X^2*d + 2*X) * p^2) + (p / 2) * d * (10 * d) * (depth - 1) 이상으로 잡으면 충분하다.
        uint64_t max_cipher_value =
            ((p * p) * ((static_cast<uint64_t>(40000) * d * d * d) + (static_cast<uint64_t>(4000) * d * d) + (static_cast<uint64_t>(500) * d) + 20 + 1))
            + ((p >> static_cast <uint64_t>(1)) * d * (10 * d) * depth)
            + (p * 600 * d * d * depth);
            
        uint64_t max_cipher_value_bit = static_cast<uint64_t>(std::log2l(max_cipher_value)) + static_cast<uint64_t>(1);

        // q가 홀수인 Zq에서 [0, q/2]은 양수, [q/2+1, q-1]은 홀수를 나타낸다.
        // 연산 후 |m + pe|가 q/2를 넘게 되면 잘못된 값이 나오게 된다.
        // 예를 들어 q가 13이고 m + pe가 8인 경우, -5 취급이 되어 다른 값이 나오게 된다. 이는 음수일 때도 똑같은 문제가 된다.
        // 따라서 |ct.coeff| < q/2의 의미는, 양수는 [0, q/2] 범위 내에, 음수는 [q/2+1, q-1] 범위 내에 항시 존재하게 하기 위해 필요 조건이다.
        uint64_t q_bound = static_cast<uint64_t>(1) << (max_cipher_value_bit + 1);

        // 다음 조건을 만족하는 q를 (depth + 1)개 찾는다.
        // 1) q[i+1] > q[i] > p
        // 2) q[i+1] = q[i] = 1 mod p
        // 3) q는 소수(or 홀수)
        // 4) q와 p는 서로소
        // 수식 k * p + 1으로 조건 2와 4를 항상 만족하는 값을 구할 수 있다.
        // 또한 k값을 수정해 나가면서 소수인지 판별하면 소수 조건도 만족 시킬 수 있다.
        std::vector<uint64_t> q_chain(depth + 1);

        q_chain[0] = get_q(p, q_bound);

        for (uint64_t i = 1; i < q_chain.size(); i++)
        {
            q_chain[i] = get_q(p, q_chain[i - 1] * p);
        }

        return q_chain;
    }
}