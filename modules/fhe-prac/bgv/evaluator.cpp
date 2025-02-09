#include "evaluator.h"
#include "encryptionparams.h"
#include "util/safeoperation.h"
#include <stdexcept>
#include <intrin.h>
#include <cmath>
#include <iostream>

namespace fheprac
{
    Evaluator::Evaluator(const Context& context) :context_(context) {}

    void Evaluator::mod_switch(const Ciphertext& ciphertext, Ciphertext& destination) const
    {
        const EncryptionParameters& curr_params = ciphertext.params();
        const EncryptionParameters& next_params = context_.param(curr_params.next_param_index());

        if (curr_params.l() <= next_params.l())
        {
            throw std::invalid_argument("Modulus switching cannot proceed further.");
        }

        const uint64_t d = context_.poly_modulus_degree();
        const uint64_t p = context_.plain_modulus_value();
        const uint64_t curr_q = curr_params.q();
        const uint64_t next_q = next_params.q();

        // ct, ct': 암호문 데이터. (2x1 poly matrix)
        const PolyMatrix& ct = ciphertext.data();
        PolyMatrix ct_dot(ct.row_size(), ct.col_size(), d, next_q);

        // curr_q > next_q > p and curr_q = next_q = 1 mod p.
        // [<ct', s>]_next_q = [<ct, s>]_curr_q mod p.
        // ct' = closet((curr_q / next_q) * ct) mod p.
        for (uint64_t row = 0; row < ct_dot.row_size(); row++)
        {
            for (uint64_t col = 0; col < ct_dot.col_size(); col++)
            {
                for (uint64_t i = 0; i < ct_dot.poly_modulus_degree(); i++)
                {
                    const uint64_t coeff_curr = ct.get(row, col, i);
                    const uint64_t coeff_next = drop_to_next_q(coeff_curr, curr_q, next_q, p);
                    ct_dot.set(row, col, i, coeff_next);
                }
            }
        }

        destination.data(ct_dot);
        destination.params(next_params);
    }

    void Evaluator::relinearize(const Ciphertext& ciphertext, const RelinKeys& relinkeys, Ciphertext& destination) const
    {
        if (ciphertext.size() != static_cast<size_t>(3))
        {
            throw std::invalid_argument(".");    // 오직 크기가 3인 암호문만 재선형화가 가능합니다.
        }

        if (context_.poly_modulus_degree() != ciphertext.data().poly_modulus_degree())
        {
            throw std::invalid_argument(".");    // 다항식 모듈러스 차수 is mismathed
        }

        const EncryptionParameters& params = ciphertext.params();
        const uint64_t d = context_.poly_modulus_degree();
        const uint64_t l = params.l();
        const uint64_t q = params.q();
        const uint64_t N = static_cast<uint64_t>(std::floor(std::log2(q))) + 1;

        // ct: 암호문 데이터. (3x1 poly matrix)
        PolyMatrix ct = ciphertext.data();

        // rk: 재선형화키. (Nx2 poly matrix)
        const PolyMatrix& rk = relinkeys.data(l);

        // D: t^2에 대응하는 암호문 비트. (1xN poly matrix)
        PolyMatrix D;
        D.assign(1, N, d, q);

        for (size_t c = 0, bit = 1; c < N; c++, bit <<= 1)
        { 
            for (size_t i = 0; i < d; i++)
            {
                D.set(0, c, i, (ct.get(2, 0, i) & bit) ? 1 : 0);
            }
        }  

        // ct_2: 재선형화가 완료된 암호문. (2x1 poly matrix)
        ct.reset(2, 1, d, q);
        destination.data(ct + (D * rk).t());
        destination.params(params);
    }

    void Evaluator::key_switch(const Ciphertext& ciphertext, const SwitchKeys& switchkeys, Ciphertext& destination) const
    {
        if (ciphertext.size() != static_cast<size_t>(2))
        {
            throw std::invalid_argument(".");    // 오직 크기가 2인 암호문만 키스위칭이 가능합니다.
        }

        const EncryptionParameters& params = ciphertext.params();
        const uint64_t d = context_.poly_modulus_degree();
        const uint64_t l = params.l();
        const uint64_t q = params.q();
        const uint64_t log_q = static_cast<uint64_t>(std::floor(std::log2(q))) + 1;
        const uint64_t N = ciphertext.size() * log_q;
        const PolyMatrix& ct = ciphertext.data();

        // D: 암호문 비트. (Nx1 poly matrix)
        PolyMatrix D;
        D.assign(N, 1, d, q);

        for (size_t r = 0; r < ct.row_size(); r++)
        {
            for (size_t c = 0, bit = 1; c < log_q; c++, bit <<= 1)
            {
                for (size_t i = 0; i < ct.poly_modulus_degree(); i++)
                {
                    D.set((r * log_q) + c, 0, i, (ct.get(r, 0, i) & bit) ? 1 : 0);
                }
            }
        }

        // rk: 재선형화키. (Nx2 poly matrix)
        const PolyMatrix& wk = switchkeys.data(l);

        // ct_2: 재선형화가 완료된 암호문. (2x1 poly matrix)
        destination.data((D.t() * wk).t());
        destination.params(params);
    }

    void Evaluator::add(const Ciphertext& ciphertext1, const Ciphertext& ciphertext2, Ciphertext& destination) const
    {
        if (ciphertext1.params().l() != ciphertext2.params().l())
        {
            throw std::invalid_argument("ciphertext1 and ciphertext2 parameter mismatch.");
        }

        if (ciphertext1.size() != ciphertext2.size())
        {
            throw std::invalid_argument("ciphertext1 and ciphertext2 size mismatch.");
        }

        const EncryptionParameters& params = ciphertext1.params();
        const PolyMatrix& ct1 = ciphertext1.data();
        const PolyMatrix& ct2 = ciphertext2.data();

        destination.data(ct1 + ct2);
        destination.params(params);
    }

    void Evaluator::add(const Ciphertext& ciphertext, const Plaintext& plaintext, Ciphertext& destination) const
    {
        if (ciphertext.size() < static_cast<size_t>(2))
        {
            throw std::invalid_argument("ciphertext's size must be at least 2.");
        }

        const EncryptionParameters& params = ciphertext.params();
        const PolyMatrix& ct = ciphertext.data();
        PolyMatrix pt = plaintext.data();

        pt.reset(ct.row_size(), ct.col_size(), ct.poly_modulus_degree(), ct.modulus());

        destination.data(ct + pt);
        destination.params(params);
    }

    void Evaluator::add(const Plaintext& plaintext1, const Plaintext& plaintext2, Plaintext& destination) const
    {
        const PolyMatrix& pt1 = plaintext1.data();
        const PolyMatrix& pt2 = plaintext2.data();

        destination.data(pt1 + pt2);
    }

    void Evaluator::sub(const Ciphertext& ciphertext1, const Ciphertext& ciphertext2, Ciphertext& destination) const
    {
        if (ciphertext1.params().l() != ciphertext2.params().l())
        {
            throw std::invalid_argument("ciphertext1 and ciphertext2 parameter mismatch.");
        }

        if (ciphertext1.size() != ciphertext2.size())
        {
            throw std::invalid_argument("ciphertext1 and ciphertext2 size mismatch.");
        }

        const EncryptionParameters& params = ciphertext1.params();
        const PolyMatrix& ct1 = ciphertext1.data();
        const PolyMatrix& ct2 = ciphertext2.data();

        destination.data(ct1 - ct2);
        destination.params(params);
    }

    void Evaluator::sub(const Ciphertext& ciphertext, const Plaintext& plaintext, Ciphertext& destination) const
    {
        if (ciphertext.size() < static_cast<size_t>(2))
        {
            throw std::invalid_argument("ciphertext's size must be at least 2.");
        }

        const EncryptionParameters& params = ciphertext.params();
        const PolyMatrix& ct = ciphertext.data();
        PolyMatrix pt = plaintext.data();

        pt.reset(ct.row_size(), ct.col_size(), ct.poly_modulus_degree(), ct.modulus());

        destination.data(ct - pt);
        destination.params(params);
    }

    void Evaluator::sub(const Plaintext& plaintext1, const Plaintext& plaintext2, Plaintext& destination) const
    {
        const PolyMatrix& pt1 = plaintext1.data();
        const PolyMatrix& pt2 = plaintext2.data();

        destination.data(pt1 - pt2);
    }

    void Evaluator::multiply(const Ciphertext& ciphertext1, const Ciphertext& ciphertext2, Ciphertext& destination) const
    {
        if (ciphertext1.params().l() != ciphertext2.params().l())
        {
            throw std::invalid_argument("ciphertext1 and ciphertext2 parameter mismatch.");
        }

        if (ciphertext1.size() != ciphertext2.size())
        {
            throw std::invalid_argument("ciphertext1 and ciphertext2 size mismatch.");
        }

        if (ciphertext1.size() != static_cast<size_t>(2))
        {
            throw std::invalid_argument("Only ciphertexts of size 2 can be multiplied.");
        }

        const EncryptionParameters& params = ciphertext1.params();
        const PolyMatrix& ct1 = ciphertext1.data();
        const PolyMatrix& ct2 = ciphertext2.data();

        const Polynomial& c0 = ct1.get(0, 0);
        const Polynomial& c1 = ct1.get(1, 0);
        const Polynomial& k0 = ct2.get(0, 0);
        const Polynomial& k1 = ct2.get(1, 0);

        PolyMatrix ct(ct1.row_size() + 1, ct1.col_size(), ct1.poly_modulus_degree(), ct1.modulus());

        ct.set(0, 0, c0 * k0);
        ct.set(1, 0, (c0 * k1) + (c1 * k0));
        ct.set(2, 0, c1 * k1);

        destination.data(ct);
        destination.params(params);
    }

    void Evaluator::multiply(const Ciphertext& ciphertext, const Plaintext& plaintext, Ciphertext& destination) const
    {
        if (ciphertext.size() < static_cast<size_t>(2))
        {
            throw std::invalid_argument("Only ciphertexts of size 2 can be multiplied.");
        }

        const EncryptionParameters& params = ciphertext.params();
        const PolyMatrix& ct = ciphertext.data();
        PolyMatrix pt = plaintext.data();

        pt.reset(pt.row_size(), ct.col_size(), ct.poly_modulus_degree(), ct.modulus());

        destination.data(ct * pt);
        destination.params(params);
    }

    void Evaluator::multiply(const Plaintext& plaintext1, const Plaintext& plaintext2, Plaintext& destination) const
    {
        const PolyMatrix& pt1 = plaintext1.data();
        const PolyMatrix& pt2 = plaintext2.data();

        destination.data(pt1 * pt2);
    }

    uint64_t Evaluator::drop_to_next_q(uint64_t value, const uint64_t curr_q, const uint64_t next_q, const uint64_t p) const
    {
        const uint64_t curr_q_h = curr_q >> static_cast<uint64_t>(1);
        const uint64_t p_h = p >> static_cast<uint64_t>(1);

        uint64_t origin = value;

        // 계산 정확도를 위해 소수점을 사용하지 않고 계산.
        // scaled = (origin * next_q) / curr_q
        uint64_t scaled, high, low, remainder;
        mul_safe(origin, next_q, low, high);
        div_safe(high, low, curr_q, scaled, remainder);

        // origin = scaled mod p 조건을 만족하면서 scaled와 가장 가까운 값(closet)을 찾아야 한다.
        uint64_t origin_mod_p = mod(origin, p);
        uint64_t scaled_mod_p = mod(scaled, p);
        uint64_t diff = add_mod_safe(origin_mod_p, negate_mod_safe(scaled_mod_p, p), p);
        uint64_t correction_factor = diff <= p_h ? diff : add_mod_safe(diff, negate_mod_safe(p, next_q), next_q);
        uint64_t result = add_mod_safe(scaled, correction_factor, next_q);
        
        // TEST
        //std::cout << origin << " -> " << result << " (correction_factor: " << diff << ", scaled: " << scaled << ", next q: " << next_q << ")" << "\n";

        return result;
    }
}