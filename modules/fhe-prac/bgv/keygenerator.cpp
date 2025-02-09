#include "keygenerator.h"
#include "util/distribution.h"
#include "util/polynomial.h"
#include "util/polymatrix.h"
#include "util/safeoperation.h"
#include <cmath>

namespace fheprac
{
	KeyGenerator::KeyGenerator(const Context& context) : context_(context)
	{
		create_secret_key_internal(sk_);
	}

	SecretKey KeyGenerator::secret_key() const
	{
		return sk_;
	}

	void KeyGenerator::create_public_key(PublicKey& destination) const
	{
		create_public_key_internal(1, destination);
	}

	void KeyGenerator::create_relin_keys(RelinKeys& destination) const
	{
		create_relin_key_internal(destination);
	}

	void KeyGenerator::create_switch_keys(const SecretKey& other, SwitchKeys& destination) const
	{
		create_switch_keys_internal(other, destination);
	}

	void KeyGenerator::create_secret_key_internal(SecretKey& destination) const
	{
		const uint64_t L = context_.depth();
		const uint64_t d = context_.poly_modulus_degree();
		const uint64_t q = context_.first_param().q();

		// sk: 비밀키. (2x1 poly matrix)
		PolyMatrix sk(2, 1, d, q);

		// sk_0: 상수 다항식. (d-1 polynomial)
		// sk_0 = 1 + 0*x + ... + 0*x^(d-1)
		sk.set(0, 0, 0, static_cast<uint64_t>(1));

		// sk_1: 가우시안 분포에서 뽑은 다항식. (d-1 polynomial)
		// sk_1 = X_0 + X_1*x + ... + X_(d-1)*x^(d-1)
		sk.set(1, 0, sample_poly_from_gaussian_dist(d, q));

		// 레벨에 따른 모듈러스 설정.
		destination.assign(L + 1);
		destination.data(L, sk);

		for (size_t j = 1; j <= L; j++)
		{
			const uint64_t level = L - j;
			const EncryptionParameters& params = context_.param(level);

			sk.reset(sk.row_size(), sk.col_size(), d, params.q());

			destination.data(level, sk);
		}
	}

	void KeyGenerator::create_public_key_internal(const uint64_t N, PublicKey& destination) const
	{
		const uint64_t L = context_.depth();
		const uint64_t d = context_.poly_modulus_degree();
		const uint64_t p = context_.plain_modulus_value();
		const uint64_t q = context_.first_param().q();

		// sk: 비밀키. (2x1 poly matrix)
		const PolyMatrix& sk = sk_.data(L, 2);

		// pk: 공개키. (Nx2 poly matrix)
		PolyMatrix pk(N, 2, d, q);

		// t: sk[1][0]. (1x1 poly matrix)
		PolyMatrix t(1, 1, d, q);
		t.set(0, 0, sk.get(1, 0));

		// B: Zq 균등 분포에서 뽑은 다항식 행렬. (Nx1 poly matrix)
		// B[r][c] = Z_0 + Z_1*x + ... + Z_(d-1)*x^(d-1)
		PolyMatrix B(N, 1, d, q);
		for (uint64_t r = 0; r < N; r++)
		{
			B.set(r, 0, sample_poly_from_uniform_dist(d, q));
		}

		// e: 가우시안 분포에서 뽑은 다항식 행렬. (Nx1 poly matrix)
		// e[r][c] = X_0 + X_1*x + ... + X_(d-1)*x^(d-1)
		PolyMatrix e(N, 1, d, q);
		for (uint64_t r = 0; r < N; r++)
		{
			e.set(r, 0, sample_poly_from_gaussian_dist(d, q));
		}

		// b = -Bt + pe. (Nx1 poly matrix)
		PolyMatrix b = -(B * t) + (e * p);

		// pk = (b, B). (Nx2 poly matrix)
		for (uint64_t r = 0; r < N; r++)
		{
			pk.set(r, 0, b.get(r, 0));
			pk.set(r, 1, B.get(r, 0));
		}

		// 레벨에 따른 모듈러스 설정.
		destination.assign(L + 1);
		destination.data(L, pk);

		for (size_t j = 1; j <= L; j++)
		{
			const uint64_t level = L - j;
			const EncryptionParameters& params = context_.param(level);

			pk.reset(pk.row_size(), pk.col_size(), d, params.q());

			destination.data(level, pk);
		}
	}

	void KeyGenerator::create_relin_key_internal(RelinKeys& destination) const
	{
		const uint64_t L = context_.depth();
		const uint64_t d = context_.poly_modulus_degree();
		const uint64_t p = context_.plain_modulus_value();

		// sks: 레벨별 비밀키. (2x1 or 3x1 poly matrix)
		const SecretKey& sks = sk_;

		// rks: 레벨별 재선형화키. (Nx2 poly matrix)
		destination.assign(L + 1);

		for (size_t j = 0; j <= L; j++)
		{
			const uint64_t l = L - j;
			const uint64_t q_l = context_.param(l).q();
			const uint64_t N_l = static_cast<uint64_t>(std::floor(std::log2(q_l))) + 1;

			// sk: 비밀키. (3x1 poly matrix)
			const PolyMatrix& sk = sks.data(l, 3);

			// rk: 재선형화키. (Nx2 poly matrix)
			PolyMatrix rk(N_l, 2, d, q_l);

			// t1: sk[1][0]. (1x1 poly matrix)
			PolyMatrix t1(1, 1, d, q_l);
			t1.set(0, 0, sk.get(1, 0));

			// t2: sk[2][0]. (1x1 poly matrix)
			PolyMatrix t2(1, 1, d, q_l);
			t2.set(0, 0, sk.get(2, 0));

			// B: Zq 균등 분포에서 뽑은 다항식 행렬. (Nx1 poly matrix)
			// B[r][c] = Z_0 + Z_1*x + ... + Z_(d-1)*x^(d-1)
			PolyMatrix B(N_l, 1, d, q_l);
			for (uint64_t r = 0; r < N_l; r++)
			{
				B.set(r, 0, sample_poly_from_uniform_dist(d, q_l));
			}

			// e: 가우시안 분포에서 뽑은 다항식 행렬. (Nx1 poly matrix)
			// e[r][c] = X_0 + X_1*x + ... + X_(d-1)*x^(d-1)
			PolyMatrix e(N_l, 1, d, q_l);
			for (uint64_t r = 0; r < N_l; r++)
			{
				e.set(r, 0, sample_poly_from_gaussian_dist(d, q_l));
			}

			// W: t2's power of 2. (Nx1 poly matrix)
			PolyMatrix W;
			W.assign(N_l, 1, d, q_l);

			for (size_t r = 0, pow2 = 1; r < N_l; r++, pow2 <<= 1)
			{
				for (size_t i = 0; i < d; i++)
				{
					W.set(r, 0, i, mul_mod_safe(pow2, t2.get(0, 0, i), q_l));
				}
			}

			// b = -Bt + pe + W. (Nx1 poly matrix)
			PolyMatrix b = -(B * t1) + (e * p) + W;

			// rk = (b, B). (Nx2 poly matrix)
			for (size_t r = 0; r < N_l; r++)
			{
				rk.set(r, 0, b.get(r, 0));
				rk.set(r, 1, B.get(r, 0));
			}

			destination.data(l, rk);
		}
	} 

	void KeyGenerator::create_switch_keys_internal(const SecretKey& other, SwitchKeys& destination) const
	{
		const uint64_t L = context_.depth();
		const uint64_t d = context_.poly_modulus_degree();
		const uint64_t p = context_.plain_modulus_value();

		// sks1: 레벨별 비밀키1. (2x1 or 3x1 poly matrix)
		const SecretKey& sks1 = sk_;

		// sks2: 레벨별 비밀키2. (2x1 or 3x1 poly matrix)
		const SecretKey& sks2 = other;

		// wks: 레벨별 스위치키. (Nx2 poly matrix)
		destination.assign(L + 1);

		for (size_t j = 0; j <= L; j++)
		{
			const uint64_t l = L - j;
			const PolyMatrix& sk1 = sks1.data(l, 2);
			const PolyMatrix& sk2 = sks2.data(l, 2);

			if (sk1.modulus() != sk2.modulus())
			{
				throw std::invalid_argument("modulus of level is mismatched.");
			}

			if (sk1.poly_modulus_degree() != sk2.poly_modulus_degree())
			{
				throw std::invalid_argument("poly modulus degree of level is mismatched.");
			}

			const uint64_t q_l = sk1.modulus();
			const uint64_t d_l = sk1.poly_modulus_degree();
			const uint64_t log_q_l = static_cast<uint64_t>(std::floor(std::log2(q_l))) + 1;
			const uint64_t N_l = sk1.row_size() * log_q_l;

			// wk: 스위치키. (Nx2 poly matrix)
			PolyMatrix wk(N_l, 2, d, q_l);

			// t: sk[1][0]. (1x1 poly matrix)
			PolyMatrix t(1, 1, d, q_l);
			t.set(0, 0, sk2.get(1, 0));

			// B: Zq 균등 분포에서 뽑은 다항식 행렬. (Nx1 poly matrix)
			// B[r][c] = Z_0 + Z_1*x + ... + Z_(d-1)*x^(d-1)
			PolyMatrix B(N_l, 1, d, q_l);
			for (uint64_t r = 0; r < N_l; r++)
			{
				B.set(r, 0, sample_poly_from_uniform_dist(d, q_l));
			}

			// e: 가우시안 분포에서 뽑은 다항식 행렬. (Nx1 poly matrix)
			// e[r][c] = X_0 + X_1*x + ... + X_(d-1)*x^(d-1)
			PolyMatrix e(N_l, 1, d, q_l);
			for (uint64_t r = 0; r < N_l; r++)
			{
				e.set(r, 0, sample_poly_from_gaussian_dist(d, q_l));
			}

			// W: 비밀키1의 power of 2. (Nx2 poly matrix)
			PolyMatrix W;
			W.assign(N_l, 1, d, q_l);

			for (size_t r = 0; r < sk1.row_size(); r++)
			{
				for (size_t c = 0, pow = 1; c < log_q_l; c++, pow <<= 1)
				{
					W.set((r * log_q_l) + c, 0, sk1.get(r, 0) * pow);
				}
			}

			// b = -Bt + pe + W. (Nx1 poly matrix)
			PolyMatrix b = -(B * t) + (e * p) + W;

			// wk = (b, B). (Nx2 poly matrix)
			for (size_t r = 0; r < N_l; r++)
			{
				wk.set(r, 0, b.get(r, 0));
				wk.set(r, 1, B.get(r, 0));
			}

			destination.data(l, wk);
		}
	}
}