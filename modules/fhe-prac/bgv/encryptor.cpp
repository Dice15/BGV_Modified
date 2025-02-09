#include "encryptor.h"
#include "util/distribution.h"
#include "util/polynomial.h"
#include "util/polymatrix.h"

namespace fheprac
{
	Encryptor::Encryptor(const Context& context, const PublicKey& publickey) :context_(context), pk_(publickey) {}

	void Encryptor::encrypt(const Plaintext& plaintext, Ciphertext& destination) const
	{
		const EncryptionParameters& params = context_.first_param();

		const uint64_t dep = context_.depth();
		const uint64_t d = context_.poly_modulus_degree();
		const uint64_t p = context_.plain_modulus_value();
		const uint64_t q = params.q();

		// pt: 평문. (1x1 poly matrix)
		const PolyMatrix& pt = plaintext.data();

		// m: 평문으로 메시지 생성. (2x1 poly matrix)
		// m = (pt_0 + pt_1*x + ... + pt_(d-1)*x) mod q
		PolyMatrix m(2, 1, d, q);
		for (uint64_t i = 0; i < d; i++)
		{
			m.set(0, 0, i, pt.get(0, 0, i));
			m.set(1, 0, i, static_cast<uint64_t>(0));
		}

		// e: 가우시안 분포에서 뽑은 다항식 행렬. (2x1 poly matrix)
		// e[r][c] = X_0 + X_1*x + ... + X_(d-1)*x^(d-1)
		PolyMatrix e(2, 1, d, q);
		e.set(0, 0, sample_poly_from_gaussian_dist(d, q));
		e.set(1, 0, sample_poly_from_gaussian_dist(d, q));

		// r: 가우시안 분포에서 뽑은 다항식 행렬. (1x1 poly matrix)
		// r[r][c] = X_0 + X_1*x + ... + X_(d-1)*x^(d-1)
		PolyMatrix r(1, 1, d, q);
		r.set(0, 0, sample_poly_from_gaussian_dist(d, q));

		// pk: 레벨dep에서 정의된 공개키. (1x2 poly matrix)
		// pk: [[b, -B]]
		PolyMatrix pk = pk_.data(dep);

		// ct: 암호문 데이터. (2x1 poly matrix)
		// ct = m + pe + (pk^T)r
		destination.data(m + (e * p) + (pk.t() * r));
		destination.params(params);
	}
}