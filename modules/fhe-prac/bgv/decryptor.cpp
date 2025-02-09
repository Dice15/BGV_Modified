#include "decryptor.h"

namespace fheprac
{
	Decryptor::Decryptor(const Context& context, const SecretKey& secretkey) :context_(context), sk_(secretkey) {}

	void Decryptor::decrypt(const Ciphertext& ciphertext, Plaintext& destination) const
	{
		const EncryptionParameters& params = ciphertext.params();

		const uint64_t p = context_.plain_modulus_value();
		const uint64_t l = params.l();
		const uint64_t q = params.q();

		// ct: 암호문 데이터. (2x1 poly matrix or 3x1 poly matrix)
		const PolyMatrix& ct = ciphertext.data();

		// sk: 레벨dep에서 정의된 비밀키. (2x1 poly matrix or 3x1 poly matrix)
		// sk: [[1], [t]]
		PolyMatrix sk = sk_.data(l, ciphertext.size());

		// m_q: 복호화 데이터. (1x1 poly matrix)
		// m_q = [<c^T, s>]_q
		destination.data(ct.t() * sk);

		// m: 평문 데이터. (1x1 poly matrix)
		// m = [m_q]_p
		destination.reset(context_);
	}
}