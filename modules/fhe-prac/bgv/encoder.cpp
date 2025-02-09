#include "encoder.h"
#include "util/polymatrix.h"
#include <stdexcept>

namespace fheprac
{
	Encoder::Encoder(const Context& context) :context_(context) {}

	void Encoder::encode(const std::vector<int64_t>& message, Plaintext& destination) const
	{
		const uint64_t d = std::min(context_.poly_modulus_degree(), message.size());
		const uint64_t p = context_.plain_modulus_value();
		const uint64_t p_h = p >> 1;

		// pt: ∆ÚπÆ. (1x1 poly matrix)
		// pt = (v_0 + v_1*x + ... + v_(d-1)*x) mod p
		destination.assign(context_);

		for (size_t i = 0; i < d; i++)
		{
			const uint64_t value = static_cast<uint64_t>(std::llabs(message[i]));

			if (value > p_h)
			{
				throw std::out_of_range("Value out of range.");
			}

			if (message[i] < 0)
			{
				destination.data(i, p - value);
			}
			else
			{
				destination.data(i, value);
			}
		}
	}

	void Encoder::decode(const Plaintext& plaintext, std::vector<int64_t>& destination) const
	{
		const uint64_t slot_count = context_.poly_modulus_degree();
		const uint64_t p = context_.plain_modulus_value();
		const uint64_t h_p = p >> 1;

		// v: ∫§≈Õ. (d-vector)
		// v = (pt_0 + pt_1*x + ... + pt_(d-1)*x mod p
		destination.assign(slot_count, 0);

		for (size_t i = 0; i < slot_count; i++)
		{
			const uint64_t value = plaintext.data(i);

			if (value > h_p)
			{
				destination[i] = static_cast<int64_t>(value) - static_cast<int64_t>(p);
			}
			else
			{
				destination[i] = value;
			}
		}
	}
}