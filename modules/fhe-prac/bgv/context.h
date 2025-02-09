#pragma once
#include "encryptionparams.h"
#include <stdint.h>
#include <vector>
#include <seal/seal.h>

namespace fheprac
{
	class Context
	{
	public:
		Context(const uint64_t poly_modulus_degree, const uint64_t plain_modulus_bit_size, const uint64_t depth);

		uint64_t poly_modulus_degree() const;

		uint64_t plain_modulus_value() const;

		uint64_t depth() const;

		uint64_t slot_count() const;

		EncryptionParameters first_param() const;

		EncryptionParameters last_param() const;

		EncryptionParameters param(const uint64_t index) const;

	private:
		uint64_t get_p(const uint64_t factor, const uint64_t bit_size) const;

		uint64_t get_q(const uint64_t factor, const uint64_t lower_bound) const;

		std::vector<uint64_t> create_modulus_chain() const;

		uint64_t poly_modulus_degree_;

		uint64_t plain_modulus_;

		uint64_t depth_;

		std::vector<EncryptionParameters> params_;
	};
}