#include "encryptionparams.h"

namespace fheprac
{
	EncryptionParameters::EncryptionParameters(const uint64_t q, const uint64_t l, const uint64_t next_index) :q_(q), l_(l), next_param_index_(next_index) {}

	uint64_t& EncryptionParameters::q()
	{
		return q_;
	}

	const uint64_t& EncryptionParameters::q() const 
	{
		return q_; 
	}

	uint64_t& EncryptionParameters::l()
	{
		return l_;
	}

	const uint64_t& EncryptionParameters::l() const
	{
		return l_;
	}

	uint64_t EncryptionParameters::next_param_index() const
	{
		return next_param_index_;
	}
}