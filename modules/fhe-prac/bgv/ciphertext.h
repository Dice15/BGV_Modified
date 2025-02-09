#pragma once

#include "context.h"
#include "encryptionparams.h"
#include "util/polymatrix.h"

namespace fheprac
{
	class Ciphertext
	{
	public:
		Ciphertext() = default;

		Ciphertext(const size_t size, const Context& context, const EncryptionParameters& params);

		void assign(const size_t size, const Context& context, const EncryptionParameters& params);

		void reset(const size_t size, const Context& context, const EncryptionParameters& params);

		size_t size() const;

		const PolyMatrix& data() const;

		uint64_t data(const size_t row, const size_t col, const size_t index) const;

		void data(const PolyMatrix& poly_matrix);

		void data(const size_t row, const size_t col, const size_t index, const uint64_t value);

		const EncryptionParameters& params() const;

		void params(const EncryptionParameters& params);

	private:
		PolyMatrix ct_;

		EncryptionParameters params_;
	};
}