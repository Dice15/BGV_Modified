#pragma once

#include "context.h"
#include "encryptionparams.h"
#include "util/polymatrix.h"

namespace fheprac
{
	class Plaintext
	{
	public:
		Plaintext() = default;

		Plaintext(const Context& context);

		void assign(const Context& context);

		void reset(const Context& context);

		size_t size() const;

		const PolyMatrix& data() const;

		uint64_t data(const size_t index) const;

		void data(const PolyMatrix& poly_matrix);

		void data(const size_t index, const uint64_t value);

	private:
		PolyMatrix pt_;
	};
}