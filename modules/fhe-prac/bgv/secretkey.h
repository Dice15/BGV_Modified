#pragma once

#include "context.h"
#include "encryptionparams.h"
#include "util/polymatrix.h"
#include "util/polynomial.h"
#include <vector>

namespace fheprac
{
	class SecretKey
	{
	public:
		SecretKey() = default;

		SecretKey(const size_t key_count);

		void assign(const size_t key_count);

		size_t count() const;

		const PolyMatrix& data(const size_t level, const size_t size) const;

		void data(const size_t level, const PolyMatrix& poly_matrix);

	private:
		void tensor_square(const PolyMatrix& poly_matrix, PolyMatrix& destination) const;

		std::vector<std::vector<PolyMatrix>> sk_;
	};
}