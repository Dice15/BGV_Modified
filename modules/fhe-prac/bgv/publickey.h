#pragma once

#include "util/polymatrix.h"
#include <vector>

namespace fheprac
{
	class PublicKey
	{
	public:
		PublicKey() = default;

		PublicKey(const size_t key_count);

		void assign(const size_t key_count);

		size_t count() const;

		const PolyMatrix& data(const size_t level) const;

		void data(const size_t level, const PolyMatrix& poly_matrix);

	private:
		std::vector<PolyMatrix> pk_;
	};
}