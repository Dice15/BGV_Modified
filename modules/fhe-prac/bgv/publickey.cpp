#include "publickey.h"
#include <stdexcept>

namespace fheprac
{
	PublicKey::PublicKey(const size_t key_count)
	{
		assign(key_count);
	}

	void PublicKey::assign(const size_t key_count)
	{
		pk_.assign(key_count, PolyMatrix());
	}

	size_t PublicKey::count() const
	{
		return pk_.size();
	}

	const PolyMatrix& PublicKey::data(const size_t level) const
	{
		return pk_[level];
	}

	void PublicKey::data(const size_t level, const PolyMatrix& poly_matrix)
	{
		if (poly_matrix.row_size() < static_cast<size_t>(1))
		{
			throw std::invalid_argument("The polynomial matrix for the public key must not be empty.");
		}

		if (poly_matrix.col_size() != static_cast<size_t>(2))
		{
			throw std::invalid_argument("The column size of the polynomial matrix for the public key must be 2.");
		}

		pk_[level] = poly_matrix;
	}
}