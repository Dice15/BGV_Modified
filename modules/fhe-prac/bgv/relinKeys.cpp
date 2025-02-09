#include "relinkeys.h"
#include <stdexcept>

namespace fheprac
{
	RelinKeys::RelinKeys(const size_t key_count)
	{
		assign(key_count);
	}

	void RelinKeys::assign(const size_t key_count)
	{
		rk_.assign(key_count, PolyMatrix());
	}

	size_t RelinKeys::count() const
	{
		return rk_.size();
	}

	const PolyMatrix& RelinKeys::data(const size_t level) const
	{
		return rk_[level];
	}

	void RelinKeys::data(const size_t level, const PolyMatrix& poly_matrix)
	{
		if (poly_matrix.row_size() < static_cast<size_t>(1))
		{
			throw std::invalid_argument("The polynomial matrix for the relinearize key must not be empty.");
		}

		if (poly_matrix.col_size() != static_cast<size_t>(2))
		{
			throw std::invalid_argument("The column size of the polynomial matrix for the relinearize key must be 2.");
		}

		rk_[level] = poly_matrix;
	}
}