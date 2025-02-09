#include "switchkeys.h"
#include <stdexcept>

namespace fheprac
{
	SwitchKeys::SwitchKeys(const size_t key_count)
	{
		assign(key_count);
	}

	void SwitchKeys::assign(const size_t key_count)
	{
		wk_.assign(key_count, PolyMatrix());
	}

	size_t SwitchKeys::count() const
	{
		return wk_.size();
	}

	const PolyMatrix& SwitchKeys::data(const size_t level) const
	{
		return wk_[level];
	}

	void SwitchKeys::data(const size_t level, const PolyMatrix& poly_matrix)
	{
		if (poly_matrix.row_size() < static_cast<size_t>(1))
		{
			throw std::invalid_argument("The polynomial matrix for the switch key must not be empty.");
		}

		if (poly_matrix.col_size() != static_cast<size_t>(2))
		{
			throw std::invalid_argument("The column size of the polynomial matrix for the switch key must be 2.");
		}

		wk_[level] = poly_matrix;
	}
}