#include "plaintext.h"
#include <stdexcept>

namespace fheprac
{
	Plaintext::Plaintext(const Context& context)
	{
		assign(context);
	}

	void Plaintext::assign(const Context& context)
	{
		pt_.assign(1, 1, context.poly_modulus_degree(), context.plain_modulus_value());
	}

	void Plaintext::reset(const Context& context)
	{
		pt_.reset(1, 1, context.poly_modulus_degree(), context.plain_modulus_value());
	}

	size_t Plaintext::size() const
	{
		return pt_.row_size();
	}

	const PolyMatrix& Plaintext::data() const
	{
		return pt_;
	}

	uint64_t Plaintext::data(const size_t index) const
	{
		if (index >= pt_.poly_modulus_degree())
		{
			throw std::out_of_range("Index is out of range.");
		}

		return 	pt_.get(0, 0, index);
	}

	void Plaintext::data(const PolyMatrix& poly_matrix)
	{
		if (poly_matrix.row_size() < static_cast<size_t>(1))
		{
			throw std::invalid_argument("The polynomial matrix for the plaintext must not be empty.");
		}

		if (poly_matrix.row_size() != static_cast<size_t>(1) || poly_matrix.col_size() != static_cast<size_t>(1))
		{
			throw std::invalid_argument("The dimension of the polynomial matrix for the plaintext must be 1 x 1.");
		}

		pt_ = poly_matrix;
	}

	void Plaintext::data(const size_t index, const uint64_t value)
	{
		if (index >= pt_.poly_modulus_degree())
		{
			throw std::out_of_range("Index is out of range.");
		}

		pt_.set(0, 0, index, value);
	}
}