#include "ciphertext.h"
#include <stdexcept>

namespace fheprac
{
	Ciphertext::Ciphertext(const size_t size, const Context& context, const EncryptionParameters& params)
	{
		assign(size, context, params);
	}

	void Ciphertext::assign(const size_t size, const Context& context, const EncryptionParameters& params)
	{
		ct_.assign(size, 1, context.poly_modulus_degree(), params.q());
		params_ = params;
	}

	void Ciphertext::reset(const size_t size, const Context& context, const EncryptionParameters& params)
	{
		ct_.reset(size, 1, context.poly_modulus_degree(), params.q());
		params_ = params;
	}

	size_t Ciphertext::size() const
	{
		return ct_.row_size();
	}

	const PolyMatrix& Ciphertext::data() const
	{
		return ct_;
	}

	uint64_t Ciphertext::data(const size_t row, const size_t col, const size_t index) const
	{
		if (row >= ct_.row_size() || col >= ct_.col_size())
		{
			throw std::out_of_range("Dimension is out of range.");
		}

		if (index >= ct_.poly_modulus_degree())
		{
			throw std::out_of_range("Index is out of range.");
		}

		return ct_.get(row, col, index);
	}

	void Ciphertext::data(const PolyMatrix& poly_matrix)
	{
		if (poly_matrix.row_size() < static_cast<size_t>(1))
		{
			throw std::invalid_argument("The polynomial matrix for the ciphertext must not be empty.");
		}

		if (poly_matrix.col_size() != static_cast<size_t>(1))
		{
			throw std::invalid_argument("The column size of the polynomial matrix for the ciphertext must be 1.");
		}


		ct_ = poly_matrix;
	}

	void Ciphertext::data(const size_t row, const size_t col, const size_t index, const uint64_t value)
	{
		if (row >= ct_.row_size() || col >= ct_.col_size())
		{
			throw std::out_of_range("Dimension is out of range.");
		}

		if (index >= ct_.poly_modulus_degree())
		{
			throw std::out_of_range("Index is out of range.");
		}

		ct_.set(row, col, index, value);
	}

	const EncryptionParameters& Ciphertext::params() const
	{
		return params_;
	}

	void Ciphertext::params(const EncryptionParameters& params)
	{
		params_ = params;
	}
}