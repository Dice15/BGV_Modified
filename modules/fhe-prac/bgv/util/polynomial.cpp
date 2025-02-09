#include "polynomial.h"
#include "safeoperation.h"
#include <stdexcept>

namespace fheprac
{
	Polynomial::Polynomial() :poly_modulus_degree_(0), modulus_(0) {}

	Polynomial::Polynomial(const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value)
		:poly_modulus_degree_(poly_modulus_degree), modulus_(modulus)
	{
		coeffs_.assign(poly_modulus_degree_, value);
	}

	uint64_t Polynomial::get(const size_t index) const
	{
		if (index >= coeffs_.size())
		{
			throw std::out_of_range("Index out of range.");
		}

		return coeffs_[index];
	}

	const std::vector<uint64_t>& Polynomial::get() const
	{
		return coeffs_;
	}

	void Polynomial::set(const size_t index, const uint64_t value)
	{
		if (index >= coeffs_.size())
		{
			throw std::out_of_range("Index out of range.");
		}

		coeffs_[index] = mod(value, modulus_);
	}

	void Polynomial::set(const std::vector<uint64_t>& coeffients)
	{
		for (size_t i = 0; i < coeffients.size(); i++)
		{
			set(i, coeffients[i]);
		}
	}

	uint64_t Polynomial::poly_modulus_degree() const
	{
		return poly_modulus_degree_;
	}

	uint64_t Polynomial::modulus() const
	{
		return modulus_;
	}

	void Polynomial::assign(const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value)
	{
		poly_modulus_degree_ = poly_modulus_degree;
		modulus_ = modulus;
		coeffs_.assign(poly_modulus_degree_, value);
	}

	void Polynomial::reset(const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value)
	{
		uint64_t mod_prev = modulus_;
		uint64_t mod_prev_h = mod_prev >> 1;
		uint64_t mod_curr = modulus;

		poly_modulus_degree_ = poly_modulus_degree;
		modulus_ = modulus;
		coeffs_.resize(poly_modulus_degree_, value);

		for (size_t i = 0; i < poly_modulus_degree_; i++)
		{
			uint64_t coeff = coeffs_[i];

			if (coeff > mod_prev_h)
			{
				coeff = mod_curr - mod((mod_prev - coeff), mod_curr);
			}
			else
			{
				coeff = mod(coeff, mod_curr);
			}

			coeffs_[i] = coeff;
		}
	}

	void Polynomial::reset_unsafe(const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value)
	{
		uint64_t mod_prev = modulus_;
		uint64_t mod_prev_h = mod_prev >> 1;
		uint64_t mod_curr = modulus;

		poly_modulus_degree_ = poly_modulus_degree;
		modulus_ = modulus;
		coeffs_.resize(poly_modulus_degree_, value);

		for (size_t i = 0; i < poly_modulus_degree_; i++)
		{
			coeffs_[i] = mod(coeffs_[i], mod_curr);
		}
	}

	Polynomial Polynomial::operator+(const Polynomial& other) const
	{
		if (poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
		{
			throw std::invalid_argument("Polynomials must have matching degree, modulus and reduction polynomial.");
		}

		Polynomial destination(poly_modulus_degree_, modulus_);

		for (uint64_t i = 0; i < poly_modulus_degree_; i++)
		{
			destination.coeffs_[i] = add_mod_safe(coeffs_[i], other.coeffs_[i], modulus_);
		}

		return destination;
	}

	void Polynomial::operator+=(const Polynomial& other)
	{
		if (poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
		{
			throw std::invalid_argument("Polynomials must have matching degree, modulus and reduction polynomial.");
		}

		for (uint64_t i = 0; i < poly_modulus_degree_; i++)
		{
			coeffs_[i] = add_mod_safe(coeffs_[i], other.coeffs_[i], modulus_);
		}
	}

	Polynomial Polynomial::operator-(const Polynomial& other) const
	{
		if (poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
		{
			throw std::invalid_argument("Polynomials must have matching degree, modulus and reduction polynomial.");
		}

		Polynomial destination(poly_modulus_degree_, modulus_);

		for (uint64_t i = 0; i < poly_modulus_degree_; i++)
		{
			destination.coeffs_[i] = add_mod_safe(coeffs_[i], negate_mod_safe(other.coeffs_[i], modulus_), modulus_);
		}

		return destination;
	}

	void Polynomial::operator-=(const Polynomial& other)
	{
		if (poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
		{
			throw std::invalid_argument("Polynomials must have matching degree, modulus and reduction polynomial.");
		}

		for (uint64_t i = 0; i < poly_modulus_degree_; i++)
		{
			coeffs_[i] = add_mod_safe(coeffs_[i], negate_mod_safe(other.coeffs_[i], modulus_), modulus_);
		}
	}

	Polynomial Polynomial::operator-() const
	{
		Polynomial destination(poly_modulus_degree_, modulus_);

		for (uint64_t i = 0; i < poly_modulus_degree_; i++)
		{
			destination.coeffs_[i] = negate_mod_safe(coeffs_[i], modulus_);
		}

		return destination;
	}


	Polynomial Polynomial::operator*(const Polynomial& other) const
	{
		if (poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
		{
			throw std::invalid_argument("Polynomials must have matching degree, modulus and reduction polynomial.");
		}

		Polynomial destination(static_cast<uint64_t>(2) * poly_modulus_degree_ - static_cast<uint64_t>(1), modulus_);

		for (uint64_t i = 0; i < poly_modulus_degree_; ++i)
		{
			for (uint64_t j = 0; j < poly_modulus_degree_; ++j)
			{
				destination.coeffs_[i + j] = add_mod_safe(destination.coeffs_[i + j], mul_mod_safe(coeffs_[i], other.coeffs_[j], modulus_), modulus_);
			}
		}

		uint64_t deg = poly_modulus_degree_;

		for (uint64_t i = deg; i < destination.poly_modulus_degree_; i++)
		{
			if (destination.coeffs_[i] != 0)
			{
				// R = Z[x] / x^d + 1
				// x^i = x^deg * x^(i-deg) = -1 * x^(i-deg)
				// -1 * x^(i-deg) + x^(i-deg)
				destination.coeffs_[i - deg] = add_mod_safe(destination.coeffs_[i - deg], negate_mod_safe(destination.coeffs_[i], modulus_), modulus_);
				destination.coeffs_[i] = 0;
			}
		}

		destination.poly_modulus_degree_ = poly_modulus_degree_;
		destination.coeffs_.resize(poly_modulus_degree_);

		return destination;
	}

	Polynomial Polynomial::operator*(const uint64_t& other) const
	{
		Polynomial destination(poly_modulus_degree_, modulus_);

		for (uint64_t i = 0; i < poly_modulus_degree_; i++)
		{
			destination.coeffs_[i] = mul_mod_safe(coeffs_[i], other, modulus_);
		}

		return destination;
	}

	void Polynomial::operator*=(const Polynomial& other)
	{
		if (poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
		{
			throw std::invalid_argument("Polynomials must have matching degree, modulus and reduction polynomial.");
		}

		Polynomial destination(static_cast<uint64_t>(2) * poly_modulus_degree_ - static_cast<uint64_t>(1), modulus_);

		for (uint64_t i = 0; i < poly_modulus_degree_; ++i)
		{
			for (uint64_t j = 0; j < poly_modulus_degree_; ++j)
			{
				destination.coeffs_[i + j] = add_mod_safe(destination.coeffs_[i + j], mul_mod_safe(coeffs_[i], other.coeffs_[j], modulus_), modulus_);
			}
		}

		uint64_t deg = poly_modulus_degree_;

		for (uint64_t i = deg; i < destination.poly_modulus_degree_; i++)
		{
			if (destination.coeffs_[i] != 0)
			{
				// R = Z[x] / x^d + 1
				// x^i = x^deg * x^(i-deg) = -1 * x^(i-deg)
				// -1 * x^(i-deg) + x^(i-deg)
				destination.coeffs_[i - deg] = add_mod_safe(destination.coeffs_[i - deg], negate_mod_safe(destination.coeffs_[i], modulus_), modulus_);
				destination.coeffs_[i] = 0;
			}
		}

		for (uint64_t i = 0; i < poly_modulus_degree_; ++i)
		{
			coeffs_[i] = destination.coeffs_[i];
		}
	}

	void Polynomial::operator*=(const uint64_t& other)
	{
		for (uint64_t i = 0; i < poly_modulus_degree_; i++)
		{
			coeffs_[i] = mul_mod_safe(coeffs_[i], other, modulus_);
		}
	}
}