#pragma once

#include <stdint.h>
#include <vector>

namespace fheprac
{
	class Polynomial
	{
	public:
		Polynomial();

		Polynomial(const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value = 0);

		uint64_t get(const size_t index) const;

		const std::vector<uint64_t>& get() const;

		void set(const size_t index, const uint64_t value);

		void set(const std::vector<uint64_t>& coeffients);

		uint64_t poly_modulus_degree() const;

		uint64_t modulus() const;

		void assign(const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value = 0);

		void reset(const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value = 0);

		void reset_unsafe(const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value = 0);

		Polynomial operator+(const Polynomial& other) const;

		void operator+=(const Polynomial& other);

		Polynomial operator-(const Polynomial& other) const;

		void operator-=(const Polynomial& other);

		Polynomial operator-() const;

		Polynomial operator*(const Polynomial& other) const;

		Polynomial operator*(const uint64_t& other) const;

		void operator*=(const Polynomial& other);

		void operator*=(const uint64_t& other);

	private:
		std::vector<uint64_t> coeffs_;

		uint64_t poly_modulus_degree_;

		uint64_t modulus_;
	};
}