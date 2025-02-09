#pragma once

#include "context.h"
#include "plaintext.h"

namespace fheprac
{
	class Encoder
	{
	public:
		Encoder(const Context& context);

		void encode(const std::vector<int64_t>& message, Plaintext& destination) const;

		void decode(const Plaintext& plaintext, std::vector<int64_t>& destination) const;

	private:
		Context context_;
	};
}