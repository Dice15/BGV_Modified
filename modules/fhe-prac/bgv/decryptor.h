#pragma once

#include "context.h"
#include "secretkey.h"
#include "plaintext.h"
#include "ciphertext.h"

namespace fheprac
{
	class Decryptor
	{
	public:
		Decryptor(const Context& context, const SecretKey& secretkey);

		void decrypt(const Ciphertext& ciphertext, Plaintext& destination) const;

	private:
		Context context_;

		SecretKey sk_;
	};
}