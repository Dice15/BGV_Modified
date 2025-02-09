#pragma once

#include "context.h"
#include "publickey.h"
#include "plaintext.h"
#include "ciphertext.h"

namespace fheprac
{
	class Encryptor
	{
	public:
		Encryptor(const Context& context, const PublicKey &publickey);

		void encrypt(const Plaintext& plaintext, Ciphertext& destination) const;

	private:
		Context context_;

		PublicKey pk_;
	};
}