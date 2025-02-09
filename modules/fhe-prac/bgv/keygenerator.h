#pragma once

#include "context.h"
#include "secretkey.h"
#include "publickey.h"
#include "relinkeys.h"
#include "switchkeys.h"

namespace fheprac
{
	class KeyGenerator
	{
	public:
		KeyGenerator(const Context& context);

		SecretKey secret_key() const;

		void create_public_key(PublicKey& destination) const;

		void create_relin_keys(RelinKeys& destination) const;

		void create_switch_keys(const SecretKey& other, SwitchKeys& destination) const;

	private:
		void create_secret_key_internal(SecretKey& destination) const;

		void create_public_key_internal(const uint64_t N, PublicKey& destination) const;

		void create_relin_key_internal(RelinKeys& destination) const;

		void create_switch_keys_internal(const SecretKey& other, SwitchKeys& destination) const;

		SecretKey sk_;

		Context context_;
	};
}