/*
 * Copyright (c) 2004 Beeyond Software Holding BV
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*!\file DSAKeyPairGenerator.h
 * \ingroup CXX_PROVIDER_m
 */

#ifndef _CLASS_DSAKEYPAIRGENERATOR_H
#define _CLASS_DSAKEYPAIRGENERATOR_H

#ifdef __cplusplus

#include "beecrypt/c++/security/KeyPairGeneratorSpi.h"
using beecrypt::security::KeyPairGeneratorSpi;
#include "beecrypt/c++/security/SecureRandom.h"
using beecrypt::security::SecureRandom;
#include "beecrypt/c++/security/spec/DSAParameterSpec.h"
using beecrypt::security::spec::DSAParameterSpec;

namespace beecrypt {
	namespace provider {
		class DSAKeyPairGenerator : public beecrypt::security::KeyPairGeneratorSpi
		{
		private:
			size_t _size;
			DSAParameterSpec* _spec;
			SecureRandom* _srng;

			KeyPair* genpair(randomGeneratorContext*);

		protected:
			virtual KeyPair* engineGenerateKeyPair();

			virtual void engineInitialize(const AlgorithmParameterSpec&, SecureRandom*) throw (InvalidAlgorithmParameterException);
			virtual void engineInitialize(size_t, SecureRandom*) throw (InvalidParameterException);

		public:
			DSAKeyPairGenerator();
			virtual ~DSAKeyPairGenerator();
		};
	}
}

#endif

#endif
