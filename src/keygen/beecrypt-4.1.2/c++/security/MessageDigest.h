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

/*!\file MessageDigest.h
 * \ingroup CXX_SECURITY_m
 */

#ifndef _CLASS_MESSAGEDIGEST_H
#define _CLASS_MESSAGEDIGEST_H

#include "beecrypt/api.h"

#ifdef __cplusplus

#include "beecrypt/c++/lang/Object.h"
using beecrypt::lang::Object;
#include "beecrypt/c++/security/MessageDigestSpi.h"
using beecrypt::security::MessageDigestSpi;
#include "beecrypt/c++/security/Provider.h"
using beecrypt::security::Provider;
#include "beecrypt/c++/security/NoSuchAlgorithmException.h"
using beecrypt::security::NoSuchAlgorithmException;
#include "beecrypt/c++/security/NoSuchProviderException.h"
using beecrypt::security::NoSuchProviderException;

namespace beecrypt {
	namespace security {
		/*!\ingroup CXX_SECURITY_m
		 */
		class BEECRYPTCXXAPI MessageDigest : public beecrypt::lang::Object
		{
		public:
			static MessageDigest* getInstance(const String& algorithm) throw (NoSuchAlgorithmException);
			static MessageDigest* getInstance(const String& algorithm, const String& provider) throw (NoSuchAlgorithmException, NoSuchProviderException);
			static MessageDigest* getInstance(const String& algorithm, const Provider& provider) throw (NoSuchAlgorithmException);

		private:
			MessageDigestSpi* _mspi;
			const Provider*   _prov;
			String            _algo;

		protected:
			MessageDigest(MessageDigestSpi* spi, const Provider* provider, const String& algorithm);

		public:
			virtual ~MessageDigest();

			virtual MessageDigest* clone() const throw (CloneNotSupportedException);

			const bytearray& digest();
			const bytearray& digest(const bytearray& b);
			size_t digest(byte* data, size_t offset, size_t length) throw (ShortBufferException);
			size_t getDigestLength();
			void reset();
			void update(byte b);
			void update(const byte* data, size_t offset, size_t length);
			void update(const bytearray& b);

			const String& getAlgorithm() const throw ();
			const Provider& getProvider() const throw ();
		};
	}
}

#endif

#endif
