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

/*!\file DataOutputStream.h
 * \ingroup CXX_IO_m
 */

#ifndef _CLASS_DATAOUTPUTSTREAM_H
#define _CLASS_DATAOUTPUTSTREAM_H

#ifdef __cplusplus

#include "beecrypt/c++/mutex.h"
using beecrypt::mutex;
#include "beecrypt/c++/io/DataOutput.h"
using beecrypt::io::DataOutput;
#include "beecrypt/c++/io/FilterOutputStream.h"
using beecrypt::io::FilterOutputStream;

#include <unicode/ucnv.h>

namespace beecrypt {
	namespace io {
		/*!\ingroup CXX_LANG_m
		 */
		class BEECRYPTCXXAPI DataOutputStream : public FilterOutputStream, public DataOutput
		{
		private:
			mutex _lock;
			UConverter* _utf;

		protected:
			size_t written;

		public:
			DataOutputStream(OutputStream& out);
			virtual ~DataOutputStream();

			size_t size() const throw ();

			virtual void write(byte b) throw (IOException);
			virtual void write(const byte* data, size_t offset, size_t length) throw (IOException);
			virtual void write(const bytearray& b) throw (IOException);
			virtual void writeBoolean(bool v) throw (IOException);
			virtual void writeByte(byte v) throw (IOException);
			virtual void writeChar(javaint v) throw (IOException);
			virtual void writeChars(const String& s) throw (IOException);
			virtual void writeInt(javaint v) throw (IOException);
			virtual void writeLong(javalong v) throw (IOException);
			virtual void writeShort(javashort v) throw (IOException);
			virtual void writeUTF(const String& str) throw (IOException);
		};
	}
}

#endif

#endif
