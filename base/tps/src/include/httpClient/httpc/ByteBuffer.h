/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 */
/** BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifndef __BYTE_BUFFER_H
#define __BYTE_BUFFER_H

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

/**
 * ByteBuffer.h	1.000 06/12/2002
 * 
 * A byte buffer class
 *
 * @author  Surendra Rajam
 * @version 1.000, 06/12/2002
 */

#define max(a,b)    (((a) > (b)) ? (a) : (b))
#define min(a,b)    (((a) < (b)) ? (a) : (b))

typedef unsigned char Byte;

class EXPORT_DECL ByteBuffer {
public:
	/**
	 * Constructor
	 */
	ByteBuffer();

	/**
	 * Destructor
	 */
	virtual ~ByteBuffer();

public:
	/**
	 * Reads a single byte from the buffer
	 * 
	 * @param	b	byte returned
	 * @return	0 on success
	 */
	int GetByte(Byte* b);

	/**
	 * Reads a number of bytes as specified by size from the buffer
	 * 
	 * @param	size	bytes to read
	 * @param	buf		bytes read
	 * @return	0 on success
	 */
	int GetBytes(int size, Byte* buf);

	/**
	 * Reads a short value from the buffer
	 * 
	 * @param	s	a short value
	 * @return	0 on success
	 */
	int GetShort(unsigned short* s);

	/**
	 * Reads a integer value from the buffer
	 * 
	 * @param	i	a integer value
	 * @return	0 on success
	 */
	int GetInt(unsigned int* i);

	/**
	 * Reads a string of given length from the buffer
	 * 
	 * @param	len		length of the string
	 * @param	str		string value
	 * @return	0 on success
	 */
	int GetString(int len, char* str);

	/**
	 * Writes a single byte to the buffer
	 * 
	 * @param	b	byte to set
	 * @return	0 on success
	 */
	int SetByte(Byte b);

	/**
	 * Writes a number of bytes as specified by size to the buffer
	 * 
	 * @param	size	number of bytes
	 * @param	buf		bytes to write
	 * @return	0 on success
	 */
	int SetBytes(int size, Byte* buf);

	/**
	 * Writes a short value to the buffer
	 * 
	 * @param	s	a short value
	 * @return	0 on success
	 */
	int SetShort(unsigned short s);

	/**
	 * Writes an integer value to the buffer
	 * 
	 * @param	i	an integer value
	 * @return	0 on success
	 */
	int SetInt(unsigned int i);

	/**
	 * Writes a string to the buffer
	 * 
	 * @param	str		a string to write
	 * @return	0 on success
	 */
	int SetString(char* str);

	/**
	 * Gets the current position in the buffer
	 * 
	 * @param	pos		position in the buffer
	 * @return	0 on success
	 */
	int GetPosition(unsigned long* pos);

	/**
	 * Sets the pointer to the position specified by pos in the buffer
	 * 
	 * @param	pos		position to be set in the buffer
	 * @return	0 on success
	 */
	int SetPosition(unsigned long pos);

	/**
	 * Gets total number of bytes in the buffer
	 * 
	 * @param	total		total number of bytes
	 * @return	0 on success
	 */
	int GetTotalBytes(unsigned long* total);

    /**
     * Dumps the buffer to the debug log
     *
     * @param logLevel Lowest debug level for which the log should be dumped
     */
	void Dump(int logLevel);

private:
	int SetTotalBytes(unsigned long size, unsigned long allocUnit);
	int ValidateBuffer(unsigned long increment);

private:
	Byte* m_buffer;
    Byte* m_bufferEnd;
    Byte* m_bufPtr;
    Byte* m_maxPtr;
};

#endif // __BYTE_BUFFER_H

