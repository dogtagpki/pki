// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#ifndef BUFFER_H
#define BUFFER_H

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

#include <stdio.h>
#include "main/Base.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * This class represents a byte array.
 */
class Buffer {

  private:
    BYTE *buf;
    unsigned int len;
    unsigned int res;

  public:
    /**
     * Creates an empty Buffer.
     */
    TPS_PUBLIC Buffer() : buf(0), len(0), res(0) { }

    /**
     * Creates a Buffer of length 'len', with each byte initialized to 'b'.
     */
    TPS_PUBLIC Buffer(unsigned int len, BYTE b);

    /**
     * Creates a Buffer of length 'len', initialized to zeroes.
     */
    TPS_PUBLIC explicit Buffer(unsigned int len);

    /**
     * Creates a Buffer of length 'len', initialized from 'buf'. 'buf' must
     * contain at least 'len' bytes.
     */
    TPS_PUBLIC Buffer(const BYTE* buf, unsigned int len);

    /**
     * Copy constructor.
     */
    TPS_PUBLIC Buffer(const Buffer& cpy);

    /**
     * Destructor.
     */
    TPS_PUBLIC ~Buffer();

    /**
     * Assignment operator.
     */
    TPS_PUBLIC Buffer& operator=(const Buffer& cpy);

    /**
     * Returns true if the two buffers are the same length and contain
     * the same byte at each offset.
     */
    TPS_PUBLIC bool operator==(const Buffer& cmp) const;

    /**
     * Returns ! operator==(cmp).
     */
    TPS_PUBLIC bool operator!=(const Buffer& cmp) const { return ! (*this == cmp); }

    /**
     * Concatenation operator.
     */
    TPS_PUBLIC Buffer operator+(const Buffer&addend) const;

    /**
     * Append operators.
     */
    TPS_PUBLIC Buffer& operator+=(const Buffer&addend);
    TPS_PUBLIC Buffer& operator+=(BYTE b);

    /**
     * Returns a pointer into the Buffer. This also enables the subscript
     * operator, so you can say, for example, 'buf[4] = b' or 'b = buf[4]'.
     */
    TPS_PUBLIC operator BYTE*() { return buf; }
    TPS_PUBLIC operator const BYTE*() const { return buf; }

    /**
     * The length of buffer. The actual amount of space allocated may be
     * higher--see capacity().
     */
    TPS_PUBLIC unsigned int size() const { return len; }

    /**
     * The amount of memory allocated for the buffer. This is the maximum
     * size the buffer can grow before it needs to allocate more memory.
     */
    TPS_PUBLIC unsigned int capacity() const { return res; }

    /**
     * Sets all bytes in the buffer to 0.
     */
    TPS_PUBLIC void zeroize();

    /**
     * Changes the length of the Buffer. If 'newLen' is shorter than the
     * current length, the Buffer is truncated. If 'newLen' is longer, the
     * new bytes are initialized to 0. If 'newLen' is the same as size(),
     * this is a no-op.
     */
    TPS_PUBLIC void resize(unsigned int newLen);

    /**
     * Ensures that capacity() is at least 'reserve'. Allocates more memory
     * if necessary. If 'reserve' is <= capacity(), this is a no-op.
     * Does not affect size().
     */
    TPS_PUBLIC void reserve(unsigned int reserve);

    /**
     * Returns a new Buffer that is a substring of this Buffer, starting
     * from offset 'start' and continuing for 'len' bytes. This Buffer
     * must have size() >= (start + len).
     */
    TPS_PUBLIC Buffer substr(unsigned int start, unsigned int len) const;

    /**
     * Replaces bytes i through i+n in this Buffer using the values in 'cpy'.
     * This Buffer is resized if necessary. The 'cpy' argument can be a
     * Buffer.
     */
    TPS_PUBLIC void replace(unsigned int i, const BYTE* cpy, unsigned int n);

    TPS_PUBLIC unsigned char* getBuf();
    TPS_PUBLIC unsigned int getLen();

    /**
     * returns a hex version of the buffer
     */
    TPS_PUBLIC char *toHex();

    /**
     * Dumps this Buffer to the given file as formatted hex: 16 bytes per
     * line, separated by spaces.
     */
    TPS_PUBLIC void dump(FILE* file) const;

    /**
     * returns a null-terminated string of the buf.
     * should be called only by callers that are certain that buf
     * is entirely representable by printable characters and wants
     * a string instead.
     */
    TPS_PUBLIC char *string();

    /**
     * dump()s this Buffer to stdout.
     */
    TPS_PUBLIC void dump() const;

};

#endif
