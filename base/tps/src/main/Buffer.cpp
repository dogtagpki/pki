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

#include <memory.h>
#include <assert.h>
#include <stdio.h>

#include "main/Buffer.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

TPS_PUBLIC Buffer::Buffer(const BYTE *buf_, unsigned int len_) : len(len_), res(len_)
{
    buf = new BYTE[len];
    memcpy(buf, buf_, len);
}

TPS_PUBLIC Buffer::Buffer(const Buffer& cpy)
{
    buf = 0;
    *this = cpy;
}

TPS_PUBLIC Buffer::Buffer(unsigned int len_) : len(len_), res(len_)
{
    buf = new BYTE[res];
    memset(buf, 0, len_);
}

TPS_PUBLIC Buffer::Buffer(unsigned int len_, BYTE b) : len(len_), res(len_)
{
    if (len_ == 0) {
      buf = NULL;
    } else {
      buf = new BYTE[res];
      memset(buf, b, len);
    }
}

TPS_PUBLIC Buffer::~Buffer()
{
    if( buf != NULL ) {
        delete [] buf;
        buf = NULL;
    }
}

TPS_PUBLIC bool
Buffer::operator==(const Buffer& cmp) const
{
    if( len != cmp.len ) return false;
    for( unsigned int i=0; i < len; ++i ) {
        if( buf[i] != cmp.buf[i] ) {
            return false;
        }
    }
    return true;
}

TPS_PUBLIC Buffer&
Buffer::operator=(const Buffer& cpy)
{
    if( this == &cpy ) return *this;
    len = cpy.len;
    if( buf != NULL ) {
        delete [] buf;
        buf = NULL;
    }
    if (cpy.len == 0) {
      buf = NULL;
    } else {
      buf = new BYTE[len];
      memcpy(buf, cpy.buf, len);
    }
    res = len;

    return *this;
}

TPS_PUBLIC void
Buffer::zeroize()
{
    if( len > 0 ) {
        memset( buf, 0, len );
    }
}

TPS_PUBLIC Buffer
Buffer::operator+(const Buffer& addend) const
{
    Buffer result(len + addend.len);
    memcpy(result.buf, buf, len);
    memcpy(result.buf+len, addend.buf, addend.len);
    return result;
}

TPS_PUBLIC Buffer&
Buffer::operator+=(const Buffer& addend)
{
    unsigned int oldLen = len;
    resize(len + addend.len);
    memcpy(buf+oldLen, addend.buf, addend.len);
    return *this;
}

TPS_PUBLIC Buffer&
Buffer::operator+=(BYTE b)
{
    resize(len+1);
    buf[len-1] = b;
    return *this;
}

TPS_PUBLIC void
Buffer::reserve(unsigned int n)
{
    if( n > res ) {
        BYTE *newBuf = new BYTE[n];
        memcpy(newBuf, buf, len);
        if( buf != NULL ) {
            delete [] buf;
            buf = NULL;
        }
        buf = newBuf;
        res = n;
    }
}

TPS_PUBLIC void
Buffer::resize(unsigned int newLen)
{
    if( newLen == len ) {
        return;
    } else if( newLen < len ) {
        len = newLen;
    } else if( newLen <= res ) {
        assert( newLen > len );
        memset(buf+len, 0, newLen-len);
        len = newLen;
    } else {
        assert( newLen > len && newLen > res );
        BYTE *newBuf = new BYTE[newLen];
        memcpy(newBuf, buf, len);
        memset(newBuf+len, 0, newLen-len);
        if( buf != NULL ) {
            delete [] buf;
            buf = NULL;
        }
        buf = newBuf;
        len = newLen;
        res = newLen;
    }
}

TPS_PUBLIC Buffer
Buffer::substr(unsigned int i, unsigned int n) const
{
    assert( i < len  && (i+n) <= len );
    return Buffer( buf+i, n );
}

TPS_PUBLIC void
Buffer::replace(unsigned int i, const BYTE* cpy, unsigned int n)
{
    if (len > i+n) {
    resize( len);
    }else {
    resize( i+n );
    }
    memcpy(buf+i, cpy, n);
}

TPS_PUBLIC void
Buffer::dump() const
{
    unsigned int i;

    for( i=0; i < len; ++i ) {
        printf("%02x ", buf[i]);
        if( i % 16 == 15 )  printf("\n");
    }
    printf("\n");
}

/*
 * if caller knows it's a string, pad with ending 0 and return.
 * note:
 *   It is the caller's responsibility to make sure it's a string.
 *   Memory needs to be released by the caller.
 */
TPS_PUBLIC char *
Buffer::string()
{
    unsigned int i;
    char *s = (char *) PR_Malloc(len+1);
    for (i = 0; i < len; i++) {
      s[i] = buf[i];
    }
    s[i] = '\0';
    return s;
}

TPS_PUBLIC unsigned char*
Buffer::getBuf() {
    return (unsigned char *) buf;
}

TPS_PUBLIC unsigned int
Buffer::getLen() {
    return len;
}

TPS_PUBLIC char *
Buffer::toHex()
{
    unsigned int i;

    char *hx =  (char *)PR_Malloc(1024);
    if (hx == NULL)
	    return NULL;
    for( i=0; i < len; ++i ) {
      PR_snprintf(hx+(i*2),1024-(i*2),"%02x", (unsigned char)buf[i]);
    }

    return hx;
}

static const char hextbl[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};
