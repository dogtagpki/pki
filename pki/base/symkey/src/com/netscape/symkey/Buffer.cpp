// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <memory.h>
#include <assert.h>
#include <stdio.h>
#include <cstdarg>
#include <string>

#include "Buffer.h"

Buffer::Buffer(const BYTE *buf_, unsigned int len_) : len(len_), res(len_)
{
    buf = new BYTE[len];
    memcpy(buf, buf_, len);
}

Buffer::Buffer(const Buffer& cpy)
{
    buf = 0;
    *this = cpy;
}

Buffer::Buffer(unsigned int len_) : len(len_), res(len_)
{
    buf = new BYTE[res];
    memset(buf, 0, len_);
}

Buffer::Buffer(unsigned int len_, BYTE b) : len(len_), res(len_)
{
    buf = new BYTE[res];
    memset(buf, b, len);
}

Buffer::~Buffer()
{
    delete [] buf;
}

bool
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

Buffer&
Buffer::operator=(const Buffer& cpy)
{
    if( this == &cpy ) return *this;
    len = cpy.len;
    delete [] buf;
    buf = new BYTE[len];
    memcpy(buf, cpy.buf, len);
    res = len;

    return *this;
}

void
Buffer::zeroize()
{
    if( len > 0 ) {
        memset( buf, 0, len );
    }
}

Buffer
Buffer::operator+(const Buffer& addend) const
{
    Buffer result(len + addend.len);
    memcpy(result.buf, buf, len);
    memcpy(result.buf+len, addend.buf, addend.len);
    return result;
}

Buffer&
Buffer::operator+=(const Buffer& addend)
{
    unsigned int oldLen = len;
    resize(len + addend.len);
    memcpy(buf+oldLen, addend.buf, addend.len);
    return *this;
}

Buffer&
Buffer::operator+=(BYTE b)
{
    resize(len+1);
    buf[len-1] = b;
    return *this;
}

void
Buffer::reserve(unsigned int n)
{
    if( n > res ) {
        BYTE *newBuf = new BYTE[n];
        memcpy(newBuf, buf, len);
        delete [] buf;
        buf = newBuf;
        res = n;
    }
}

void
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
        delete [] buf;
        buf = newBuf;
        len = newLen;
        res = newLen;
    }
}

Buffer
Buffer::substr(unsigned int i, unsigned int n) const
{
    assert( i < len  && (i+n) <= len );
    return Buffer( buf+i, n );
}

void
Buffer::replace(unsigned int i, const BYTE* cpy, unsigned int n)
{
    if (len > i+n) {
    resize( len);
    }else {
    resize( i+n );
    }
    memcpy(buf+i, cpy, n);
}

void
Buffer::dump() const
{
    unsigned int i;

    for( i=0; i < len; ++i ) {
        printf("%02x ", buf[i]);
        if( i % 16 == 15 )  printf("\n");
    }
    printf("\n");
}

static const char hextbl[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};
