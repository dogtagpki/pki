/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */







static char nib2b64[0x40f] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";



static int
ldif_base64_encode_internal( unsigned char *src, char *dst, int srclen, int lenused, int wraplen )
{
    unsigned char   *byte, *stop;
    unsigned char   buf[3];
    char        *out;
    unsigned long   bits;
    int     i, pad, len;

    len = 0;
    out = dst;
    stop = src + srclen;

    /* convert to base 64 (3 bytes => 4 base 64 digits) */
    for ( byte = src; byte < stop - 2; byte += 3 ) {
        bits = (byte[0] & 0xff) << 16;
        bits |= (byte[1] & 0xff) << 8;
        bits |= (byte[2] & 0xff);

        for ( i = 0; i < 4; i++, bits <<= 6 ) {
            if ( wraplen != -1 &&  lenused >= 0 && lenused++ > wraplen ) {
                *out++ = '\n';
                *out++ = ' ';
                lenused = 2;
            }

            /* get b64 digit from high order 6 bits */
            *out++ = nib2b64[ (bits & 0xfc0000L) >> 18 ];
        }
    }
    /* add padding if necessary */
    if ( byte < stop ) {
        for ( i = 0; byte + i < stop; i++ ) {
            buf[i] = byte[i];
        }
        for ( pad = 0; i < 3; i++, pad++ ) {
            buf[i] = '\0';
        }
        byte = buf;
        bits = (byte[0] & 0xff) << 16;
        bits |= (byte[1] & 0xff) << 8;
        bits |= (byte[2] & 0xff);

        for ( i = 0; i < 4; i++, bits <<= 6 ) {
            if ( wraplen != -1 && lenused >= 0 && lenused++ > wraplen ) {
                *out++ = '\n';
                *out++ = ' ';
                lenused = 2;
            }

            if (( i == 3 && pad > 0 ) || ( i == 2 && pad == 2 )) {
                /* Pad as appropriate */
                *out++ = '=';
            } else {
                /* get b64 digit from low order 6 bits */
                *out++ = nib2b64[ (bits & 0xfc0000L) >> 18 ];
            }
        }
    }

    *out = '\0';

    return( out - dst );
}


int
ldif_base64_encode( unsigned char *src, char *dst, int srclen, int lenused )
{
    return ldif_base64_encode_internal( src, dst, srclen, lenused, 200);
}

