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
package netscape.security.x509;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;

import netscape.security.util.ASN1CharStrConvMap;
import netscape.security.util.DerValue;

/**
 * A GenericValueConverter converts a string that is not associated with
 * a particular attribute to a DER encoded ASN.1 character string type.
 * Currently supports PrintableString, IA5String, BMPString T.61String and
 * Universal String.
 * 
 * <p>
 * The conversion is done as follows. An encoder is obtained for the all the character sets from the global default ASN1CharStrConvMap. The encoders are then used to convert the string to the smallest character set first -- printableString. If the string contains characters outside of that character set, it is converted to the next character set -- IA5String character set. If that is not enough it is converted to a BMPString, then Universal String which contains all characters.
 * 
 * @author Lily Hsiao, Slava Galperin at Netscape Communications, Inc.
 * 
 */

public class GenericValueConverter implements AVAValueConverter {
    public GenericValueConverter() {
    }

    /**
     * Converts a string to a DER encoded ASN.1 primtable string, defined here
     * as a PrintableString, IA5String, T.61String, BMPString or
     * UniversalString. The string is not expected to be encoded in any form.
     * 
     * <p>
     * If an encoder is not available for a character set that is needed to convert the string, the string cannot be converted and an IOException is thrown. For example, if the string contains characters outside the PrintableString character and only a PrintableString encoder is available then an IOException is thrown.
     * 
     * @param s A string representing a generic attribute string value.
     * 
     * @return The DER value of the attribute.
     * 
     * @exception IOException if the string cannot be converted, such as
     *                when an encoder needed is
     *                unavailable.
     */
    public DerValue getValue(String s)
            throws IOException {
        return getValue(s, null);
    }

    public DerValue getValue(String valueString, byte[] tags) throws IOException {
        // try to convert to printable, then t61 the universal -
        // i.e. from minimal coverage to the broadest.

        if (tags == null || tags.length == 0)
            tags = DefEncodingTags;

        for (int i = 0; i < tags.length; i++) {
            try {
                CharsetEncoder encoder = ASN1CharStrConvMap.getDefault().getEncoder(tags[i]);
                if (encoder == null)
                    continue;

                CharBuffer charBuffer = CharBuffer.wrap(valueString.toCharArray());
                ByteBuffer byteBuffer = encoder.encode(charBuffer);

                return new DerValue(tags[i], byteBuffer.array(), byteBuffer.arrayOffset(), byteBuffer.limit());

            } catch (CharacterCodingException e) {
                continue;
            }
        }

        throw new IOException(
                "Cannot convert the string value to a ASN.1 type");
    }

    /**
     * Creates a DerValue from the byte array of BER encoded value.
     * 
     * NOTE: currently only supports DER encoding (a form of BER) on input .
     * 
     * @param berStream Byte array of a BER encoded value.
     * 
     * @return DerValue object.
     * 
     * @exception IOException If the BER value cannot be converted to a
     *                valid Directory String DER value.
     */
    public DerValue getValue(byte[] berByteStream)
            throws IOException {
        // accepts any tag.
        DerValue value = new DerValue(berByteStream);
        return value;
    }

    /**
     * Converts a DerValue of ASN1 Character string type to a java string
     * (the string is not encoded in any form).
     * 
     * @param avaValue A DerValue
     * @return A string representing the attribute value.
     * @exception IOException if a decoder needed for the
     *                conversion is not available or if BER value
     *                is not one of the ASN1 character string types
     *                here.
     */
    public String getAsString(DerValue avaValue)
            throws IOException {
        return avaValue.getASN1CharString();
    }

    private static byte DefEncodingTags[] = {
            DerValue.tag_PrintableString,
                    DerValue.tag_IA5String,
                    DerValue.tag_BMPString,
                    DerValue.tag_UTF8String,
                    DerValue.tag_T61String,
                    DerValue.tag_UniversalString
             };
}
