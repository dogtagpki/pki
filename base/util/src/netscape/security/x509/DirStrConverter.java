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
 * A DirStrConverter converts a string to a DerValue of ASN.1 Directory String,
 * which is a CHOICE of Printable (subset of ASCII), T.61 (Teletex) or
 * Universal String (UCS-4), and vice versa.
 *
 * <p>
 * The string to DerValue conversion is done as follows. If the string has only PrintableString characters it is
 * converted to a ASN.1 Printable String using the PrintableString encoder from the global default ASN1CharStrConvMap.
 * If it has only characters covered in the PrintableString or T.61 character set it is converted to a ASN.1 T.61 string
 * using the T.61 encoder from the ASN1CharStrCovnMap. Otherwise it is converted to a ASN.1 UniversalString (UCS-4
 * character set) which covers all characters.
 *
 * @see AVAValueConverter
 * @see ASN1CharStrConvMap
 *
 * @author Lily Hsiao, Slava Galperin at Netscape Communications, Inc.
 */

public class DirStrConverter implements AVAValueConverter {
    // public constructors

    /**
     * Constructs a DirStrConverter.
     */
    public DirStrConverter() {
    }

    // public functions

    /**
     * Converts a string to a DER encoded ASN1 Directory String, which is a
     * CHOICE of PrintableString, T.61String or UniversalString.
     * The string is taken as is i.e. should not be in Ldap DN string syntax.
     *
     * @param ds a string representing a directory string value.
     *
     * @return a DerValue
     *
     * @exception IOException if the string cannot be converted, such as
     *                when a UniversalString encoder
     *                isn't available and the string contains
     *                characters covered only in the universal
     *                string (or UCS-4) character set.
     */
    private static byte[] DefEncodingOrder =
            new byte[] {
                    DerValue.tag_UTF8String,
                    DerValue.tag_PrintableString,
                    DerValue.tag_T61String,
                    DerValue.tag_UniversalString
    };

    public static synchronized void
            setDefEncodingOrder(byte[] defEncodingOrder) {
        DefEncodingOrder = defEncodingOrder;
    }

    public DerValue getValue(String ds)
            throws IOException {
        return getValue(ds, DefEncodingOrder);
    }

    /**
     * Like getValue(String) with specified DER tags as encoding order.
     */
    public DerValue getValue(String valueString, byte[] tags) throws IOException {
        // try to convert to printable, then t61 the universal -
        // i.e. from minimal to the most liberal.

        if (tags == null || tags.length == 0)
            tags = DefEncodingOrder;

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
                "Cannot convert the directory string value to a ASN.1 type");
    }

    /**
     * Creates a DerValue from a BER encoded value, obtained from for example
     * a attribute value in octothorpe form of a Ldap DN string.
     * Checks if the BER encoded value is legal for a DirectoryString.
     *
     * NOTE: currently only supports DER encoding for the BER encoded value.
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
        DerValue value = new DerValue(berByteStream);

        /*
        if (value.tag != DerValue.tag_PrintableString &&
            value.tag != DerValue.tag_T61String &&
            value.tag != DerValue.tag_UniversalString)
        	throw new IOException("Invalid Directory String AVA Value");
        */

        return value;
    }

    /**
     * Converts a DerValue to a string.
     * The string is not in any syntax, such as RFC1779 string syntax.
     *
     * @param avaValue a DerValue
     * @return a string if the value can be converted.
     * @exception IOException if a decoder needed for the
     *                conversion is not available.
     */
    public String getAsString(DerValue avaValue)
            throws IOException {
        /*
        if (avaValue.tag != DerValue.tag_PrintableString &&
            avaValue.tag != DerValue.tag_BMPString &&
            avaValue.tag != DerValue.tag_UniversalString &&
                avaValue.tag != DerValue.tag_T61String)
            throw new IllegalArgumentException(
        	"Invalid Directory String value");
        // NOTE will return null if a decoder is not available.
        */
        return avaValue.getASN1CharString();
    }

}
