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
 * A AVAValueConverter that converts a IA5String attribute to a DerValue
 * and vice versa. An example an attribute that is a IA5String string is "E".
 *
 * @see AVAValueConverter
 *
 * @author Lily Hsiao, Slava Galperin at Netscape Communications, Inc.
 */

public class IA5StringConverter implements AVAValueConverter {
    // public constructors

    /*
     * Contructs a IA5String Converter.
     */
    public IA5StringConverter() {
    }

    /*
     * Converts a string with ASN.1 IA5String characters to a DerValue.
     *
     * @param valueString 	a string with IA5String characters.
     *
     * @return			a DerValue.
     *
     * @exception IOException	if a IA5String encoder is not
     *				available for the conversion.
     */
    public DerValue getValue(String valueString)
            throws IOException {
        return getValue(valueString, null);
    }

    public DerValue getValue(String valueString, byte[] tags) throws IOException {
        try {
            CharsetEncoder encoder = ASN1CharStrConvMap.getDefault().getEncoder(DerValue.tag_IA5String);
            if (encoder == null)
                throw new IOException("No encoder for IA5String");

            CharBuffer charBuffer = CharBuffer.wrap(valueString.toCharArray());
            ByteBuffer byteBuffer = encoder.encode(charBuffer);

            return new DerValue(DerValue.tag_IA5String,
                    byteBuffer.array(), byteBuffer.arrayOffset(), byteBuffer.limit());

        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Invalid IA5String AVA Value string");
        }
    }

    /*
     * Converts a BER encoded value of IA5String to a DER encoded value.
     * Checks if the BER encoded value is a IA5String.
     * NOTE only DER encoding is currently supported on for the BER
     * encoded value.
     *
     * @param berStream 	a byte array of the BER encoded value.
     *
     * @return 			a DerValue.
     *
     * @exception IOException   if the BER value cannot be converted
     *				to a IA5String DER value.
     */
    public DerValue getValue(byte[] berStream)
            throws IOException {
        DerValue value = new DerValue(berStream);
        if (value.tag == DerValue.tag_IA5String)
            return value;
        if (value.tag == DerValue.tag_PrintableString)
            return value;
        throw new IOException("Invalid IA5String AVA Value.");
    }

    /*
     * Converts a DerValue of IA5String to a java string with IA5String
     * characters.
     *
     * @param avaValue 	a DerValue.
     *
     * @return 		a string with IA5String characters.
     *
     * @exception IOException 	if the DerValue is not a IA5String i.e.
     *				The DerValue cannot be converted to a string
     *				with IA5String characters.
     */
    public String getAsString(DerValue avaValue)
            throws IOException {
        if (avaValue.tag == DerValue.tag_IA5String)
            return avaValue.getIA5String();
        if (avaValue.tag == DerValue.tag_PrintableString)
            return avaValue.getPrintableString();
        throw new IOException("Invalid IA5String AVA Value.");
    }

}
