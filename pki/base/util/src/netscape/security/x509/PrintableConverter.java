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
 * A AVAValueConverter that converts a Printable String attribute to a DerValue 
 * and vice versa. An example an attribute that is a printable string is "C".
 *
 * @see ASN1CharStrConvMap
 * @see AVAValueConverter
 *
 * @author Lily Hsiao, Slava Galperin at Netscape Communications, Inc.
 */

public class PrintableConverter implements AVAValueConverter
{
    // public constructors.

    public PrintableConverter()
    {
    }

    /**
     * Converts a string with ASN.1 Printable characters to a DerValue.
     * 
     * @param valueString 	a string with Printable characters.
     * 
     * @return			a DerValue. 
     * 
     * @exception IOException	if a Printable encoder is not
     *				available for the conversion.
     */
    public DerValue getValue(String valueString)
	throws IOException
    {
	return getValue(valueString, null);
    }

    public DerValue getValue(String valueString, byte[] tags) throws IOException {
        try {
            CharsetEncoder encoder = ASN1CharStrConvMap.getDefault().getEncoder(DerValue.tag_PrintableString);
            if (encoder == null) throw new IOException("No encoder for printable");

            CharBuffer charBuffer = CharBuffer.wrap(valueString.toCharArray());
            ByteBuffer byteBuffer = encoder.encode(charBuffer);

            return new DerValue(DerValue.tag_PrintableString,
                byteBuffer.array(), byteBuffer.arrayOffset(), byteBuffer.limit());

        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Invalid Printable String AVA Value", e);
        }
    }

    /**
     * Converts a BER encoded value of PrintableString to a DER encoded value.
     * Checks if the BER encoded value is a PrintableString.
     * NOTE only DER encoded values are currently accepted on input.
     * 
     * @param berStream 	A byte array of the BER encoded value.
     * 
     * @return 			A DerValue. 
     * 
     * @exception IOException   if the BER value cannot be converted to a 
     *				PrintableString DER value.
     */
    public DerValue getValue(byte[] berStream)
	throws IOException
    {
	DerValue value = new DerValue(berStream);
	if (value.tag != DerValue.tag_PrintableString)
	    throw new IOException("Invalid Printable String AVA Value");
	return value;
    }

    /**
     * Converts a DerValue of PrintableString to a java string with 
     * PrintableString characters. 
     * 
     * @param avaValue 	a DerValue.
     *
     * @return 		a string with PrintableString characters.
     *
     * @exception IOException 	if the DerValue is not a PrintableString i.e.
     *				The DerValue cannot be converted to a string
     *				with PrintableString characters.
     */
    public String getAsString(DerValue avaValue)
	throws IOException
    {
	return avaValue.getPrintableString();
    }

}
