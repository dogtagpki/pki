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

import netscape.security.util.ASN1CharStrConvMap;
import netscape.security.util.DerValue;
import sun.io.CharToByteConverter;

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
     * @exception IOException	if a Printable CharToByteConverter is not 
     *				available for the conversion.
     */
    public DerValue getValue(String valueString)
	throws IOException
    {
	return getValue(valueString, null);
    }

    public DerValue getValue(String valueString, byte[] encodingOrder)
	throws IOException
    {
	CharToByteConverter printable;
	byte[] bbuf = new byte[valueString.length()];
	try {
	    printable = ASN1CharStrConvMap.getDefault().getCBC(
				DerValue.tag_PrintableString);
	    if (printable == null) {
		throw new IOException("No CharToByteConverter for printable");
	    }
	    printable.convert(valueString.toCharArray(), 0, 
			      valueString.length(), bbuf, 0, bbuf.length);
	}
	catch (java.io.CharConversionException e) {
	    throw new IllegalArgumentException(
			"Invalid Printable String AVA Value");
	}
	catch (InstantiationException e) {
	    throw new IOException("Cannot instantiate CharToByteConverter");
	}
	catch (IllegalAccessException e) {
	    throw new IOException("Cannot load CharToByteConverter");
	}
	return new DerValue(DerValue.tag_PrintableString, bbuf);
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
