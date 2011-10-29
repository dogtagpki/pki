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

import java.io.*;

import netscape.security.util.DerValue;

/**
 * Interface for classes that convert a attribute value string to a 
 * DER encoded ASN.1 value and vice versa.
 * The converters are associated with attribute types, such as 
 * directory string, ia5string, etc. 
 * 
 * <P>For example, to convert a string, such as an organization name for the 
 * "O" attribute to a DerValue, the "O" attribute is mapped to the 
 * DirStrConverter which is used to convert the organization name to a 
 * DER encoded Directory String which is a DerValue of a ASN.1 PrintableString, 
 * T.61String or UniversalString for the organization name.
 *
 * @author Lily Hsiao, Slava Galperin at Netscape Communications, Inc.
 */

public interface AVAValueConverter
{
    /**
     * Converts a string to a DER encoded attribute value.
     * 
     * @param valueString 	An AVA value string not encoded in any form.
     * 
     * @return 			A DerValue object. 
     *
     * @exception IOException   if an error occurs during the conversion.
     */
    public DerValue getValue(String valueString) 
	throws IOException;


    /**
     * Converts a string to a DER encoded attribute value. 
     * Specify the order of DER tags to use if more than one encoding is 
     * possible. Currently Directory Strings can have different order 
     * for backwards compatibility. By 2003 all should be UTF8String.
     * 
     * @param valueString 	An AVA value string not encoded in any form.
     * 
     * @return 			A DerValue object. 
     *
     * @exception IOException   if an error occurs during the conversion.
     */
    public DerValue getValue(String valueString, byte[] tags) 
	throws IOException;

    /**
     * Converts a BER encoded value to a DER encoded attribute value.
     * 
     * @param berStream 	A byte array of the BER encoded AVA value.
     * @return 			A DerValue object. 
     */
    public DerValue getValue(byte[] berStream) 
	throws IOException; 

    /**
     * Converts a DER encoded value to a string, not encoded in any form.
     * 
     * @param avaValue 	A DerValue object.
     *
     * @return 		A string for the value or null if it can't be converted.
     *
     * @exception IOException if an error occurs during the conversion.
     */
    public String getAsString(DerValue avaValue) 
	throws IOException;
}
