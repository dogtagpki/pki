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
package netscape.security.util;

import java.util.*;
import sun.io.*;

/**
 * Maps a ASN.1 character string type to a CharToByte and ByteToChar converter.
 * The converter is used to convert a DerValue of a ASN.1 character string type
 * from bytes to unicode characters and vice versa.
 *
 * <p>A global default ASN1CharStrConvMap is created when the class is
 * initialized. The global default map is extensible.
 *
 * @author Lily Hsiao
 * @author Slava Galperin
 *
 */

public class ASN1CharStrConvMap
{
    // public constructors

    /**
     * Constructs a ASN1CharStrConvMap.
     */
    public ASN1CharStrConvMap()
    {
    }

    /**
     * Get a Character to Byte converter for the specified DER tag.
     *
     * @param tag 	A DER tag of a ASN.1 character string type,
     *			for example DerValue.tag_PrintableString.
     *
     * @return 		A CharToByteConverter for the DER tag.
     *
     * @exception InstantiationException
     *		if error occurs when instantiating the CharToByteConverter.
     * @exception IllegalAccessException
     *		if error occurs when loading the CharToByteConverter class.
     */
    public CharToByteConverter getCBC(byte tag)
	throws IllegalAccessException, InstantiationException
    {
	Byte tagObj = Byte.valueOf(tag);
	CharToByteConverter cbc = null;
	Class cbcClass;
	cbcClass = (Class)tag2CBC.get(tagObj);
	if (cbcClass == null)
	    return null;
	cbc = (CharToByteConverter)cbcClass.newInstance();
	cbc.setSubstitutionMode(false);
	return cbc;
    }

    /**
     * Get a Byte to Character converter for the given DER tag.
     *
     * @param tag 	A DER tag of a ASN.1 character string type,
     *			for example DerValue.tag_PrintableString.
     *
     * @return 		A ByteToCharConverter for the DER tag.
     *
     * @exception InstantiationException
     *		if error occurs when instantiationg the ByteToCharConverter.
     * @exception IllegalAccessException
     *		if error occurs when loading the ByteToCharConverter class.
     */
    public ByteToCharConverter getBCC(byte tag)
	throws IllegalAccessException, InstantiationException
    {
	Byte tagObj = Byte.valueOf(tag);
	ByteToCharConverter bcc = null;
	Class bccClass = (Class)tag2BCC.get(tagObj);
	if (bccClass == null)
	    return null;
	bcc = (ByteToCharConverter)bccClass.newInstance();
	bcc.setSubstitutionMode(false);
	return bcc;
    }

    /**
     * Add a tag-CharToByteConverter-ByteToCharConverter entry in the map.
     *
     * @param tag	A DER tag of a ASN.1 character string type,
     *			ex. DerValue.tag_IA5String
     * @param cbc	A CharToByteConverter for the tag.
     * @param bcc	A ByteToCharConverter for the tag.
     */
    public void addEntry(byte tag, Class cbc, Class bcc)
    {
	Class current_cbc;
	Class current_bcc;
	Byte tagByte = Byte.valueOf(tag);

	current_cbc = (Class)tag2CBC.get(tagByte);
	current_bcc = (Class)tag2BCC.get(tagByte);
	if (current_cbc != null || current_bcc != null)
	{
	    if (current_cbc != cbc || current_bcc != bcc)
	    {
		throw new IllegalArgumentException(
		    "a DER tag to converter entry already exists.");
	    }
	    else {
		return;
	    }
	}
	if (!CharToByteConverter.class.isAssignableFrom(cbc) ||
	    !ByteToCharConverter.class.isAssignableFrom(bcc)) {
	    throw new IllegalArgumentException(
		"arguments not a CharToByteConverter or ByteToCharConverter");
	}
	tag2CBC.put(tagByte, cbc);
	tag2BCC.put(tagByte, bcc);
    }

    /**
     * Get and enumeration of all tags in the map.
     * @return 	An Enumeration of DER tags in the map as Bytes.
     */
    public Enumeration getTags()
    {
	return tag2CBC.keys();
    }

    // static public methods.

    /**
     * Get the global ASN1CharStrConvMap.
     * @return 	The global default ASN1CharStrConvMap.
     */
    static public ASN1CharStrConvMap getDefault()
    {
	return defaultMap;
    }

    /**
     * Set the global default ASN1CharStrConvMap.
     * @param newDefault 	The new default ASN1CharStrConvMap.
     */
    static public void setDefault(ASN1CharStrConvMap newDefault)
    {
	if (newDefault == null)
	    throw new IllegalArgumentException(
	       "Cannot set a null default Der Tag Converter map");
	defaultMap = newDefault;
    }

    // private methods and variables.

    private Hashtable tag2CBC = new Hashtable();
    private Hashtable tag2BCC = new Hashtable();

    private static ASN1CharStrConvMap defaultMap;

    /**
     * Create the default converter map on initialization
     */
    static {
	defaultMap = new ASN1CharStrConvMap();
	defaultMap.addEntry(DerValue.tag_PrintableString,
	    	CharToBytePrintable.class, ByteToCharPrintable.class);
	defaultMap.addEntry(DerValue.tag_VisibleString,
	    	CharToBytePrintable.class, ByteToCharPrintable.class);
	defaultMap.addEntry(DerValue.tag_IA5String,
	    	CharToByteIA5String.class, ByteToCharIA5String.class);
	defaultMap.addEntry(DerValue.tag_BMPString,
	        // Changed by bskim
	    	//sun.io.CharToByteUnicode.class,
	    	//netscape.security.util.ByteToCharUnicode.class);
	    	sun.io.CharToByteUnicodeBig.class,
	    	sun.io.ByteToCharUnicodeBig.class);
	    	// Change end
	defaultMap.addEntry(DerValue.tag_UniversalString,
	    	CharToByteUniversalString.class,
	    	ByteToCharUniversalString.class);
    	// XXX this is an oversimplified implementation of T.61 strings, it
    	// doesn't handle all cases
	defaultMap.addEntry(DerValue.tag_T61String,
	    	latin1CBC.class, latin1BCC.class);
	// UTF8String added to ASN.1 in 1998
	defaultMap.addEntry(DerValue.tag_UTF8String,
	    	CharToByteUTF8.class,
	    	ByteToCharUTF8.class);
	defaultMap.addEntry(DerValue.tag_GeneralString,
	    	CharToByteUTF8.class,
	    	ByteToCharUTF8.class);
    };

};

class latin1CBC extends sun.io.CharToByteISO8859_1 {
	public latin1CBC() {
		super();
		subMode = false;
	}
}

class latin1BCC extends sun.io.ByteToCharISO8859_1 {
	public latin1BCC() {
		super();
		subMode = false;
	}
}


