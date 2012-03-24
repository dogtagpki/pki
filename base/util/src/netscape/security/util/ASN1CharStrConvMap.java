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

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Maps a ASN.1 character string type to a charset encoder and decoder.
 * The converter is used to convert a DerValue of a ASN.1 character string type
 * from bytes to unicode characters and vice versa.
 * 
 * <p>
 * A global default ASN1CharStrConvMap is created when the class is initialized. The global default map is extensible.
 * 
 * @author Lily Hsiao
 * @author Slava Galperin
 * 
 */

public class ASN1CharStrConvMap {
    // public constructors

    /**
     * Constructs a ASN1CharStrConvMap.
     */
    public ASN1CharStrConvMap() {
    }

    /**
     * Get an encoder for the specified DER tag.
     * 
     * @param tag A DER tag of a ASN.1 character string type,
     *            for example DerValue.tag_PrintableString.
     * 
     * @return An encoder for the DER tag.
     */
    public CharsetEncoder getEncoder(byte tag) {
        Charset charset = charsets.get(tag);
        if (charset == null)
            return null;
        return charset.newEncoder();
    }

    /**
     * Get a decoder for the given DER tag.
     * 
     * @param tag A DER tag of a ASN.1 character string type,
     *            for example DerValue.tag_PrintableString.
     * 
     * @return A decoder for the DER tag.
     */
    public CharsetDecoder getDecoder(byte tag) {
        Charset charset = charsets.get(tag);
        if (charset == null)
            return null;
        return charset.newDecoder();
    }

    /**
     * Add a tag-charset entry in the map.
     * 
     * @param tag A DER tag of a ASN.1 character string type,
     *            ex. DerValue.tag_IA5String
     * @param charset A charset for the tag.
     */
    public void addEntry(byte tag, Charset charset) {

        Charset currentCharset = charsets.get(tag);

        if (currentCharset != null) {
            if (currentCharset != charset) {
                throw new IllegalArgumentException(
                        "a DER tag to converter entry already exists.");
            } else {
                return;
            }
        }

        charsets.put(tag, charset);
    }

    /**
     * Get an iterator of all tags in the map.
     * 
     * @return An Iterator of DER tags in the map as Bytes.
     */
    public Iterator<Byte> getTags() {
        return charsets.keySet().iterator();
    }

    // static public methods.

    /**
     * Get the global ASN1CharStrConvMap.
     * 
     * @return The global default ASN1CharStrConvMap.
     */
    static public ASN1CharStrConvMap getDefault() {
        return defaultMap;
    }

    /**
     * Set the global default ASN1CharStrConvMap.
     * 
     * @param newDefault The new default ASN1CharStrConvMap.
     */
    static public void setDefault(ASN1CharStrConvMap newDefault) {
        if (newDefault == null)
            throw new IllegalArgumentException(
                    "Cannot set a null default Der Tag Converter map");
        defaultMap = newDefault;
    }

    // private methods and variables.

    private Map<Byte, Charset> charsets = new HashMap<Byte, Charset>();

    private static ASN1CharStrConvMap defaultMap;

    /**
     * Create the default converter map on initialization
     */
    static {
        ASN1CharsetProvider provider = new ASN1CharsetProvider();

        defaultMap = new ASN1CharStrConvMap();
        defaultMap.addEntry(DerValue.tag_PrintableString,
                provider.charsetForName("ASN.1-Printable"));
        defaultMap.addEntry(DerValue.tag_VisibleString,
                provider.charsetForName("ASN.1-Printable"));
        defaultMap.addEntry(DerValue.tag_IA5String,
                provider.charsetForName("ASN.1-IA5"));
        defaultMap.addEntry(DerValue.tag_BMPString,
                Charset.forName("UnicodeBig"));
        defaultMap.addEntry(DerValue.tag_UniversalString,
                provider.charsetForName("ASN.1-Universal"));
        // XXX this is an oversimplified implementation of T.61 strings, it
        // doesn't handle all cases
        defaultMap.addEntry(DerValue.tag_T61String,
                Charset.forName("ISO-8859-1"));
        // UTF8String added to ASN.1 in 1998
        defaultMap.addEntry(DerValue.tag_UTF8String,
                Charset.forName("UTF-8"));
        defaultMap.addEntry(DerValue.tag_GeneralString,
                Charset.forName("UTF-8"));
    };

};
