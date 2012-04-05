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

import java.util.Enumeration;
import java.util.Hashtable;

import netscape.security.util.ObjectIdentifier;

/**
 * Maps an attribute name in an X500 AVA to its OID and a
 * converter for the attribute type. The converter converts from a string to
 * its DER encoded attribute value. * For example, "CN" maps to its OID of
 * 2.5.4.3 and the Directory String Converter. The Directory String
 * Converter converts from a string to a DerValue with tag Printable, T.61 or
 * UniversalString.
 *
 * @author Lily Hsiao, Slava Galperin at Netscape Communications, Inc.
 *
 */

public class X500NameAttrMap {
    //
    // public constructors.
    //

    /**
     * Construct a X500NameAttrMap.
     */
    public X500NameAttrMap() {
    }

    //
    // public get methods.
    //

    /**
     * Get the attribute name (keyword) of the specified OID.
     *
     * @param oid An ObjectIdentifier
     *
     * @return An attribute name (keyword string) for the OID.
     */
    public String getName(ObjectIdentifier oid) {
        // XXX assert oid != null
        return oid2Name.get(oid);
    }

    /**
     * Get the ObjectIdentifier of the attribute name.
     *
     * @param name An attribute name (string of ascii characters)
     *
     * @return An ObjectIdentifier for the attribute.
     */
    public ObjectIdentifier getOid(String name) {
        // XXX assert name != null
        return name2OID.get(name.toUpperCase());
    }

    /**
     * Get the Attribute Value Converter for the specified attribute name.
     *
     * @param name An attribute name
     *
     * @return An attribute value converter for the attribute name
     */
    public AVAValueConverter getValueConverter(String name) {
        ObjectIdentifier oid =
                name2OID.get(name.toUpperCase());
        if (oid == null)
            return null;
        return (AVAValueConverter) oid2ValueConverter.get(oid);
    }

    /**
     * Get the Attribute Value Converter for the specified ObjectIdentifier.
     *
     * @param oid An ObjectIdentifier
     *
     * @return An AVAValueConverter for the OID.
     */
    public AVAValueConverter getValueConverter(ObjectIdentifier oid) {
        return (AVAValueConverter) oid2ValueConverter.get(oid);
    }

    /**
     * Get an Enumeration of all attribute names in this map.
     *
     * @return An Enumeration of all attribute names.
     */
    public Enumeration<String> getAllNames() {
        return name2OID.keys();
    }

    /**
     * Get an Enumeration of all ObjectIdentifiers in this map.
     *
     * @return An Enumeration of all OIDs in this map.
     */
    public Enumeration<ObjectIdentifier> getAllOIDs() {
        return oid2Name.keys();
    }

    /**
     * Get the ObjectIdentifier object in the map for the specified OID.
     *
     * @param oid An ObjectIdentifier.
     * @return The ObjectIdentifier object in this map for the OID.
     */
    public ObjectIdentifier getOid(ObjectIdentifier oid) {
        String name = oid2Name.get(oid);
        if (name == null)
            return null;
        return name2OID.get(name);
    }

    //
    // public add methods.
    //

    /**
     * Adds a attribute name, ObjectIdentifier, AVAValueConverter entry
     * to the map.
     *
     * @param name An attribute name (string of ascii chars)
     * @param oid The ObjectIdentifier for the attribute.
     * @param valueConverter An AVAValueConverter object for converting
     *            an value for this attribute from a string to
     *            a DerValue and vice versa.
     */
    public void addNameOID(String name, ObjectIdentifier oid,
               AVAValueConverter valueConverter) {
        // normalize name for case insensitive compare.
        ObjectIdentifier theOid;
        Class<? extends AVAValueConverter> expValueConverter;

        theOid = name2OID.get(name);
        if (theOid != null) {
            expValueConverter = oid2ValueConverter.get(theOid).getClass();
            if (!theOid.equals(oid) ||
                    expValueConverter != valueConverter.getClass()) {
                throw new IllegalArgumentException(
                        "Another keyword-oid-valueConverter triple already " +
                                "exists in the X500NameAttrMap ");
            }
            return;
        }
        name2OID.put(name.toUpperCase(), oid);
        oid2Name.put(oid, name.toUpperCase());
        oid2ValueConverter.put(oid, valueConverter);
    }

    //
    // public static methods.
    //

    /**
     * Get the global default X500NameAttrMap.
     *
     * @return The global default X500NameAttrMap.
     */
    public static X500NameAttrMap getDefault() {
        return defMap;
    }

    /**
     * Get the global default X500NamAttrMap using the DirStrConverter.
     *
     * @return The global default X500NameAttrMap using the DirStrConverter.
     */

    public static X500NameAttrMap getDirDefault() {
        return defDirMap;

    }

    /**
     * Set the global default X500NameAttrMap.
     *
     * @param newDefault The new default X500NameAttrMap.
     */
    public static void setDefault(X500NameAttrMap newDefault) {
        // XXX assert newDef != null
        defMap = newDefault;
    }

    //
    // private variables
    //

    Hashtable<String, ObjectIdentifier> name2OID = new Hashtable<String, ObjectIdentifier>();
    Hashtable<ObjectIdentifier, String> oid2Name = new Hashtable<ObjectIdentifier, String>();
    Hashtable<ObjectIdentifier, AVAValueConverter> oid2ValueConverter =
            new Hashtable<ObjectIdentifier, AVAValueConverter>();

    //
    // global defaults.
    //

    private static X500NameAttrMap defMap;

    private static X500NameAttrMap defDirMap;

    /*
     * Create the default maps on initialization.
     */
    static {
        defMap = new X500NameAttrMap();
        AVAValueConverter directoryStr = new DirStrConverter(), ia5Str = new IA5StringConverter();
        defMap.addNameOID("CN",
                new ObjectIdentifier("2.5.4.3"),
                directoryStr);
        defMap.addNameOID("OU",
                new ObjectIdentifier("2.5.4.11"),
                directoryStr);
        defMap.addNameOID("O",
                new ObjectIdentifier("2.5.4.10"),
                directoryStr);
        // serialNumber added for CEP support
        defMap.addNameOID("SERIALNUMBER",
                new ObjectIdentifier("2.5.4.5"),
                new PrintableConverter());
        defMap.addNameOID("C",
                new ObjectIdentifier("2.5.4.6"),
                new PrintableConverter());
        defMap.addNameOID("L",
                new ObjectIdentifier("2.5.4.7"),
                directoryStr);
        defMap.addNameOID("ST",
                new ObjectIdentifier("2.5.4.8"),
                directoryStr);
        defMap.addNameOID("STREET",
                new ObjectIdentifier("2.5.4.9"),
                directoryStr);
        defMap.addNameOID("TITLE",
                new ObjectIdentifier("2.5.4.12"),
                directoryStr);
        // RFC 1274 UserId, rfc822MailBox
        defMap.addNameOID("UID",
                new ObjectIdentifier("0.9.2342.19200300.100.1.1"),
                directoryStr);
        defMap.addNameOID("MAIL",
                new ObjectIdentifier("0.9.2342.19200300.100.1.3"),
                ia5Str);
        // PKCS9 e-mail address
        defMap.addNameOID("E",
                new ObjectIdentifier("1.2.840.113549.1.9.1"),
                ia5Str);

        // DC definition from draft-ietf-asid-ldap-domains-02.txt
        defMap.addNameOID("DC",
                new ObjectIdentifier("0.9.2342.19200300.100.1.25"),
                ia5Str);

        // more defined in RFC2459 used in Subject Directory Attr extension
        defMap.addNameOID("SN", // surname
                new ObjectIdentifier("2.5.4.4"),
                directoryStr);
        defMap.addNameOID("GIVENNAME",
                new ObjectIdentifier("2.5.4.42"),
                directoryStr);
        defMap.addNameOID("INITIALS",
                new ObjectIdentifier("2.5.4.43"),
                directoryStr);
        defMap.addNameOID("GENERATIONQUALIFIER",
                new ObjectIdentifier("2.5.4.44"),
                directoryStr);
        defMap.addNameOID("DNQUALIFIER",
                new ObjectIdentifier("2.5.4.46"),
                directoryStr);

        // these two added mainly for CEP support
        // PKCS9 unstructured name
        defMap.addNameOID("UNSTRUCTUREDNAME",
                new ObjectIdentifier("1.2.840.113549.1.9.2"),
                ia5Str);
        // PKCS9 unstructured address
        defMap.addNameOID("UNSTRUCTUREDADDRESS",
                new ObjectIdentifier("1.2.840.113549.1.9.8"),
                new PrintableConverter());
    };

    static {
        defDirMap = new X500NameAttrMap();
        AVAValueConverter directoryStr = new DirStrConverter();

        defDirMap.addNameOID("CN",
                          new ObjectIdentifier("2.5.4.3"),
                          directoryStr);
        defDirMap.addNameOID("OU",
                          new ObjectIdentifier("2.5.4.11"),
                          directoryStr);
        defDirMap.addNameOID("O",
                          new ObjectIdentifier("2.5.4.10"),
                          directoryStr);
        // serialNumber added for CEP support
        defDirMap.addNameOID("SERIALNUMBER",
                          new ObjectIdentifier("2.5.4.5"),
                          directoryStr);
        defDirMap.addNameOID("C",
                          new ObjectIdentifier("2.5.4.6"),
                          directoryStr);
        defDirMap.addNameOID("L",
                          new ObjectIdentifier("2.5.4.7"),
                          directoryStr);
        defDirMap.addNameOID("ST",
                          new ObjectIdentifier("2.5.4.8"),
                          directoryStr);
        defDirMap.addNameOID("STREET",
                          new ObjectIdentifier("2.5.4.9"),
                          directoryStr);
        defDirMap.addNameOID("TITLE",
                          new ObjectIdentifier("2.5.4.12"),
                          directoryStr);
        // RFC 1274 UserId, rfc822MailBox
        defDirMap.addNameOID("UID",
                          new ObjectIdentifier("0.9.2342.19200300.100.1.1"),
                          directoryStr);
        defDirMap.addNameOID("MAIL",
                          new ObjectIdentifier("0.9.2342.19200300.100.1.3"),
                          directoryStr);
        // PKCS9 e-mail address
        defDirMap.addNameOID("E",
                          new ObjectIdentifier("1.2.840.113549.1.9.1"),
                          directoryStr);

        // DC definition from draft-ietf-asid-ldap-domains-02.txt
        defDirMap.addNameOID("DC",
                          new ObjectIdentifier("0.9.2342.19200300.100.1.25"),
                          directoryStr);

        // more defined in RFC2459 used in Subject Directory Attr extension
        defDirMap.addNameOID("SN", // surname
                new ObjectIdentifier("2.5.4.4"),
                          directoryStr);
        defDirMap.addNameOID("GIVENNAME",
                          new ObjectIdentifier("2.5.4.42"),
                          directoryStr);
        defDirMap.addNameOID("INITIALS",
                          new ObjectIdentifier("2.5.4.43"),
                          directoryStr);
        defDirMap.addNameOID("GENERATIONQUALIFIER",
                          new ObjectIdentifier("2.5.4.44"),
                          directoryStr);
        defDirMap.addNameOID("DNQUALIFIER",
                          new ObjectIdentifier("2.5.4.46"),
                          directoryStr);

        // these two added mainly for CEP support
        // PKCS9 unstructured name
        defDirMap.addNameOID("UNSTRUCTUREDNAME",
                          new ObjectIdentifier("1.2.840.113549.1.9.2"),
                          directoryStr);
        // PKCS9 unstructured address
        defDirMap.addNameOID("UNSTRUCTUREDADDRESS",
                          new ObjectIdentifier("1.2.840.113549.1.9.8"),
                          directoryStr);
    };

}
