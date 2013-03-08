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
import java.security.Principal;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * X.500 names are used to identify entities, such as those which are
 * identified by X.509 certificates. They are world-wide, hierarchical,
 * and descriptive. Entities can be identified by attributes, and in
 * some systems can be searched for according to those attributes.
 *
 * <P>
 * <em>This class exposes only partial X.500 name functionality.  Most
 * notably, it works best if Relative Distinguished Names only have one
 * (unique) attribute each, and if only the most common attributes need
 * to be visible to applications.  This limitation, and others, will
 * be lifted over time.</em>
 *
 * @author David Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.35
 * @see GeneralName
 * @see GeneralNames
 * @see GeneralNameInterface
 * @see RDN
 * @see AVA
 * @see LdapDNStrConverter
 */

public class X500Name implements Principal, GeneralNameInterface {
    /**
     *
     */
    private static final long serialVersionUID = -730790062013191108L;

    /**
     * Constructs a name from a Ldap DN string, such
     * as &lb;CN=Dave, OU=JavaSoft, O=Sun Microsystems, C=US&rb;. The
     * older "/C=US/O=Sun Microsystems, Inc/OU=JavaSoft/CN=Dave" syntax
     * is not currently supported. (The former is RFC 1779 style.)
     *
     * @param ldapDNString a Ldap DN String e.g. as defined in RFC1779
     */
    public X500Name(String ldapDNString)
            throws IOException {
        X500Name x500name;

        if (ldapDNString == null || ldapDNString.equals("")) {
            clear();
            return;
        }
        x500name = LdapDNStrConverter.getDefault().parseDN(ldapDNString);
        names = x500name.getNames();
    }

    /**
     * Constructs a X500Name from a Ldap DN String using the specified
     * LdapDNStrConverter. Also use the input tags.
     *
     * @see LdapDNStrConverter
     *
     * @param ldapDNString a Ldap DN String e.g. as defined in RFC1779.
     * @param ldapDNStrConverter A LdapDNStrConverter
     */
    public X500Name(String ldapDNString, LdapDNStrConverter ldapDNStrConverter, byte[] tags)
            throws IOException {

        if (ldapDNString == null || ldapDNString.equals("")) {
            clear();
            return;
        }
        X500Name x500name;
        x500name = ldapDNStrConverter.parseDN(ldapDNString, tags);
        names = x500name.getNames();

    }

    public X500Name(String ldapDNString, byte[] tags)
            throws IOException {
        if (ldapDNString == null || ldapDNString.equals("")) {
            clear();
            return;
        }
        X500Name x500name;
        x500name = LdapDNStrConverter.getDefault().parseDN(ldapDNString, tags);
        names = x500name.getNames();
    }

    /**
     * Constructs a X500Name from a Ldap DN String using the specified
     * LdapDNStrConverter.
     *
     * @see LdapDNStrConverter
     *
     * @param ldapDNString a Ldap DN String e.g. as defined in RFC1779.
     * @param ldapDNStrConverter A LdapDNStrConverter
     */
    public X500Name(String ldapDNString,
             LdapDNStrConverter ldapDNStrConverter)
            throws IOException {
        if (ldapDNString == null || ldapDNString.equals("")) {
            clear();
            return;
        }
        X500Name x500name;
        x500name = ldapDNStrConverter.parseDN(ldapDNString);
        names = x500name.getNames();
    }

    /**
     * Constructs a X500Name from fields common in enterprise application
     * environments.
     *
     * @param commonName common name of a person, e.g. "Vivette Davis"
     * @param organizationUnit small organization name, e.g. "Purchasing"
     * @param organizationName large organization name, e.g. "Onizuka, Inc."
     * @param country two letter country code, e.g. "CH"
     */
    public X500Name(
            String commonName,
            String organizationUnit,
            String organizationName,
            String country) throws IOException {
        DirStrConverter dirStrConverter = new DirStrConverter();
        PrintableConverter printableConverter = new PrintableConverter();
        AVA[] assertion = new AVA[1]; // array is cloned in constructors.
        int i = 4;

        names = new RDN[i];
        /*
         * NOTE:  it's only on output that little-endian
         * ordering is used.
         */
        assertion[0] = new AVA(commonName_oid,
                dirStrConverter.getValue(commonName));
        names[--i] = new RDN(assertion);

        assertion[0] = new AVA(orgUnitName_oid,
                dirStrConverter.getValue(organizationUnit));
        names[--i] = new RDN(assertion);

        assertion[0] = new AVA(orgName_oid,
                dirStrConverter.getValue(organizationName));
        names[--i] = new RDN(assertion);

        assertion[0] = new AVA(countryName_oid,
                printableConverter.getValue(country));
        names[--i] = new RDN(assertion);
    }

    /**
     * Constructs a X500Name from fields common in Internet application
     * environments.
     *
     * @param commonName common name of a person, e.g. "Vivette Davis"
     * @param organizationUnit small organization name, e.g. "Purchasing"
     * @param organizationName large organization name, e.g. "Onizuka, Inc."
     * @param localityName locality (city) name, e.g. "Palo Alto"
     * @param stateName state name, e.g. "California"
     * @param country two letter country code, e.g. "CH"
     */
    public X500Name(
            String commonName,
            String organizationUnit,
            String organizationName,
            String localityName,
            String stateName,
            String country) throws IOException {
        DirStrConverter dirStrConverter = new DirStrConverter();
        PrintableConverter printableConverter = new PrintableConverter();
        AVA[] assertion = new AVA[1]; // array is cloned in constructors.
        int i = 6;

        names = new RDN[i];
        /*
         * NOTE:  it's only on output that little-endian
         * ordering is used.
         */
        assertion[0] = new AVA(commonName_oid,
                dirStrConverter.getValue(commonName));
        names[--i] = new RDN(assertion);

        assertion[0] = new AVA(orgUnitName_oid,
                dirStrConverter.getValue(organizationUnit));
        names[--i] = new RDN(assertion);

        assertion[0] = new AVA(orgName_oid,
                dirStrConverter.getValue(organizationName));
        names[--i] = new RDN(assertion);

        assertion[0] = new AVA(localityName_oid,
                dirStrConverter.getValue(localityName));
        names[--i] = new RDN(assertion);

        assertion[0] = new AVA(stateName_oid,
                dirStrConverter.getValue(stateName));
        names[--i] = new RDN(assertion);

        assertion[0] = new AVA(countryName_oid,
                printableConverter.getValue(country));
        names[--i] = new RDN(assertion);
    }

    /**
     * Constructs a name from an ASN.1 encoded value. The encoding
     * of the name in the stream uses DER (a BER/1 subset).
     *
     * @param value a DER-encoded value holding an X.500 name.
     */
    public X500Name(DerValue value) throws IOException {

        this(value.toDerInputStream());
    }

    /**
     * Constructs a name from an ASN.1 encoded input stream. The encoding
     * of the name in the stream uses DER (a BER/1 subset).
     *
     * @param in DER-encoded data holding an X.500 name.
     */
    public X500Name(DerInputStream in)
            throws IOException {
        parseDER(in);
    }

    /**
     * Constructs a name from an ASN.1 encoded byte array.
     *
     * @param name DER-encoded byte array holding an X.500 name.
     */
    public X500Name(byte[] name)
            throws IOException {
        DerInputStream in = new DerInputStream(name);
        parseDER(in);

    }

    /**
     * Constructs a X500Name from array of RDN. The RDNs are expected to
     * be in big endian order i.e. most significant first.
     *
     * @param rdns an array of RDN.
     */
    public X500Name(RDN[] rdns)
            throws IOException {
        names = rdns.clone();
    }

    /**
     * convenience method.
     *
     * @param rdns a vector of rdns.
     */
    public X500Name(Vector<RDN> rdnVector)
            throws IOException {
        int size = rdnVector.size();
        names = new RDN[size];
        for (int i = 0; i < size; i++) {
            names[i] = rdnVector.elementAt(i);
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(names);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        X500Name other = (X500Name) obj;
        if (!Arrays.equals(names, other.names))
            return false;
        return true;
    }

    /**
     * Sets private data to a null state
     */

    private void clear() {
        dn = "";
        names = null;

    }

    /**
     * Returns the name component as a Java string, regardless of its
     * encoding restrictions.
     */
    private String getString(DerValue attribute) throws IOException {
        String value = attribute.getAsString();

        if (value == null)
            throw new IOException("not a DER string encoding, "
                    + attribute.tag);
        else
            return value;
    }

    /**
     * Return type of GeneralName.
     */
    public int getType() {
        return (GeneralNameInterface.NAME_DIRECTORY);
    }

    /**
     * Returns a "Country" name component. If more than one
     * such attribute exists, the topmost one is returned.
     *
     * @return "C=" component of the name, if any.
     */
    public String getCountry() throws IOException {
        DerValue attr = findAttribute(countryName_oid);

        return getString(attr);
    }

    /**
     * Returns an "Organization" name component. If more than
     * one such attribute exists, the topmost one is returned.
     *
     * @return "O=" component of the name, if any.
     */
    public String getOrganization() throws IOException {
        DerValue attr = findAttribute(orgName_oid);

        return getString(attr);
    }

    /**
     * Returns an "Organizational Unit" name component. If more
     * than one such attribute exists, the topmost one is returned.
     *
     * @return "OU=" component of the name, if any.
     */
    public String getOrganizationalUnit() throws IOException {
        DerValue attr = findAttribute(orgUnitName_oid);

        return getString(attr);
    }

    /**
     * Returns a "Common Name" component. If more than one such
     * attribute exists, the topmost one is returned.
     *
     * @return "CN=" component of the name, if any.
     */
    public String getCommonName() throws IOException {
        DerValue attr = findAttribute(commonName_oid);

        return getString(attr);
    }

    /**
     * Returns a "UID" component. If more than one such
     * attribute exists, the topmost one is returned.
     *
     * @return "UID=" component of the name, if any.
     */
    public String getUserID() throws IOException {
        DerValue attr = findAttribute(uidName_oid);

        return getString(attr);
    }

    /**
     * Returns a "Locality" name component. If more than one
     * such component exists, the topmost one is returned.
     *
     * @return "L=" component of the name, if any.
     */
    public String getLocality() throws IOException {
        DerValue attr = findAttribute(localityName_oid);

        return getString(attr);
    }

    /**
     * Returns a "State" name component. If more than one
     * such component exists, the topmost one is returned.
     *
     * @return "S=" component of the name, if any.
     */
    public String getState() throws IOException {
        DerValue attr = findAttribute(stateName_oid);

        return getString(attr);
    }

    /**
     * Returns a "Email" name component. If more than one
     * such component exists, the topmost one is returned.
     *
     * @return "E=" component of the name, if any.
     */
    public String getEmail() throws IOException {
        DerValue attr = findAttribute(email_oid);
        if (attr == null)
            return null;
        return getString(attr);
    }

    /**
     * Returns a Ldap DN String from the X500Name using the global default
     * LdapDNStrConverter
     *
     * @see LdapDNStrConverter
     * @return Ldap DN string of this X500Name using the default converter.
     */
    public String toLdapDNString()
            throws IOException {
        if (dn == null)
            generateDN(LdapDNStrConverter.getDefault());
        return dn;
    }

    /**
     * Returns a Ldap DN String from the X500Name
     * using the specified LdapDNStrconverter.
     * For example, RFC1779String converter can be passed to convert the
     * DN to RFC1779 string syntax.
     *
     * @see LdapDNStrConverter
     * @param ldapDNStrConverter a LdapDNStrConverter
     * @return Ldap DN string of the X500Name
     */
    public String toLdapDNString(LdapDNStrConverter ldapDNStrConverter)
            throws IOException {

        if (dn == null)
            generateDN(ldapDNStrConverter);
        return dn;
    }

    /**
     * Returns a Ldap DN string, using the global default LdapDNStrConverter
     * or null if an error occurs in the conversion.
     */
    public String toString() {
        String s;
        if (names == null) {
            s = "";
            return s;
        }
        try {
            s = toLdapDNString();
        } catch (IOException e) {
            return null;
        }
        return s;
    }

    /**
     * Returns the value of toString(). This call is needed to
     * implement the java.security.Principal interface.
     */
    public String getName() {
        return toString();
    }

    private String dn; // RFC 1779 style DN, or null
    private RDN names[]; // RDNs

    /**
     * Find the first instance of this attribute in a "top down"
     * search of all the attributes in the name.
     */
    private DerValue findAttribute(ObjectIdentifier attribute) {
        int i;
        DerValue retval = null;

        for (i = 0; i < names.length; i++) {
            retval = names[i].findAttribute(attribute);
            if (retval != null)
                break;
        }
        return retval;
    }

    /**
     * Returns an enumerator of RDNs in the X500Name.
     *
     * @return enumeration of rdns in this X500Name.
     */
    public Enumeration<RDN> getRDNs() {
        return new RDNEnumerator();
    }

    /**
     * Returns an array of RDN in the X500Name.
     *
     * @return array of RDN in this X500name.
     */
    public RDN[] getNames() {
        return names.clone();
    }

    /**
     * Returns the number of RDNs in the X500Name.
     *
     * @return number of RDNs in this X500Name.
     */
    public int getNamesLength() {
        return names.length;
    }

    /****************************************************************/

    private void parseDER(DerInputStream in) throws IOException {
        //
        // X.500 names are a "SEQUENCE OF" RDNs, which means one or
        // more and order matters.  We scan them in order, which
        // conventionally is big-endian.
        //
        DerValue nameseq[] = in.getSequence(5);
        int i;

        if (nameseq.length != 0) {
            names = new RDN[nameseq.length];
        } else {
            clear();
        }

        for (i = 0; i < nameseq.length; i++)
            names[i] = new RDN(nameseq[i]);
    }

    /**
     * Encodes the name in DER-encoded form.
     *
     * @param out where to put the DER-encoded X.500 name
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        int i;

        int len = 0;
        if (names == null) {
            len = 0;
        } else {
            len = names.length;

        }

        for (i = 0; i < len; i++)
            names[i].encode(tmp);

        out.write(DerValue.tag_Sequence, tmp);
    }

    /**
     * Gets the name in DER-encoded form.
     *
     * @return the DER encoded byte array of this name,
     *         null if no names are present.
     */
    public byte[] getEncoded() throws IOException {
        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            int len = 0;

            if (names == null) {
                len = 0;
            } else {
                len = names.length;
            }

            for (int i = 0; i < len; i++)
                names[i].encode(tmp);

            out.write(DerValue.tag_Sequence, tmp);
            return out.toByteArray();
        }
    }

    /*
     * Dump the printable form of a distinguished name.  Each relative
     * name is separated from the next by a ",", and assertions in the
     * relative names have "label=value" syntax.
     *
     * Uses RFC 1779 syntax (i.e. little-endian, comma separators)
     *
     */
    private void generateDN(LdapDNStrConverter ldapDNStrConverter)
            throws IOException {
        if (names == null)
            return;

        dn = ldapDNStrConverter.encodeDN(this);
    }

    private class RDNEnumerator implements Enumeration<RDN> {
        private int index;

        public RDNEnumerator() {
            index = 0;
        }

        public boolean hasMoreElements() {
            return (index < names.length);
        }

        public RDN nextElement() {
            if (index >= names.length)
                return null;
            return names[index++];
        }
    }

    /****************************************************************/

    /*
     * Maybe return a preallocated OID, to reduce storage costs
     * and speed recognition of common X.500 attributes.
     */
    static ObjectIdentifier intern(ObjectIdentifier oid)
            throws IOException {
        return X500NameAttrMap.getDefault().getOid(oid);
    }

    /*
     * Selected OIDs from X.520
     */

    /** OID for the "CN=" attribute, denoting a person's common name. */
    public static final ObjectIdentifier commonName_oid = X500NameAttrMap.getDefault().getOid("CN");

    /** OID for the "UID=" attribute, denoting a person's ID. */
    public static final ObjectIdentifier uidName_oid = X500NameAttrMap.getDefault().getOid("UID");

    /** OID for the "C=" attribute, denoting a country. */
    public static final ObjectIdentifier countryName_oid = X500NameAttrMap.getDefault().getOid("C");

    /** OID for the "L=" attribute, denoting a locality (such as a city) */
    public static final ObjectIdentifier localityName_oid = X500NameAttrMap.getDefault().getOid("L");

    /** OID for the "O=" attribute, denoting an organization name */
    public static final ObjectIdentifier orgName_oid = X500NameAttrMap.getDefault().getOid("O");

    /** OID for the "OU=" attribute, denoting an organizational unit name */
    public static final ObjectIdentifier orgUnitName_oid = X500NameAttrMap.getDefault().getOid("OU");

    /** OID for the "S=" attribute, denoting a state (such as Delaware) */
    public static final ObjectIdentifier stateName_oid = X500NameAttrMap.getDefault().getOid("ST");

    /** OID for the "STREET=" attribute, denoting a street address. */
    public static final ObjectIdentifier streetAddress_oid = X500NameAttrMap.getDefault().getOid("STREET");

    /** OID for the "T=" attribute, denoting a person's title. */
    public static final ObjectIdentifier title_oid = X500NameAttrMap.getDefault().getOid("TITLE");

    /** OID for the "E=" attribute, denoting a person's email address. */
    public static final ObjectIdentifier email_oid = X500NameAttrMap.getDefault().getOid("E");

    /*
     * OIDs from other sources which show up in X.500 names we
     * expect to deal with often
     */

    private static final int ipAddress_data[] = // SKIP
            { 1, 3, 6, 1, 4, 1, 42, 2, 11, 2, 1 };

    /** OID for "IP=" IP address attributes, used with SKIP. */
    public static final ObjectIdentifier ipAddress_oid = new ObjectIdentifier(ipAddress_data);
}
