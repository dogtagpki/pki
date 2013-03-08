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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.UnsupportedCharsetException;

import netscape.security.util.DerEncoder;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * X.500 Attribute-Value-Assertion (AVA): an attribute, as identified by
 * some attribute ID, has some particular value. Values are as a rule ASN.1
 * printable strings. A conventional set of type IDs is recognized when
 * parsing (and generating) RFC 1779 syntax strings.
 *
 * <P>
 * AVAs are components of X.500 relative names. Think of them as being individual fields of a database record. The
 * attribute ID is how you identify the field, and the value is part of a particular record.
 *
 * @see X500Name
 * @see RDN
 * @see LdapDNStrConverter
 *
 * @version 1.14
 *
 * @author David Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
// public ... when RDN is public and X.500Names can be
// constructed using RDNs, and all three classes are cleaner
public final class AVA implements DerEncoder {
    ObjectIdentifier oid;
    DerValue value;

    /**
     * Constructs an AVA from a Ldap DN string with one AVA component
     * using the global default LdapDNStrConverter.
     *
     * @see LdapDNStrConverter
     * @param avaString a Ldap DN string with one AVA component.
     */
    public AVA(String avaString)
            throws IOException {
        AVA ava;
        ava = LdapDNStrConverter.getDefault().parseAVA(avaString);
        oid = ava.getOid();
        value = ava.getValue();
    }

    /**
     * Like AVA(String) with a DER encoding order given for Directory Strings.
     */
    public AVA(String avaString, byte[] tags)
            throws IOException {
        AVA ava;
        ava = LdapDNStrConverter.getDefault().parseAVA(avaString, tags);
        oid = ava.getOid();
        value = ava.getValue();
    }

    /**
     * Constructs an AVA from a Ldap DN string containing one AVA
     * component using the specified LdapDNStrConverter.
     *
     * @see LdapDNStrConverter
     * @param avaString a Ldap DN string containing one AVA.
     * @param ldapDNStrConverter a LdapDNStrConverter
     */
    public AVA(String avaString, LdapDNStrConverter ldapDNStrConverter)
            throws IOException {
        AVA ava;
        ava = ldapDNStrConverter.parseAVA(avaString);
        oid = ava.getOid();
        value = ava.getValue();
    }

    /**
     * Constructs an AVA from an OID and DerValue.
     *
     * @param type an ObjectIdentifier
     * @param val a DerValue
     */
    public AVA(ObjectIdentifier type, DerValue val)
            throws IOException {
        oid = type;
        value = val;
    }

    /**
     * Constructs an AVA from an input stream of UTF8 bytes that form
     * a Ldap DN string. Then parse the Ldap DN string using the global
     * default LdapDNStrConverter. <br>
     * Parses an RFC 1779 style AVA string: CN=fee fie foe fum
     * or perhaps with quotes. Not all defined AVA tags are supported;
     * of current note are X.400 related ones (PRMD, ADMD, etc).
     *
     * This terminates at unescaped AVA separators ("+") or RDN
     * separators (",", ";"), or DN terminators (">"), and removes
     * cosmetic whitespace at the end of values.
     *
     * @see LdapDNStrConverter
     * @param in the input stream.
     */
    public AVA(InputStream in) throws IOException {
        try {
            // convert from UTF8 bytes to java string then parse it.
            byte[] buffer = new byte[in.available()];
            in.read(buffer);

            Charset charset = Charset.forName("UTF-8");
            CharsetDecoder decoder = charset.newDecoder();

            CharBuffer charBuffer = decoder.decode(ByteBuffer.wrap(buffer));

            AVA a = LdapDNStrConverter.getDefault().parseAVA(charBuffer.toString());
            oid = a.getOid();
            value = a.getValue();

        } catch (UnsupportedCharsetException e) {
            throw new IOException("UTF8 encoding not supported", e);
        }
    }

    /**
     * Constructs an AVA from a Der Input Stream.
     *
     * @param in the Der Input Stream.
     */
    public AVA(DerInputStream in) throws IOException {
        DerValue assertion = in.getDerValue();

        /*
         * Individual attribute value assertions are SEQUENCE of two values.
         * That'd be a "struct" outside of ASN.1.
         */
        if (assertion.tag != DerValue.tag_Sequence)
            throw new CertParseError("X500 AVA, not a sequence");

        ObjectIdentifier o = assertion.data.getOID();
        oid = X500NameAttrMap.getDefault().getOid(o);
        if (oid == null) {
            // NSCP #329837
            // if this OID is not recongized in our map (table),
            // it is fine. we just store it as regular OID.
            oid = o;
        }
        value = assertion.data.getDerValue();

        if (assertion.data.available() != 0)
            throw new CertParseError("AVA, extra bytes = "
                    + assertion.data.available());
    }

    // other public methods.

    /**
     * Returns true if another AVA has the same OID and DerValue.
     *
     * @param other the other AVA.
     * @return ture iff other AVA has same oid and value.
     */
    public boolean equals(AVA other) {
        return oid.equals(other.oid) && value.equals(other.value);
    }

    /**
     * Compares the AVA with an Object, returns true if the object is
     * an AVA and has the same OID and value.
     *
     * @param other the other object.
     * @return true iff other object is an AVA and has same oid and value.
     */
    public boolean equals(Object other) {
        if (other instanceof AVA)
            return equals((AVA) other);
        else
            return false;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((oid == null) ? 0 : oid.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
    }

    /**
     * Encodes the AVA to a Der output stream.
     * AVAs are encoded as a SEQUENCE of two elements.
     *
     * @param out The Der output stream.
     */
    public void encode(DerOutputStream out) throws IOException {
        derEncode(out);
    }

    /**
     * DER encode this object onto an output stream.
     * Implements the <code>DerEncoder</code> interface.
     *
     * @param out
     *            the output stream on which to write the DER encoding.
     *
     * @exception IOException on encoding error.
     */
    public void derEncode(OutputStream out) throws IOException {
        try (DerOutputStream tmp2 = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            tmp.putOID(oid);
            value.encode(tmp);
            tmp2.write(DerValue.tag_Sequence, tmp);
            out.write(tmp2.toByteArray());
        }
    }

    /**
     * Returns a Ldap DN string with one AVA component using
     * the global default LdapDNStrConverter.
     *
     * @return a Ldap DN string
     * @exception IOException if an error occurs during conversion.
     * @see LdapDNStrConverter
     */
    public String toLdapDNString()
            throws IOException {
        LdapDNStrConverter v = LdapDNStrConverter.getDefault();
        return v.encodeAVA(this);
    }

    /**
     * Returns a Ldap DN string with one AVA component using the specified
     * LdapDNStrConverter.
     *
     * @return a Ldap DN string
     * @param ldapDNStrConverter a Ldap DN String Converter
     * @exception IOException if an error occurs during the conversion.
     * @see LdapDNStrConverter
     */
    public String toLdapDNString(LdapDNStrConverter ldapDNStrConverter)
            throws IOException {
        return ldapDNStrConverter.encodeAVA(this);
    }

    /**
     * Returns a Ldap DN string with the AVA component using the global
     * default LdapDNStrConverter, or null if an error occurs in conversion.
     *
     * @return a Ldap DN string containing the AVA, or null if an
     *         error occurs in the conversion.
     */
    public String toString() {
        String s;
        try {
            // NOTE that a LdapDNString is returned here to match the
            // original source from sun. Could also return the raw value
            // (before Ldap escaping) here.
            s = toLdapDNString();
        } catch (IOException e) {
            return null;
        }
        return s;
    }

    /**
     * Returns the OID in the AVA.
     *
     * @return the ObjectIdentifier in this AVA.
     */
    public ObjectIdentifier getOid() {
        return oid;
    }

    /**
     * Returns the value in this AVA as a DerValue
     *
     * @return attribute value in this AVA.
     */
    public DerValue getValue() {
        return value;
    }

}
