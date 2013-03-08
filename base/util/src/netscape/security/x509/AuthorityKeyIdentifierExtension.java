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
import java.lang.reflect.Array;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class represents the Authority Key Identifier Extension.
 *
 * <p>
 * The authority key identifier extension provides a means of identifying the particular public key used to sign a
 * certificate. This extension would be used where an issuer has multiple signing keys (either due to multiple
 * concurrent key pairs or due to changeover).
 * <p>
 * The ASN.1 syntax for this is:
 *
 * <pre>
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
 * }
 * KeyIdentifier ::= OCTET STRING
 * </pre>
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.9
 * @see Extension
 * @see CertAttrSet
 */
public class AuthorityKeyIdentifierExtension extends Extension
        implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = -157913621972354170L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT =
                         "x509.info.extensions.AuthorityKeyIdentifier";
    /**
     * Attribute names.
     */
    public static final String NAME = "AuthorityKeyIdentifier";
    public static final String KEY_ID = "key_id";
    public static final String AUTH_NAME = "auth_name";
    public static final String SERIAL_NUMBER = "serial_number";

    // Private data members
    private static final byte TAG_ID = 0;
    private static final byte TAG_NAMES = 1;
    private static final byte TAG_SERIAL_NUM = 2;

    private KeyIdentifier id = null;
    private GeneralNames names = null;
    private SerialNumber serialNum = null;

    // Encode only the extension value
    private void encodeThis() throws IOException {
        try (DerOutputStream tmp = new DerOutputStream();
             DerOutputStream seq = new DerOutputStream()) {

            if (id != null) {
                DerOutputStream tmp1 = new DerOutputStream();
                id.encode(tmp1);
                tmp.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                        false, TAG_ID), tmp1);
            }
            try {
                if (names != null) {
                    DerOutputStream tmp1 = new DerOutputStream();
                    names.encode(tmp1);
                    tmp.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                            true, TAG_NAMES), tmp1);
                }
            } catch (Exception e) {
                throw new IOException(e.toString());
            }
            if (serialNum != null) {
                DerOutputStream tmp1 = new DerOutputStream();
                serialNum.encode(tmp1);
                tmp.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                        false, TAG_SERIAL_NUM), tmp1);
            }
            seq.write(DerValue.tag_Sequence, tmp);
            this.extensionValue = seq.toByteArray();
        }
    }

    /**
     * Exposed critical parameter. 99/11/03
     */
    public AuthorityKeyIdentifierExtension(boolean critical,
            KeyIdentifier kid, GeneralNames name,
                                          SerialNumber sn)
            throws IOException {
        this.id = kid;
        this.names = name;
        this.serialNum = sn;

        this.extensionId = PKIXExtensions.AuthorityKey_Id;
        this.critical = critical;
        encodeThis();
    }

    /**
     * The default constructor for this extension. Null parameters make
     * the element optional (not present).
     *
     * @param id the KeyIdentifier associated with this extension.
     * @param names the GeneralNames associated with this extension
     * @param serialNum the CertificateSerialNumber associated with
     *            this extension.
     * @exception IOException on error.
     */
    public AuthorityKeyIdentifierExtension(KeyIdentifier kid, GeneralNames name,
                                           SerialNumber sn)
            throws IOException {
        this.id = kid;
        this.names = name;
        this.serialNum = sn;

        this.extensionId = PKIXExtensions.AuthorityKey_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public AuthorityKeyIdentifierExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.AuthorityKey_Id;
        this.critical = critical.booleanValue();

        if (!(value instanceof byte[]))
            throw new IOException("Illegal argument type");

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        System.arraycopy(value, 0, extValue, 0, len);

        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for " +
                                  "AuthorityKeyIdentifierExtension.");
        }

        // NB. this is always encoded with the IMPLICIT tag
        // The checks only make sense if we assume implicit tagging,
        // with explicit tagging the form is always constructed.
        while (val.data.available() != 0) {
            DerValue opt = val.data.getDerValue();

            if (opt.isContextSpecific(TAG_ID) && !opt.isConstructed()) {
                if (id != null)
                    throw new IOException("Duplicate KeyIdentifier in " +
                                          "AuthorityKeyIdentifier.");
                opt.resetTag(DerValue.tag_OctetString);
                id = new KeyIdentifier(opt);

            } else if (opt.isContextSpecific(TAG_NAMES) &&
                       opt.isConstructed()) {
                if (names != null)
                    throw new IOException("Duplicate GeneralNames in " +
                                          "AuthorityKeyIdentifier.");
                try {
                    opt.resetTag(DerValue.tag_Sequence);
                    names = new GeneralNames(opt);
                } catch (GeneralNamesException e) {
                    throw new IOException(e.toString());
                }

            } else if (opt.isContextSpecific(TAG_SERIAL_NUM) &&
                       !opt.isConstructed()) {
                if (serialNum != null)
                    throw new IOException("Duplicate SerialNumber in " +
                                          "AuthorityKeyIdentifier.");
                opt.resetTag(DerValue.tag_Integer);
                serialNum = new SerialNumber(opt);
            } else
                throw new IOException("Invalid encoding of " +
                                      "AuthorityKeyIdentifierExtension.");
        }
    }

    /**
     * Return the object as a string.
     */
    public String toString() {
        String s = super.toString() + "AuthorityKeyIdentifier [\n";
        if (id != null) {
            s += id.toString();
        }
        if (names != null) {
            s += names.toString() + "\n";
        }
        if (serialNum != null) {
            s += serialNum.toString() + "\n";
        }
        return (s + "]\n");
    }

    /**
     * Decode the extension from the InputStream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception IOException on decoding or validity errors.
     */
    public void decode(InputStream in) throws IOException {
        throw new IOException("Method not to be called directly.");
    }

    /**
     * Write the extension to the OutputStream.
     *
     * @param out the OutputStream to write the extension to.
     * @exception IOException on error.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (this.extensionValue == null) {
            extensionId = PKIXExtensions.AuthorityKey_Id;
            critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        clearValue();
        if (name.equalsIgnoreCase(KEY_ID)) {
            if (!(obj instanceof KeyIdentifier)) {
                throw new IOException("Attribute value should be of " +
                                    "type KeyIdentifier.");
            }
            id = (KeyIdentifier) obj;
        } else if (name.equalsIgnoreCase(AUTH_NAME)) {
            if (!(obj instanceof GeneralNames)) {
                throw new IOException("Attribute value should be of " +
                                    "type GeneralNames.");
            }
            names = (GeneralNames) obj;
        } else if (name.equalsIgnoreCase(SERIAL_NUMBER)) {
            if (!(obj instanceof SerialNumber)) {
                throw new IOException("Attribute value should be of " +
                                    "type SerialNumber.");
            }
            serialNum = (SerialNumber) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:AuthorityKeyIdentifier.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(KEY_ID)) {
            return (id);
        } else if (name.equalsIgnoreCase(AUTH_NAME)) {
            return (names);
        } else if (name.equalsIgnoreCase(SERIAL_NUMBER)) {
            return (serialNum);
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:AuthorityKeyIdentifier.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(KEY_ID)) {
            id = null;
        } else if (name.equalsIgnoreCase(AUTH_NAME)) {
            names = null;
        } else if (name.equalsIgnoreCase(SERIAL_NUMBER)) {
            serialNum = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:AuthorityKeyIdentifier.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(KEY_ID);
        elements.addElement(AUTH_NAME);
        elements.addElement(SERIAL_NUMBER);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
