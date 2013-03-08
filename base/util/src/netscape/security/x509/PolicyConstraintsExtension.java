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

import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class defines the certificate extension which specifies the
 * Policy constraints.
 * <p>
 * The policy constraints extension can be used in certificates issued to CAs. The policy constraints extension
 * constrains path validation in two ways. It can be used to prohibit policy mapping or require that each certificate in
 * a path contain an acceptable policy identifier.
 * <p>
 * The ASN.1 syntax for this is (IMPLICIT tagging is defined in the module definition):
 *
 * <pre>
 * PolicyConstraints ::= SEQUENCE {
 *     requireExplicitPolicy [0] SkipCerts OPTIONAL,
 *     inhibitPolicyMapping  [1] SkipCerts OPTIONAL
 * }
 * SkipCerts ::= INTEGER (0..MAX)
 * </pre>
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.9
 * @see Extension
 * @see CertAttrSet
 */
public class PolicyConstraintsExtension extends Extension
        implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = -3723759691127622370L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.PolicyConstraints";
    /**
     * Attribute names.
     */
    public static final String NAME = "PolicyConstraints";
    public static final String REQUIRE = "require";
    public static final String INHIBIT = "inhibit";

    private static final byte TAG_REQUIRE = 0;
    private static final byte TAG_INHIBIT = 1;

    private int require = -1;
    private int inhibit = -1;

    // Encode this extension value.
    private void encodeThis() throws IOException {
        try (DerOutputStream seq = new DerOutputStream()) {
            DerOutputStream tagged = new DerOutputStream();

            if (require != -1) {
                DerOutputStream tmp = new DerOutputStream();
                tmp.putInteger(new BigInt(require));
                tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                        false, TAG_REQUIRE), tmp);
            }
            if (inhibit != -1) {
                DerOutputStream tmp = new DerOutputStream();
                tmp.putInteger(new BigInt(inhibit));
                tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                        false, TAG_INHIBIT), tmp);
            }
            seq.write(DerValue.tag_Sequence, tagged);
            extensionValue = seq.toByteArray();
        }
    }

    /**
     * Create a PolicyConstraintsExtension object with criticality and
     * both require explicit policy and inhibit policy mapping.
     *
     * @param critical whether this extension should be critical
     * @param require require explicit policy (-1 for optional).
     * @param inhibit inhibit policy mapping (-1 for optional).
     */
    public PolicyConstraintsExtension(boolean crit, int require, int inhibit)
            throws IOException {
        init(crit, require, inhibit);
    }

    /**
     * Create a PolicyConstraintsExtension object with both
     * require explicit policy and inhibit policy mapping.
     *
     * @param require require explicit policy (-1 for optional).
     * @param inhibit inhibit policy mapping (-1 for optional).
     */
    public PolicyConstraintsExtension(int require, int inhibit)
            throws IOException {
        init(false, require, inhibit);
    }

    private void init(boolean crit, int require, int inhibit)
            throws IOException {
        this.require = require;
        this.inhibit = inhibit;
        this.extensionId = PKIXExtensions.PolicyConstraints_Id;
        this.critical = crit;
        encodeThis();
    }

    /**
     * Create the extension from its DER encoded value and criticality.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public PolicyConstraintsExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.PolicyConstraints_Id;
        this.critical = critical.booleanValue();

        if (!(value instanceof byte[]))
            throw new IOException("Illegal argument type");

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        System.arraycopy(value, 0, extValue, 0, len);

        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Sequence tag missing for PolicyConstraint.");
        }
        DerInputStream in = val.data;
        while (in != null && in.available() != 0) {
            DerValue next = in.getDerValue();

            if (next.isContextSpecific(TAG_REQUIRE) && !next.isConstructed()) {
                if (this.require != -1)
                    throw new IOException("Duplicate requireExplicitPolicy" +
                            "found in the PolicyConstraintsExtension");
                next.resetTag(DerValue.tag_Integer);
                this.require = (next.getInteger()).toInt();

            } else if (next.isContextSpecific(TAG_INHIBIT) &&
                       !next.isConstructed()) {
                if (this.inhibit != -1)
                    throw new IOException("Duplicate inhibitPolicyMapping" +
                            "found in the PolicyConstraintsExtension");
                next.resetTag(DerValue.tag_Integer);
                this.inhibit = (next.getInteger()).toInt();
            } else
                throw new IOException("Invalid encoding of PolicyConstraint");
        }
    }

    /**
     * Return the extension as user readable string.
     */
    public String toString() {
        String s;
        s = super.toString() + "PolicyConstraints: [" + "  Require: ";
        if (require == -1)
            s += "unspecified;";
        else
            s += require + ";";
        s += "\tInhibit: ";
        if (inhibit == -1)
            s += "unspecified";
        else
            s += inhibit;
        s += " ]\n";
        return s;
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
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            extensionId = PKIXExtensions.PolicyConstraints_Id;
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
        if (!(obj instanceof Integer)) {
            throw new IOException("Attribute value should be of type Integer.");
        }
        if (name.equalsIgnoreCase(REQUIRE)) {
            require = ((Integer) obj).intValue();
        } else if (name.equalsIgnoreCase(INHIBIT)) {
            inhibit = ((Integer) obj).intValue();
        } else {
            throw new IOException("Attribute name " + "[" + name + "]" +
                                " not recognized by " +
                    "CertAttrSet:PolicyConstraints.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(REQUIRE)) {
            return Integer.valueOf(require);
        } else if (name.equalsIgnoreCase(INHIBIT)) {
            return Integer.valueOf(inhibit);
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:PolicyConstraints.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(REQUIRE)) {
            require = -1;
        } else if (name.equalsIgnoreCase(INHIBIT)) {
            inhibit = -1;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:PolicyConstraints.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(REQUIRE);
        elements.addElement(INHIBIT);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    /**
     * returns the requireExplicitMapping parameter.
     */
    public int getRequireExplicitMapping() {
        return require;
    }

    /**
     * returns the inhibitPolicyMapping parameter.
     */
    public int getInhibitPolicyMapping() {
        return inhibit;
    }
}
