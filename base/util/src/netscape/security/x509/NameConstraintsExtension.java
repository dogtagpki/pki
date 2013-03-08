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
import netscape.security.util.PrettyPrintFormat;

/**
 * This class defines the Name Constraints Extension.
 * <p>
 * The name constraints extension provides permitted and excluded subtrees that place restrictions on names that may be
 * included within a certificate issued by a given CA. Restrictions may apply to the subject distinguished name or
 * subject alternative names. Any name matching a restriction in the excluded subtrees field is invalid regardless of
 * information appearing in the permitted subtrees.
 * <p>
 * The ASN.1 syntax for this is:
 *
 * <pre>
 * NameConstraints ::= SEQUENCE {
 *    permittedSubtrees [0]  GeneralSubtrees OPTIONAL,
 *    excludedSubtrees  [1]  GeneralSubtrees OPTIONAL
 * }
 * GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
 * GeneralSubtree ::== SEQUENCE {
 *    base                   GeneralName,
 *    minimum           [0]  BaseDistance DEFAULT 0,
 *    maximum           [1]  BaseDistance OPTIONAL }
 * BaseDistance ::== INTEGER (0..MAX)
 * </pre>
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.10
 * @see Extension
 * @see CertAttrSet
 */
public class NameConstraintsExtension extends Extension implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = -3506940192931244539L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.NameConstraints";
    /**
     * Attribute names.
     */
    public static final String NAME = "NameConstraints";
    public static final String PERMITTED_SUBTREES = "permitted_subtrees";
    public static final String EXCLUDED_SUBTREES = "excluded_subtrees";

    // Private data members
    private static final byte TAG_PERMITTED = 0;
    private static final byte TAG_EXCLUDED = 1;

    private GeneralSubtrees permitted;
    private GeneralSubtrees excluded;

    private transient PrettyPrintFormat pp = new PrettyPrintFormat(":");

    // Encode this extension value.
    private void encodeThis() throws IOException {
        try (DerOutputStream seq = new DerOutputStream()) {

            DerOutputStream tagged = new DerOutputStream();
            if ((permitted != null) && (permitted.getSubtrees().size() > 0)) {
                DerOutputStream tmp = new DerOutputStream();
                permitted.encode(tmp);
                tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                        true, TAG_PERMITTED), tmp);
            }
            if ((excluded != null) && (excluded.getSubtrees().size() > 0)) {
                DerOutputStream tmp = new DerOutputStream();
                excluded.encode(tmp);
                tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                        true, TAG_EXCLUDED), tmp);
            }
            if (permitted == null && excluded == null) {
                extensionValue = null; // no need to encode this extension
            } else {
                seq.write(DerValue.tag_Sequence, tagged);
                this.extensionValue = seq.toByteArray();
            }
        }
    }

    /**
     * The default constructor for this class. Either parameter
     * can be set to null to indicate it is omitted but both
     * cannot be null.
     *
     * @param permitted the permitted GeneralSubtrees (null for optional).
     * @param excluded the excluded GeneralSubtrees (null for optional).
     */
    public NameConstraintsExtension(GeneralSubtrees permitted,
                                    GeneralSubtrees excluded)
            throws IOException {
        init(false, permitted, excluded);
    }

    public NameConstraintsExtension(boolean critical,
            GeneralSubtrees permitted, GeneralSubtrees excluded)
            throws IOException {
        init(critical, permitted, excluded);
    }

    private void init(boolean critical,
            GeneralSubtrees permitted, GeneralSubtrees excluded)
            throws IOException {
        if (permitted == null && excluded == null) {
            throw new IOException("NameConstraints: Invalid arguments");
        }
        this.permitted = permitted;
        this.excluded = excluded;

        this.extensionId = PKIXExtensions.NameConstraints_Id;
        this.critical = critical;
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public NameConstraintsExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.NameConstraints_Id;
        this.critical = critical.booleanValue();

        if (!(value instanceof byte[]))
            throw new IOException("Illegal argument type");

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        System.arraycopy(value, 0, extValue, 0, len);

        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for" +
                                  " NameConstraintsExtension.");
        }

        // NB. this is always encoded with the IMPLICIT tag
        // The checks only make sense if we assume implicit tagging,
        // with explicit tagging the form is always constructed.
        while (val.data.available() != 0) {
            DerValue opt = val.data.getDerValue();

            if (opt.isContextSpecific(TAG_PERMITTED) && opt.isConstructed()) {
                if (permitted != null) {
                    throw new IOException("Duplicate permitted " +
                            "GeneralSubtrees in NameConstraintsExtension.");
                }
                opt.resetTag(DerValue.tag_Sequence);
                permitted = new GeneralSubtrees(opt);

            } else if (opt.isContextSpecific(TAG_EXCLUDED) &&
                       opt.isConstructed()) {
                if (excluded != null) {
                    throw new IOException("Duplicate excluded " +
                             "GeneralSubtrees in NameConstraintsExtension.");
                }
                opt.resetTag(DerValue.tag_Sequence);
                excluded = new GeneralSubtrees(opt);
            } else
                throw new IOException("Invalid encoding of " +
                                      "NameConstraintsExtension.");
        }
    }

    /**
     * Return the printable string.
     */
    public String toString() {
        return (super.toString() + "NameConstraints: [" +
                ((permitted == null) ? "" :
                        ("\n    Permitted:" + permitted.toString())) +
                ((excluded == null) ? "" :
                        ("\n    Excluded:" + excluded.toString())) + "   ]\n");
    }

    public String toPrint(int indent) {
        return ("GeneralSubtrees: " +
                ((permitted == null) ? "" :
                        ("\n" + pp.indent(indent + 2) + "Permitted:" + permitted.toPrint(indent + 4))) +
                ((excluded == null) ? "" :
                        ("\n" + pp.indent(indent + 2) + "Excluded:" + excluded.toPrint(indent + 4))) + "\n");

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
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (this.extensionValue == null) {
            this.extensionId = PKIXExtensions.NameConstraints_Id;
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
        if (name.equalsIgnoreCase(PERMITTED_SUBTREES)) {
            if (!(obj instanceof GeneralSubtrees)) {
                throw new IOException("Attribute value should be"
                                    + " of type GeneralSubtrees.");
            }
            permitted = (GeneralSubtrees) obj;
        } else if (name.equalsIgnoreCase(EXCLUDED_SUBTREES)) {
            if (!(obj instanceof GeneralSubtrees)) {
                throw new IOException("Attribute value should be "
                                    + "of type GeneralSubtrees.");
            }
            excluded = (GeneralSubtrees) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:NameConstraintsExtension.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(PERMITTED_SUBTREES)) {
            return (permitted);
        } else if (name.equalsIgnoreCase(EXCLUDED_SUBTREES)) {
            return (excluded);
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:NameConstraintsExtension.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(PERMITTED_SUBTREES)) {
            permitted = null;
        } else if (name.equalsIgnoreCase(EXCLUDED_SUBTREES)) {
            excluded = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:NameConstraintsExtension.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(PERMITTED_SUBTREES);
        elements.addElement(EXCLUDED_SUBTREES);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
