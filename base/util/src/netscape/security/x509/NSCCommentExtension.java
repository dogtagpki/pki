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
import netscape.security.util.ObjectIdentifier;
import netscape.security.util.PrettyPrintFormat;

/**
 * This class defines the NSCCommentExtension
 *
 * @author asondhi
 * @see Extension
 * @see CertAttrSet
 */
public class NSCCommentExtension extends Extension implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = 4066287070285105375L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.CommentExtension";
    /**
     * Attribute names.
     */
    public static final String NAME = "NSCCommentExtension";
    public static final String INFOS = "infos";
    public static final ObjectIdentifier OID =
            new ObjectIdentifier("2.16.840.1.113730.1.13");
    public String mComment = null;

    // Private data members
    private Vector<Object> mInfos;

    private transient PrettyPrintFormat pp = new PrettyPrintFormat(":");

    // Encode this extension value
    private void encodeThis() throws IOException {
        try (DerOutputStream os = new DerOutputStream()) {
            os.putIA5String(mComment);
            // DerOutputStream tmp = new DerOutputStream();
            // os.write(DerValue.tag_Sequence,tmp);
            extensionValue = os.toByteArray();
        }
    }

    /**
     * Create a NSCCommentExtension with the Vector of CertificatePolicyInfo.
     *
     * @param infos the Vector of CertificatePolicyInfo.
     */
    public NSCCommentExtension(boolean critical, String comment) throws IOException {
        this.mComment = comment;
        this.extensionId = new ObjectIdentifier("2.16.840.1.113730.1.13");
        this.critical = critical;
        encodeThis();
    }

    /**
     * Create a default NSCCommentExtension.
     */
    public NSCCommentExtension(boolean critical) {
        this.extensionId = new ObjectIdentifier("2.16.840.1.113730.1.13");
        this.critical = critical;
        mInfos = new Vector<Object>(1, 1);
    }

    /**
     * Create the extension from the passed DER encoded value.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public NSCCommentExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = new ObjectIdentifier("2.16.840.1.113730.1.13");

        this.critical = critical.booleanValue();

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        for (int i = 0; i < len; i++) {
            extValue[i] = Array.getByte(value, i);
        }
        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);

        mComment = val.getIA5String();
    }

    /**
     * Returns a printable representation of the policy extension.
     */
    public String toString() {
        if (mInfos == null)
            return "";
        String s = super.toString() + "Netscape Comment [\n"
                 + mInfos.toString() + "]\n";

        return (s);
    }

    public String toPrint(int indent) {
        String s;
        s = "Comment :\n" + pp.indent(indent + 4) +
                ((mComment == null) ? "" : mComment.trim()) + "\n";

        return (s);
    }

    /**
     * Write the extension to the OutputStream.
     *
     * @param out the OutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            extensionId = new ObjectIdentifier("2.16.840.1.113730.1.13");
            critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
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

    public String getComment() {
        return mComment;
    }

    /**
     * Set the attribute value.
     */
    @SuppressWarnings("unchecked")
    public void set(String name, Object obj) throws IOException {
        clearValue();
        if (name.equalsIgnoreCase(INFOS)) {
            if (!(obj instanceof Vector)) {
                throw new IOException("Attribute value should be of" +
                                    " type Vector.");
            }
            mInfos = (Vector<Object>) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:NSCCommentExtension.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(INFOS)) {
            return (mInfos);
        } else {
            throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:NSCCommentExtension.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(INFOS)) {
            mInfos = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:NSCCommentExtension.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(INFOS);
        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

}
