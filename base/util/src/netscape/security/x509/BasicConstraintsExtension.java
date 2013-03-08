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
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class represents the Basic Constraints Extension.
 *
 * <p>
 * The basic constraints extension identifies whether the subject of the certificate is a CA and how deep a
 * certification path may exist through that CA.
 *
 * <pre>
 * The ASN.1 syntax for this extension is:
 * BasicConstraints ::= SEQUENCE {
 *     cA                BOOLEAN DEFAULT FALSE,
 *     pathLenConstraint INTEGER (0..MAX) OPTIONAL
 * }
 * </pre>
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.7
 * @see CertAttrSet
 * @see Extension
 */
public class BasicConstraintsExtension extends Extension
        implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = 6213957094939885889L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.BasicConstraints";
    /**
     * Attribute names.
     */
    public static final String NAME = "BasicConstraints";
    public static final String IS_CA = "is_ca";
    public static final String PATH_LEN = "path_len";

    // Private data members
    private boolean ca = false;
    private int pathLen = -1;

    // Encode this extension value
    private void encodeThis() throws IOException {
        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            if (ca) {
                tmp.putBoolean(ca);
            }
            if (pathLen >= 0) {
                tmp.putInteger(new BigInt(pathLen));
            }
            out.write(DerValue.tag_Sequence, tmp);
            this.extensionValue = out.toByteArray();
        }
    }

    /**
     * Default constructor for this object.
     *
     * @param ca true, if the subject of the Certificate is a CA.
     * @param len specifies the depth of the certification path.
     */
    public BasicConstraintsExtension(boolean ca, int len) throws IOException {
        this.ca = ca;
        this.pathLen = len;
        this.extensionId = PKIXExtensions.BasicConstraints_Id;
        if (ca) {
            critical = true;
        } else {
            critical = false;
        }
        encodeThis();
    }

    /**
     * Default constructor for this object.
     *
     * @param ca true, if the subject of the Certificate is a CA.
     * @param len specifies the depth of the certification path.
     */
    public BasicConstraintsExtension(boolean ca, boolean critical, int len) throws IOException {
        this.ca = ca;
        this.pathLen = len;
        this.extensionId = PKIXExtensions.BasicConstraints_Id;
        this.critical = critical;
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param extension the DER encoded value of the extension.
     * @exception IOException on error.
     */
    public BasicConstraintsExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.BasicConstraints_Id;
        this.critical = critical.booleanValue();

        if (value instanceof byte[]) {
            int len = Array.getLength(value);
            byte[] extValue = new byte[len];
            System.arraycopy(value, 0, extValue, 0, len);

            this.extensionValue = extValue;
            DerValue val = new DerValue(extValue);
            if (val.tag != DerValue.tag_Sequence) {
                throw new IOException("Invalid encoding of BasicConstraints");
            }

            // non-CA cert with no limit to certification path length
            if (val.data == null || val.data.available() < 1) {
                this.ca = false;
                this.pathLen = -1;
                return;
            }
            DerValue opt = val.data.getDerValue();
            if (opt.tag != DerValue.tag_Boolean) {
                this.ca = false;
            } else {
                this.ca = true;
                if (val.data.available() != 0) {
                    opt = val.data.getDerValue();
                } else {
                    this.pathLen = -1;
                    return;
                }
            }
            if (opt.tag != DerValue.tag_Integer) {
                throw new IOException("Invalid encoding of BasicConstraints");
            }
            this.pathLen = (opt.getInteger()).toInt();
            /*
             * Activate this check once again after PKIX profiling
             * is a standard and this check no longer imposes an
             * interoperability barrier.
             * if (ca) {
             *   if (!this.critical) {
             *   throw new IOException("Criticality cannot be false for CA.");
             *   }
             * }
             */
        } else
            throw new IOException("Invalid argument type");
    }

    /**
     * Return user readable form of extension.
     */
    public String toString() {
        String s = super.toString() + "BasicConstraints:[\n";

        s += ((ca) ? ("CA:true") : ("CA:false")) + "\n";
        if (pathLen >= 0) {
            s += "PathLen:" + pathLen + "\n";
        } else {
            s += "PathLen: undefined\n";
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
     * Encode this extension value to the output stream.
     *
     * @param out the DerOutputStream to encode the extension to.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            this.extensionId = PKIXExtensions.BasicConstraints_Id;
            /* #57286 - so that profile can set critiality */
            /*
                         if (ca) {
            	         critical = true;
                         } else {
            	         critical = false;
                         }
            */
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
        if (name.equalsIgnoreCase(IS_CA)) {
            if (!(obj instanceof Boolean)) {
                throw new IOException("Attribute value should be of type Boolean.");
            }
            ca = ((Boolean) obj).booleanValue();
        } else if (name.equalsIgnoreCase(PATH_LEN)) {
            if (!(obj instanceof Integer)) {
                throw new IOException("Attribute value should be of type Integer.");
            }
            pathLen = ((Integer) obj).intValue();
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:BasicConstraints.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(IS_CA)) {
            return (Boolean.valueOf(ca));
        } else if (name.equalsIgnoreCase(PATH_LEN)) {
            return (Integer.valueOf(pathLen));
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:BasicConstraints.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(IS_CA)) {
            ca = false;
        } else if (name.equalsIgnoreCase(PATH_LEN)) {
            pathLen = -1;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:BasicConstraints.");
        }
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(IS_CA);
        elements.addElement(PATH_LEN);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
