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
import java.io.Serializable;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * Represent a X509 Extension Attribute.
 *
 * <p>
 * Extensions are addiitonal attributes which can be inserted in a X509 v3 certificate. For example a
 * "Driving License Certificate" could have the driving license number as a extension.
 *
 * <p>
 * Extensions are represented as a sequence of the extension identifier (Object Identifier), a boolean flag stating
 * whether the extension is to be treated as being critical and the extension value itself (this is again a DER encoding
 * of the extension value).
 *
 * <pre>
 * ASN.1 definition of Extension:
 * Extension ::= SEQUENCE {
 * ExtensionId	OBJECT IDENTIFIER,
 * critical	BOOLEAN DEFAULT FALSE,
 * extensionValue	OCTET STRING
 * }
 * </pre>
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.9
 */
public class Extension implements Serializable {
    private static final long serialVersionUID = -643549610716024753L;
    protected ObjectIdentifier extensionId = null;
    protected boolean critical = false;
    protected byte[] extensionValue = null;

    /**
     * Default constructor. Used only by sub-classes.
     */
    public Extension() {
    }

    /**
     * Constructs an extension from a DER encoded array of bytes.
     */
    public Extension(DerValue derVal) throws IOException {

        DerInputStream in = derVal.toDerInputStream();

        // Object identifier
        extensionId = in.getOID();

        // If the criticality flag was false, it will not have been encoded.
        DerValue val = in.getDerValue();
        if (val.tag == DerValue.tag_Boolean) {
            critical = val.getBoolean();

            // Extension value (DER encoded)
            val = in.getDerValue();
            extensionValue = val.getOctetString();
        } else {
            critical = false;
            extensionValue = val.getOctetString();
        }
    }

    /**
     * Constructs an Extension from individual components of ObjectIdentifier,
     * criticality and the DER encoded OctetString.
     *
     * @param extensionId the ObjectIdentifier of the extension
     * @param critical the boolean indicating if the extension is critical
     * @param extensionValue the DER encoded octet string of the value.
     */
    public Extension(ObjectIdentifier extensionId, boolean critical,
                     byte[] extensionValue) throws IOException {
        this.extensionId = extensionId;
        this.critical = critical;
        // passed in a DER encoded octet string, strip off the tag
        // and length
        DerValue inDerVal = new DerValue(extensionValue);
        this.extensionValue = inDerVal.getOctetString();
    }

    /**
     * Constructs an Extension from another extension. To be used for
     * creating decoded subclasses.
     *
     * @param ext the extension to create from.
     */
    public Extension(Extension ext) {
        this.extensionId = ext.extensionId;
        this.critical = ext.critical;
        this.extensionValue = ext.extensionValue;
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors
     */
    public void encode(DerOutputStream out) throws IOException {
        if (extensionId == null)
            throw new IOException("Null OID to encode for the extension!");

        DerOutputStream bytes = new DerOutputStream();
        bytes.putOID(extensionId);
        if (critical)
            bytes.putBoolean(critical);
        if (extensionValue != null)
            bytes.putOctetString(extensionValue);

        out.write(DerValue.tag_Sequence, bytes);
    }

    /**
     * Returns true if extension is critical.
     */
    public boolean isCritical() {
        return (critical);
    }

    public void setCritical(boolean c) {
        critical = c;
    }

    public void clearValue() {
        extensionValue = null;
    }

    /**
     * Returns the ObjectIdentifier of the extension.
     */
    public ObjectIdentifier getExtensionId() {
        return (extensionId);
    }

    public void setExtensionId(ObjectIdentifier oid) {
        extensionId = oid;
    }

    /**
     * Returns the extension value as an byte array for further processing.
     * Note, this is the raw DER value of the extension, not the DER
     * encoded octet string which is in the certificate.
     */
    public byte[] getExtensionValue() {
        if (extensionValue == null)
            return null;

        byte[] dup = new byte[extensionValue.length];
        System.arraycopy(extensionValue, 0, dup, 0, dup.length);
        return dup;
    }

    public void setExtensionValue(byte value[]) {
        extensionValue = value;
    }

    /**
     * Returns the Extension in user readable form.
     */
    public String toString() {
        String s = "ObjectId: " + extensionId.toString();
        if (critical) {
            s += " Criticality=true\n";
        } else {
            s += " Criticality=false\n";
        }
        return (s);
    }
}
