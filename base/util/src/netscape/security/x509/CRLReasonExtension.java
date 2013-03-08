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
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Represent the CRLReason Extension of CRL entry.
 *
 * <p>
 * This extension, if present, defines the identifies the reason for the certificate revocation.
 *
 * @author galperin
 * @version $Revision$, $Date$
 * @see Extension
 * @see CertAttrSet
 */

public final class CRLReasonExtension extends Extension implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = 4544973296866779535L;
    /**
     * Canned instances for all revocation reasons
     */
    public static final CRLReasonExtension UNSPECIFIED = new CRLReasonExtension(RevocationReason.UNSPECIFIED);
    public static final CRLReasonExtension KEY_COMPROMISE = new CRLReasonExtension(RevocationReason.KEY_COMPROMISE);
    public static final CRLReasonExtension CA_COMPROMISE = new CRLReasonExtension(RevocationReason.CA_COMPROMISE);
    public static final CRLReasonExtension AFFILIATION_CHANGED = new CRLReasonExtension(
            RevocationReason.AFFILIATION_CHANGED);
    public static final CRLReasonExtension SUPERSEDED = new CRLReasonExtension(RevocationReason.SUPERSEDED);
    public static final CRLReasonExtension CESSATION_OF_OPERATION = new CRLReasonExtension(
            RevocationReason.CESSATION_OF_OPERATION);
    public static final CRLReasonExtension CERTIFICATE_HOLD = new CRLReasonExtension(RevocationReason.CERTIFICATE_HOLD);
    public static final CRLReasonExtension REMOVE_FROM_CRL = new CRLReasonExtension(RevocationReason.REMOVE_FROM_CRL);
    public static final CRLReasonExtension PRIVILEGE_WITHDRAWN = new CRLReasonExtension(
            RevocationReason.PRIVILEGE_WITHDRAWN);
    public static final CRLReasonExtension AA_COMPROMISE = new CRLReasonExtension(RevocationReason.AA_COMPROMISE);

    /**
     * Attribute names.
     */
    public static final String NAME = "CRLReason";
    public static final String REASON = "value";

    private RevocationReason mReason = null;

    public RevocationReason getReason() {
        return mReason;
    }

    /**
     * Default constructor
     *
     */

    public CRLReasonExtension() {
        this.extensionId = PKIXExtensions.ReasonCode_Id;
        this.critical = false;
        mReason = null;
    }

    /**
     * Create extension value for specific revocation reason
     *
     */

    public CRLReasonExtension(RevocationReason reason) {
        this.extensionId = PKIXExtensions.ReasonCode_Id;
        this.critical = false;
        mReason = reason;
    }

    public CRLReasonExtension(Boolean critical, RevocationReason reason)
                throws IOException {
        this.extensionId = PKIXExtensions.ReasonCode_Id;
        this.critical = critical.booleanValue();
        mReason = reason;
    }

    /**
     * Create the object from the passed DER encoded value.
     *
     * @param derVal the DerValue decoded from the stream.
     * @exception IOException on decoding errors.
     */
    public CRLReasonExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.ReasonCode_Id;
        this.critical = critical.booleanValue();

        byte[] extValue = ((byte[]) value).clone();
        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        int reasonCode = val.getEnumerated();
        mReason = RevocationReason.fromInt(reasonCode);
        if (mReason == null)
            throw new IOException("Unknown revocation reason value " + reasonCode);
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (!(obj instanceof RevocationReason)) {
            throw new IOException("Attribute must be of type RevocationReason.");
        }

        if (name.equalsIgnoreCase(REASON)) {
            mReason = (RevocationReason) obj;
        } else {
            throw new IOException("Name not recognized by CRLReason");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(REASON)) {
            return mReason;
        } else {
            throw new IOException("Name not recognized by CRLReason");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(REASON)) {
            mReason = null;
        } else {
            throw new IOException("Name not recognized by CRLReason");
        }
    }

    /**
     * Returns a printable representation of the ReasonFlags.
     */
    public String toString() {
        String s = super.toString() + "CRL Reason [" + mReason + "]\n";
        return (s);
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

    // Encode this extension value
    private void encodeThis() throws IOException {
        if (mReason == null)
            throw new IOException("Unintialized CRLReason extension");
        try (DerOutputStream os = new DerOutputStream()) {
            os.putEnumerated(mReason.toInt());
            this.extensionValue = os.toByteArray();
        }
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the OutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        if (this.extensionValue == null) {
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());

    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(REASON);

        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    public boolean equals(Object other) {
        if (this == other)
            return true;
        else if (other instanceof CRLReasonExtension)
            return ((CRLReasonExtension) other).mReason == mReason &&
                    ((CRLReasonExtension) other).critical == critical;
        else
            return false;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mReason == null) ? 0 : mReason.hashCode());
        return result;
    }

}
