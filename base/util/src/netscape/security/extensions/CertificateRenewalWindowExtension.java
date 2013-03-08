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
package netscape.security.extensions;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertAttrSet;
import netscape.security.x509.Extension;

/**
 * This represents the CertificateRenewalWindow extension
 * as defined in draft-thayes-cert-renewal-00
 *
 * CertificateRenewalWindow ::= SEQUENCE {
 * beginTime GeneralizedTime,
 * endTime GeneralizedTime OPTIONAL }
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CertificateRenewalWindowExtension extends Extension
        implements CertAttrSet {
    private static final long serialVersionUID = 4470220533545299271L;
    public static final String NAME = "CertificateRenewalWindow";
    public static final int OID[] = { 2, 16, 840, 1, 113730, 1, 15 };
    public static final ObjectIdentifier ID = new ObjectIdentifier(OID);

    private Date mBeginTime = null;
    private Date mEndTime = null; // optional

    public CertificateRenewalWindowExtension(boolean critical, Date beginTime,
            Date endTime) throws IOException {
        this.extensionId = ID;
        this.critical = critical;
        mBeginTime = beginTime;
        mEndTime = endTime;
        encodeThis();
    }

    public CertificateRenewalWindowExtension(boolean critical) {
        this.extensionId = ID;
        this.critical = critical;
        this.extensionValue = null; // build this when encodeThis() is called
    }

    public CertificateRenewalWindowExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = ID;
        this.critical = critical.booleanValue();
        this.extensionValue = ((byte[]) value).clone();
        decodeThis();
    }

    public String getName() {
        return NAME;
    }

    /**
     * Sets extension attribute.
     */
    public void set(String name, Object obj) throws CertificateException {
        // NOT USED
    }

    /**
     * Retrieves extension attribute.
     */
    public Object get(String name) throws CertificateException {
        // NOT USED
        return null;
    }

    /**
     * Deletes attribute.
     */
    public void delete(String name) throws CertificateException {
        // NOT USED
    }

    /**
     * Decodes this extension.
     */
    public void decode(InputStream in) throws IOException {
        // NOT USED
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        // NOT USED
        return null;
    }

    public Date getBeginTime() {
        return mBeginTime;
    }

    public Date getEndTime() {
        return mEndTime;
    }

    public void setBeginTime(Date d) {
        mBeginTime = d;
    }

    public void setEndTime(Date d) {
        mEndTime = d;
    }

    private void decodeThis() throws IOException {
        DerValue val = new DerValue(this.extensionValue);

        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding of CertificateWindow extension");
        }
        while (val.data.available() != 0) {
            if (mBeginTime == null) {
                mBeginTime = val.data.getGeneralizedTime();
            } else {
                mEndTime = val.data.getGeneralizedTime();
            }
        }
    }

    private void encodeThis() throws IOException {
        try (DerOutputStream seq = new DerOutputStream();
             DerOutputStream tmp = new DerOutputStream()) {

            tmp.putGeneralizedTime(mBeginTime);
            if (mEndTime != null) {
                tmp.putGeneralizedTime(mEndTime);
            }
            seq.write(DerValue.tag_Sequence, tmp);
            this.extensionValue = seq.toByteArray();
        }
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
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
     * Returns a printable representation of the CertificateRenewalWindow.
     */
    public String toString() {
        String s = super.toString() + "CertificateRenewalWindow [\n";

        s += "BeginTime: " + mBeginTime + "\n";
        if (mEndTime != null) {
            s += "EndTime: " + mEndTime;
        }
        return (s + "]\n");
    }
}
