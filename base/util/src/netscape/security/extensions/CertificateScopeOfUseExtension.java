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
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertAttrSet;
import netscape.security.x509.Extension;
import netscape.security.x509.OIDMap;

/**
 * This represents the CertificateScopeOfUse extension
 * as defined in draft-thayes-cert-scope-00
 *
 * CertificateScopeEntry ::= SEQUENCE {
 * name GeneralName, -- pattern, as for NameConstraints
 * portNumber INTEGER OPTIONAL
 * }
 * CertificateScopeOfUse ::= SEQUENCE OF CertificateScopeEntry
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CertificateScopeOfUseExtension extends Extension
        implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = 2143292831971567770L;
    public static final String NAME = "CertificateScopeOfUse";
    public static final int OID[] = { 2, 16, 840, 1, 113730, 1, 17 };
    public static final ObjectIdentifier ID = new ObjectIdentifier(OID);

    private Vector<CertificateScopeEntry> mEntries = null;

    static {
        try {
            OIDMap.addAttribute(CertificateScopeOfUseExtension.class.getName(),
                    ID.toString(), NAME);
        } catch (CertificateException e) {
        }
    }

    public CertificateScopeOfUseExtension(boolean critical, Vector<CertificateScopeEntry> scopeEntries)
            throws IOException {
        this.extensionId = ID;
        this.critical = critical;
        this.extensionValue = null; // build this when encodeThis() is called
        mEntries = scopeEntries;
        encodeThis();
    }

    public CertificateScopeOfUseExtension(boolean critical) {
        this.extensionId = ID;
        this.critical = critical;
        this.extensionValue = null; // build this when encodeThis() is called
    }

    public CertificateScopeOfUseExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = ID;
        this.critical = critical.booleanValue();
        this.extensionValue = ((byte[]) value).clone();
        decodeThis();
    }

    public String getName() {
        return NAME;
    }

    public Vector<CertificateScopeEntry> getCertificateScopeEntries() {
        return mEntries;
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

    private void decodeThis() throws IOException {
        DerValue val = new DerValue(this.extensionValue);

        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding of CertificateWindow extension");
        }
        mEntries = new Vector<CertificateScopeEntry>();
        while (val.data.available() != 0) {
            mEntries.addElement(new CertificateScopeEntry(
                    val.data.getDerValue()));
        }
    }

    private void encodeThis() throws IOException {
        try (DerOutputStream seq = new DerOutputStream();
             DerOutputStream tmp = new DerOutputStream()) {

            if (mEntries == null)
                throw new IOException("Invalid Scope Entries");

            for (int i = 0; i < mEntries.size(); i++) {
                CertificateScopeEntry se = mEntries.elementAt(i);

                se.encode(tmp);
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
        StringBuffer s = new StringBuffer(super.toString() + "CertificateUseOfScope [\n");

        if (mEntries != null) {
            for (int i = 0; i < mEntries.size(); i++) {
                CertificateScopeEntry se = mEntries.elementAt(i);

                s.append(se.toString());
            }
        }
        return (s.toString() + "]\n");
    }
}
