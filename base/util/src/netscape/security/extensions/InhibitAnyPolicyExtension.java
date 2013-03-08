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
import java.lang.reflect.Array;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertAttrSet;
import netscape.security.x509.Extension;
import netscape.security.x509.OIDMap;

/**
 * RFC3280:
 *
 * id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::= { id-ce 54 }
 *
 * InhibitAnyPolicy ::= SkipCerts
 *
 * SkipCerts ::= INTEGER (0..MAX)
 */
public class InhibitAnyPolicyExtension
          extends Extension implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = -8963439897419343166L;
    public static final String OID = "2.5.29.54";
    public static final String NAME = OIDMap.EXT_INHIBIT_ANY_POLICY_NAME;

    private BigInt mSkipCerts = new BigInt(-1);

    static {
        try {
            OIDMap.addAttribute(InhibitAnyPolicyExtension.class.getName(),
                    OID, NAME);
        } catch (CertificateException e) {
        }
    }

    public InhibitAnyPolicyExtension() {
        this(false, null);
    }

    public InhibitAnyPolicyExtension(boolean crit, BigInt skipCerts) {
        try {
            extensionId = ObjectIdentifier.getObjectIdentifier(OID);
        } catch (IOException e) {
            // never here
        }
        critical = crit;
        mSkipCerts = skipCerts;
        encodeExtValue();
    }

    public InhibitAnyPolicyExtension(Boolean crit, Object value)
            throws IOException {
        extensionId = ObjectIdentifier.getObjectIdentifier(OID);
        critical = crit.booleanValue();
        //extensionValue = (byte[]) ((byte[]) byteVal).clone();
        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        for (int i = 0; i < len; i++) {
            extValue[i] = Array.getByte(value, i);
        }

        extensionValue = extValue;
        decodeThis();
    }

    public void setCritical(boolean newValue) {
        if (critical != newValue) {
            critical = newValue;
        }
    }

    public BigInt getSkipCerts() {
        return mSkipCerts;
    }

    @Override
    public String toString() {
        String presentation = "ObjectId: " + OID + " ";

        if (critical) {
            presentation += "Criticality=true";
        } else {
            presentation += "Criticality=false";
        }
        if (extensionValue != null) {
            String extByteValue = " skipCerts=" + mSkipCerts;

            presentation += extByteValue;
        }
        return presentation;
    }

    public void decode(InputStream in)
            throws CertificateException, IOException {
    }

    public void set(String name, Object obj)
            throws CertificateException, IOException {
        // NOT USED
    }

    public Object get(String name) throws CertificateException, IOException {
        // NOT USED
        return null;
    }

    public Enumeration<String> getAttributeNames() {
        return null;
    }

    public String getName() {
        return NAME;
    }

    public void delete(String name)
            throws CertificateException, IOException {
        // NOT USED
    }

    private void decodeThis() throws IOException {
        DerValue val = new DerValue(this.extensionValue);

        mSkipCerts = val.getInteger();
    }

    public void encode(OutputStream out) throws IOException {
        try (DerOutputStream os = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            if (this.extensionValue == null) {
                try {
                    extensionId = ObjectIdentifier.getObjectIdentifier(OID);
                } catch (IOException e) {
                    // never here
                }
                os.putInteger(mSkipCerts);
                this.extensionValue = os.toByteArray();
            }

            super.encode(tmp);
            out.write(tmp.toByteArray());
        }
    }

    private void encodeExtValue() {
        DerOutputStream out = new DerOutputStream();
        try {
            out.putInteger(mSkipCerts);
        } catch (IOException e) {
        }
        extensionValue = out.toByteArray();
    }
}
