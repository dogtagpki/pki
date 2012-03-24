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


import netscape.security.x509.*;
import netscape.security.util.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.io.*;


/**
 * This represents the extended key usage extension.
 */
public class ExtendedKeyUsageExtension extends Extension implements CertAttrSet {

    public static final String OID = "2.5.29.37";
    public static final String NAME = OIDMap.EXT_KEY_USAGE_NAME;
    public static final String OID_OCSPSigning = "1.3.6.1.5.5.7.3.9";
    public static final String OID_CODESigning = "1.3.6.1.5.5.7.3.3";

    public static final int OID_OCSP_SIGNING_STR[] = 
        { 1, 3, 6, 1, 5, 5, 7, 3, 9 };
    public static final ObjectIdentifier OID_OCSP_SIGNING = new
        ObjectIdentifier(OID_OCSP_SIGNING_STR);

    public static final int OID_CODE_SIGNING_STR[] = 
        { 1, 3, 6, 1, 5, 5, 7, 3, 3 };
    public static final ObjectIdentifier OID_CODE_SIGNING = new
        ObjectIdentifier(OID_OCSP_SIGNING_STR);

    private Vector oidSet = null;
    private byte mCached[] = null;

    static {
        try {
            OIDMap.addAttribute(ExtendedKeyUsageExtension.class.getName(),
                OID, NAME);
        } catch (CertificateException e) {
        }
    }

    public ExtendedKeyUsageExtension() {
        this(false, null);
    }

    public ExtendedKeyUsageExtension(boolean crit, Vector oids) {
        try {
            extensionId = ObjectIdentifier.getObjectIdentifier(OID);
        } catch (IOException e) {	
            // never here
        }
        critical = crit;
        if (oids != null) {
            oidSet = (Vector) oids.clone();
        } else {
            oidSet = new Vector();
        }
        encodeExtValue();
    }

    public ExtendedKeyUsageExtension(Boolean crit, Object byteVal) 
        throws IOException {
        extensionId = ObjectIdentifier.getObjectIdentifier(OID);
        critical = crit.booleanValue();
        extensionValue = (byte[]) ((byte[]) byteVal).clone();
        decodeThis();
    }

    public void setCritical(boolean newValue) {
        if (critical != newValue) {
            critical = newValue;
            mCached = null;
        }
    }
    
    public Enumeration getOIDs() {
        if (oidSet == null)
            return null;
        return oidSet.elements();
    }

    public void deleteAllOIDs() {
        if (oidSet == null)
		return;
	oidSet.clear();
    }

    public void addOID(ObjectIdentifier oid) {
        if (oidSet == null) {
            oidSet = new Vector();
        }
        
        if (oidSet.contains(oid)) return;
        oidSet.addElement(oid);
        mCached = null;
    }
         
    public void encode(DerOutputStream out) throws IOException {
        if (mCached == null) {
            encodeExtValue();
            super.encode(out);  
            mCached = out.toByteArray();
        }
    }

    public String toString() {
        String presentation = "oid=" + ExtendedKeyUsageExtension.OID + " ";

        if (critical) {
            presentation += "critical=true";
        }
        if (extensionValue != null) {
            String extByteValue = new String(" val=");

            for (int i = 0; i < extensionValue.length; i++) {
                extByteValue += (extensionValue[i] + " ");
            }
            presentation += extByteValue;    
        }
        return presentation;
    }

    public void decode(InputStream in) 
        throws CertificateException, IOException {
    }

    public void encode(OutputStream out) 
        throws CertificateException, IOException {
        if (mCached == null) {
            DerOutputStream temp = new DerOutputStream();

            encode(temp);
        }
        out.write(mCached);
    }

    public void set(String name, Object obj) 
        throws CertificateException, IOException {
        // NOT USED
    }

    public Object get(String name) throws CertificateException, IOException {
        // NOT USED
        return null;
    }

    public Enumeration getElements() {
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

        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding of AuthInfoAccess extension"
                );
        }
        if (oidSet == null)
            oidSet = new Vector();
        while (val.data.available() != 0) {
            DerValue oidVal = val.data.getDerValue();

            oidSet.addElement(oidVal.getOID());
        }
    }

    private void encodeExtValue() {
        DerOutputStream out = new DerOutputStream();
        DerOutputStream temp = new DerOutputStream();
 
        if (!oidSet.isEmpty()) {
            Enumeration oidList = oidSet.elements();

            try {
                while (oidList.hasMoreElements()) {
                    temp.putOID((ObjectIdentifier) oidList.nextElement());
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

        try {
            out.write(DerValue.tag_Sequence, temp);
        } catch (IOException ex) {
        }

        extensionValue = out.toByteArray();
    }
}
