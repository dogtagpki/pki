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

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertAttrSet;
import netscape.security.x509.Extension;

public class PresenceServerExtension extends Extension implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = -6333109673043357921L;
    private boolean mCritical;
    private int mVersion = 0;
    private String mStreetAddress = null;
    private String mTelephoneNumber = null;
    private String mRFC822Name = null;
    private String mID = null;
    private String mHostName = null;
    private int mPortNumber = 0;
    private int mMaxUsers = 0;
    private int mServiceLevel = 0;

    public static final String OID = "2.16.840.1.113730.1.18";

    /*
        public PresenceServerExtension()
        {
        }
    */

    public PresenceServerExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = new ObjectIdentifier(OID);
        this.critical = critical.booleanValue();
        this.extensionValue = ((byte[]) value).clone();
        decodeThis();
    }

    public PresenceServerExtension(
            boolean critical,
            int version,
            String streetAddress,
            String telephoneNumber,
            String rfc822Name,
            String ID,
            String hostName,
            int portNumber,
            int maxUsers,
            int serviceLevel)
            throws IOException {
        mCritical = critical;
        mVersion = version;
        mStreetAddress = streetAddress;
        mTelephoneNumber = telephoneNumber;
        mRFC822Name = rfc822Name;
        mID = ID;
        mHostName = hostName;
        mPortNumber = portNumber;
        mMaxUsers = maxUsers;
        mServiceLevel = serviceLevel;

        this.extensionId = new ObjectIdentifier(OID);
        this.critical = mCritical;
        encodeThis();
    }

    public int getVersion() {
        return mVersion;
    }

    public String getStreetAddress() {
        return mStreetAddress;
    }

    public String getTelephoneNumber() {
        return mTelephoneNumber;
    }

    public String getRFC822() {
        return mRFC822Name;
    }

    public String getID() {
        return mID;
    }

    public String getHostName() {
        return mHostName;
    }

    public int getPortNumber() {
        return mPortNumber;
    }

    public int getMaxUsers() {
        return mMaxUsers;
    }

    public int getServiceLevel() {
        return mServiceLevel;
    }

    public void encodeThis() throws IOException {
        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream temp = new DerOutputStream();
            temp.putInteger(new BigInt(mVersion));
            temp.putOctetString(mStreetAddress.getBytes());
            temp.putOctetString(mTelephoneNumber.getBytes());
            temp.putOctetString(mRFC822Name.getBytes());
            temp.putOctetString(mID.getBytes());
            temp.putOctetString(mHostName.getBytes());
            temp.putInteger(new BigInt(mPortNumber));
            temp.putInteger(new BigInt(mMaxUsers));
            temp.putInteger(new BigInt(mServiceLevel));
            out.write(DerValue.tag_Sequence, temp);
            this.extensionValue = out.toByteArray();
        }
    }

    public void decodeThis() throws IOException {
        DerInputStream val = new DerInputStream(this.extensionValue);
        byte data[] = null;
        DerValue seq[] = val.getSequence(0);

        mVersion = seq[0].getInteger().toInt();
        data = null;
        if (seq[1].length() > 0) {
            data = seq[1].getOctetString();
        }
        if (data == null) {
            mStreetAddress = "";
        } else {
            mStreetAddress = new String(data);
        }
        data = null;
        if (seq[2].length() > 0)
            data = seq[2].getOctetString();
        if (data == null) {
            mTelephoneNumber = "";
        } else {
            mTelephoneNumber = new String(data);
        }
        data = null;
        if (seq[3].length() > 0)
            data = seq[3].getOctetString();
        if (data == null) {
            mRFC822Name = "";
        } else {
            mRFC822Name = new String(data);
        }
        data = null;
        if (seq[4].length() > 0)
            data = seq[4].getOctetString();
        if (data == null) {
            mID = "";
        } else {
            mID = new String(data);
        }
        data = null;
        if (seq[5].length() > 0)
            data = seq[5].getOctetString();
        if (data == null) {
            mHostName = "";
        } else {
            mHostName = new String(data);
        }
        mPortNumber = seq[6].getInteger().toInt();
        mMaxUsers = seq[7].getInteger().toInt();
        mServiceLevel = seq[8].getInteger().toInt();
    }

    public void decode(InputStream in)
            throws CertificateException, IOException {
    }

    public void encode(OutputStream out)
            throws CertificateException, IOException {
        DerOutputStream dos = new DerOutputStream();
        super.encode(dos);
        out.write(dos.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        throw new IOException("Method not to be called directly.");
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        return null;
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        throw new IOException("Method not to be called directly.");
    }

    public Enumeration<String> getAttributeNames() {
        return null;
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return "PresenceServerExtension";
    }

    /**
     * Set the name of this attribute.
     */
    public void setName(String name) {
    }

    /**
     * Return the OID of this attribute.
     */
    public String getOID() {
        return OID;
    }

    /**
     * Set the OID of this attribute.
     */
    public void setOID(String oid) {
    }

    public static void main(String args[]) {
        /*
           0 30  115: SEQUENCE {
           2 06    9:   OBJECT IDENTIFIER '2 16 840 1 113730 1 100'
          13 04  102:   OCTET STRING, encapsulates {
          15 30  100:       SEQUENCE {
          17 02    1:         INTEGER 0
          20 04   31:         OCTET STRING
                    :           34 30 31 45 20 4D 69 64 64 6C 65 66 69 65 6C 64
                    :           20 52 64 2E 2C 4D 56 2C 43 41 39 34 30 34 31
          53 04   12:         OCTET STRING
                    :           36 35 30 2D 31 31 31 2D 31 31 31 31
          67 04   18:         OCTET STRING
                    :           61 64 6D 69 6E 40 6E 65 74 73 63 61 70 65 2E 63
                    :           6F 6D
          87 04   10:         OCTET STRING
                    :           70 73 2D 63 61 70 69 74 6F 6C
          99 04    7:         OCTET STRING
                    :           63 61 70 69 74 6F 6C
         108 02    1:         INTEGER 80
         111 02    1:         INTEGER 10
         114 02    1:         INTEGER 1
                    :         }
                    :       }
                    :   }
         */
        ByteArrayOutputStream dos = null;
        FileOutputStream fos = null;
        try {
            boolean critical = false;
            int version = 1;
            String streetAddress = "401E Middlefield Rd.,MV,CA94041";
            String telephoneNumber = "650-111-1111";
            String rfc822Name = "admin@netscape.com";
            String ID = "ps-capitol";
            String hostName = "capitol";
            int portNumber = 80;
            int maxUsers = 10;
            int serviceLevel = 1;

            PresenceServerExtension ext = new PresenceServerExtension(
                    critical,
                    version, streetAddress, telephoneNumber,
                    rfc822Name, ID, hostName, portNumber,
                    maxUsers, serviceLevel);

            // encode

            dos = new ByteArrayOutputStream();
            ext.encode(dos);
            fos = new FileOutputStream("pse.der");
            fos.write(dos.toByteArray());
            Extension ext1 = new Extension(new DerValue(dos.toByteArray()));

            @SuppressWarnings("unused")
            PresenceServerExtension ext2 = new PresenceServerExtension(
                    Boolean.valueOf(false), ext1.getExtensionValue());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } finally {
            if (dos != null) {
                try {
                    dos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
