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

import netscape.security.util.BitArray;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertAttrSet;
import netscape.security.x509.Extension;

/**
 * NSCertTypeExtension
 * Represents Netscape Certificate Type Extension
 *
 * <p>
 * This deprecated extension, if present, defines both the purpose (e.g., encipherment, signature, certificate signing)
 * and the application (e.g., SSL, S/Mime or Object Signing of the key contained in the certificate.
 *
 * @author galperin
 * @version $Revision$, $Date$
 */
public class NSCertTypeExtension extends Extension implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = 1856407688086284397L;

    // The object identifiers
    private static final int CertType_data[] = { 2, 16, 840, 1, 113730, 1, 1 };

    /**
     * Identifies the particular public key used to sign the certificate.
     */
    public static final ObjectIdentifier CertType_Id = new
            ObjectIdentifier(CertType_data);

    /**
     * Attribute names.
     */
    public static final String NAME = "NSCertType";
    public static final String SSL_CLIENT = "ssl_client";
    public static final String SSL_SERVER = "ssl_server";
    public static final String EMAIL = "email";
    public static final String OBJECT_SIGNING = "object_signing";
    public static final String SSL_CA = "ssl_ca";
    public static final String EMAIL_CA = "email_ca";
    public static final String OBJECT_SIGNING_CA = "object_signing_ca";

    /**
     * Attribute names.
     */
    public static final int SSL_CLIENT_BIT = 0;
    public static final int SSL_SERVER_BIT = 1;
    public static final int EMAIL_BIT = 2;
    public static final int OBJECT_SIGNING_BIT = 3;
    // 4 is reserved.
    public static final int SSL_CA_BIT = 5;
    public static final int EMAIL_CA_BIT = 6;
    public static final int OBJECT_SIGNING_CA_BIT = 7;

    public static final int NBITS = 8;

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.NSCertType";

    // Private data members
    private byte[] mBitString;

    private static class MapEntry {
        String mName;
        int mPosition;

        MapEntry(String name, int position) {
            mName = name;
            mPosition = position;
        }
    }

    private static MapEntry[] mMapData =
        {
                new MapEntry(SSL_CLIENT, 0),
                new MapEntry(SSL_SERVER, 1),
                new MapEntry(EMAIL, 2),
                new MapEntry(OBJECT_SIGNING, 3),
                // note that bit 4 is reserved
                new MapEntry(SSL_CA, 5),
                new MapEntry(EMAIL_CA, 6),
                new MapEntry(OBJECT_SIGNING_CA, 7),
        };

    private static Vector<String> mAttributeNames = new Vector<String>();

    static {
        for (int i = 0; i < mMapData.length; ++i) {
            mAttributeNames.addElement(mMapData[i].mName);
        }
    }

    private static int getPosition(String name) throws CertificateException {
        for (int i = 0; i < mMapData.length; ++i) {
            if (name.equalsIgnoreCase(mMapData[i].mName))
                return mMapData[i].mPosition;
        }
        throw new CertificateException("Attribute name [" + name
                + "] not recognized by"
                + " CertAttrSet:NSCertType.");
    }

    // Encode this extension value
    private void encodeThis() throws IOException {
        try (DerOutputStream os = new DerOutputStream()) {

            os.putUnalignedBitString(mBitString);
            this.extensionValue = os.toByteArray();
        }
    }

    /**
     * Check if bit is set.
     *
     * @param position the position in the bit string to check.
     */
    public boolean isSet(int position) {
        int index = position / 8;
        byte pos = (byte) (1 << (7 - (position % 8)));

        if (mBitString.length <= index)
            return false;
        return ((mBitString[index] & pos) != 0);
    }

    /**
     * Set the bit at the specified position.
     */
    public void set(int position, boolean val) {
        int index = position / 8;
        byte pos = (byte) (1 << (7 - (position % 8)));

        if (index >= mBitString.length) {
            byte[] tmp = new byte[index + 1];

            System.arraycopy(mBitString, 0, tmp, 0, mBitString.length);
            mBitString = tmp;
        }
        if (val) {
            mBitString[index] |= pos;
        } else {
            mBitString[index] &= ~pos;
        }
    }

    /**
     * Create NSCertTypeExtension from boolean array.
     * The criticality is set to false.
     */
    public NSCertTypeExtension(boolean critical, boolean[] bits) {
        this.extensionId = CertType_Id;
        this.critical = critical;
        this.mBitString = new byte[0];

        for (int i = 0; i < bits.length && i < 8; i++) {
            set(i, bits[i]);
        }
    }

    public NSCertTypeExtension(boolean[] bits) {
        this.extensionId = CertType_Id;
        this.critical = false;
        this.mBitString = new byte[0];

        for (int i = 0; i < bits.length && i < 8; i++) {
            set(i, bits[i]);
        }
    }

    /**
     * Create a NSCertTypeExtension with the passed bit settings.
     * The criticality is set to false.
     *
     * @param bitString the bits to be set for the extension.
     */
    public NSCertTypeExtension(boolean critical, byte[] bitString) throws IOException {
        this.mBitString = bitString;
        this.extensionId = CertType_Id;
        this.critical = critical;
        encodeThis();
    }

    public NSCertTypeExtension(byte[] bitString) throws IOException {
        this.mBitString = bitString;
        this.extensionId = CertType_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public NSCertTypeExtension(Boolean critical, Object value)
            throws IOException {

        /**
         * Debug.trace("NSCertTypeExtension");
         * this.mBitString = new byte[1];
         * this.mBitString[0] = (byte)0x00;
         * return;
         **/

        this.extensionId = CertType_Id;
        this.critical = critical.booleanValue();
        byte[] extValue = ((byte[]) value).clone();

        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        BitArray bitArray = val.getUnalignedBitString();
        if (bitArray == null) {
            throw new IOException("Invalid Encoded DER Value");
        }
        this.mBitString = bitArray.toByteArray();
    }

    /**
     * Create a default key usage.
     */
    public NSCertTypeExtension() {
        this.extensionId = CertType_Id;
        this.critical = false;
        this.mBitString = new byte[0];
        try {
            encodeThis();
        } catch (Exception e) {
        }
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws CertificateException {
        if (!(obj instanceof Boolean)) {
            throw new CertificateException("Attribute must be of type Boolean.");
        }
        boolean val = ((Boolean) obj).booleanValue();

        set(getPosition(name), val);
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws CertificateException {
        return Boolean.valueOf(isSet(getPosition(name)));
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws CertificateException {
        set(getPosition(name), false);
    }

    /**
     * Returns a printable representation of the NSCertType.
     */
    public String toString() {
        String s = super.toString() + "NSCertType [\n";

        try {

            if (isSet(getPosition(SSL_CLIENT))) {
                s += "   SSL client";
            }
            if (isSet(getPosition(SSL_SERVER))) {
                s += "   SSL server";
            }

            if (isSet(getPosition(EMAIL))) {
                s += "   Email";
            }

            if (isSet(getPosition(OBJECT_SIGNING))) {
                s += "   Object Signing";
            }

            if (isSet(getPosition(SSL_CA))) {
                s += "   SSL CA";
            }

            if (isSet(getPosition(EMAIL_CA))) {
                s += "   Email CA";
            }

            if (isSet(getPosition(OBJECT_SIGNING_CA))) {
                s += "   Object Signing CA";
            }

        } catch (Exception e) {
            // this is reached only if there is a bug
            throw new IllegalArgumentException(e.getMessage());
        }

        s += "]\n";

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

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        encodeThis();
        if (this.extensionValue == null) {
            this.extensionId = CertType_Id;
            this.critical = true;
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        return mAttributeNames.elements();
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    public static void main(String[] argv) {
    }
}
