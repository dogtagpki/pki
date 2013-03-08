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
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

import com.netscape.cmsutil.util.Utils;

/**
 * This class defines the Certificate Policies Extension.
 *
 * <p>
 * The certificate policies extension conatins a sequence of policy information terms, each of which consists of an
 * object identifier (OID) and optional qualifiers. These policy information terms indicate the policy under which the
 * certificate has been issued and the purposes for which the certificate may be used. Aplications with specific policy
 * requirements are expected to have a list of those policies which they will accept and to compare the policy OIDs in
 * the certificate to that list. If this extension is critical, the path validation software must be able to interpret
 * this extension, or must reject the certificate.
 *
 * <pre>
 * CertificatePolicies ::= SEQUENECE OF PolicyInformation
 * </pre>
 *
 * @author Christine Ho
 * @see Extension
 * @see CertAttrSet
 */
public class CertificatePoliciesExtension extends Extension
        implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = -3729294064061837367L;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.extensions.CertificatePolicies";
    /**
     * Attribute names.
     */
    public static final String NAME = "CertificatePolicies";
    public static final String INFOS = "infos";

    // Private data members
    private Vector<CertificatePolicyInfo> mInfos;

    // Encode this extension value
    private void encodeThis() throws IOException {
        try (DerOutputStream os = new DerOutputStream();) {
            DerOutputStream tmp = new DerOutputStream();

            for (int i = 0; i < mInfos.size(); i++) {
                mInfos.elementAt(i).encode(tmp);
            }
            os.write(DerValue.tag_Sequence, tmp);
            extensionValue = os.toByteArray();
        }
    }

    public CertificatePoliciesExtension(boolean critical, Vector<CertificatePolicyInfo> infos) throws IOException {
        this.mInfos = infos;
        this.extensionId = PKIXExtensions.CertificatePolicies_Id;
        this.critical = critical;
        encodeThis();
    }

    /**
     * Create a CertificatePolicies with the Vector of CertificatePolicyInfo.
     *
     * @param infos the Vector of CertificatePolicyInfo.
     */
    public CertificatePoliciesExtension(Vector<CertificatePolicyInfo> infos) throws IOException {
        this.mInfos = infos;
        this.extensionId = PKIXExtensions.CertificatePolicies_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create a default CertificatePoliciesExtension.
     */
    public CertificatePoliciesExtension() {
        this.extensionId = PKIXExtensions.CertificatePolicies_Id;
        critical = false;
        mInfos = new Vector<CertificatePolicyInfo>(1, 1);
    }

    /**
     * Create the extension from the passed DER encoded value.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public CertificatePoliciesExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.CertificatePolicies_Id;
        this.critical = critical.booleanValue();

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        for (int i = 0; i < len; i++) {
            extValue[i] = Array.getByte(value, i);
        }
        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for " +
                                  "CertificatePoliciesExtension.");
        }
        mInfos = new Vector<CertificatePolicyInfo>(1, 1);
        while (val.data.available() != 0) {
            DerValue seq = val.data.getDerValue();
            CertificatePolicyInfo info = new CertificatePolicyInfo(seq);
            mInfos.addElement(info);
        }
    }

    /**
     * Returns a printable representation of the policy extension.
     */
    public String toString() {
        if (mInfos == null)
            return "";
        String s = super.toString() + "Certificate Policies [\n"
                 + mInfos.toString() + "]\n";

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
            extensionId = PKIXExtensions.CertificatePolicies_Id;
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
            mInfos = (Vector<CertificatePolicyInfo>) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                        "CertAttrSet:CertificatePoliciesExtension.");
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
                        "CertAttrSet:CertificatePoliciesExtension.");
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
                        "CertAttrSet:CertificatePoliciesExtension.");
        }
    }

    /**
     * Return an enumeration of attributes existing within this
     * attribute.
     */
    public Enumeration<Vector<CertificatePolicyInfo>> getAttributes() {
        Vector<Vector<CertificatePolicyInfo>> elements = new Vector<Vector<CertificatePolicyInfo>>();
        elements.addElement(mInfos);
        return (elements.elements());
    }

    private static final String[] NAMES = { INFOS };

    @Override
    public Enumeration<String> getAttributeNames() {
        // TODO Auto-generated method stub
        return Collections.enumeration(Arrays.asList(NAMES));
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    public static void main(String args[]) {

        /**
         * From ASN.1 dump
         *
         * 0 30 133: SEQUENCE {
         * 3 30 45: . SEQUENCE {
         * 5 06 3: . . OBJECT IDENTIFIER '1 2 3 5'
         * 10 30 38: . . SEQUENCE {
         * 12 30 36: . . . SEQUENCE {
         * 14 06 8: . . . . OBJECT IDENTIFIER cps (1 3 6 1 5 5 7 2 1)
         * : . . . . . (PKIX policy qualifier)
         * 24 16 24: . . . . IA5String 'http://home.netscape.com'
         * : . . . . }
         * : . . . }
         * : . . }
         * 50 30 84: . SEQUENCE {
         * 52 06 2: . . OBJECT IDENTIFIER '2 3 5'
         * 56 30 78: . . SEQUENCE {
         * 58 30 36: . . . SEQUENCE {
         * 60 06 8: . . . . OBJECT IDENTIFIER cps (1 3 6 1 5 5 7 2 1)
         * : . . . . . (PKIX policy qualifier)
         * 70 16 24: . . . . IA5String 'http://home.netscape.com'
         * : . . . . }
         * 96 30 38: . . . SEQUENCE {
         * 98 06 8: . . . . OBJECT IDENTIFIER unotice (1 3 6 1 5 5 7 2 2)
         * : . . . . . (PKIX policy qualifier)
         * 108 30 26: . . . . SEQUENCE {
         * 110 30 16: . . . . . SEQUENCE {
         * 112 1E 8: . . . . . . BMPString (1993) '_..o.r.g'
         * 122 02 1: . . . . . . INTEGER 1
         * 125 02 1: . . . . . . INTEGER 2
         * : . . . . . . }
         * 128 1E 6: . . . . . BMPString (1993) '_..d.t'
         * : . . . . . }
         * : . . . . }
         * : . . . }
         * : . . }
         * : . }
         **/

        CertificatePolicyId plcyId0 = new CertificatePolicyId(
                new ObjectIdentifier("1.2.3.5")
                );
        PolicyQualifiers qualifiers0 = new PolicyQualifiers();
        CPSuri cpsQualifier0 = new CPSuri("http://home.netscape.com");
        PolicyQualifierInfo qualifierInfo0 = new PolicyQualifierInfo(
                PolicyQualifierInfo.QT_CPS,
                cpsQualifier0
                );
        qualifiers0.add(qualifierInfo0);
        CertificatePolicyInfo info0 = new CertificatePolicyInfo(
                plcyId0, qualifiers0);
        CertificatePolicyId plcyId1 = new CertificatePolicyId(
                new ObjectIdentifier("2.3.5")
                );
        PolicyQualifiers qualifiers1 = new PolicyQualifiers();
        DisplayText org1 = new DisplayText(DisplayText.tag_BMPString,
                "org");
        int nums[] = { 1, 2 };
        NoticeReference nr1 = new NoticeReference(org1, nums);
        DisplayText dt1 = new DisplayText(DisplayText.tag_BMPString,
                "dt");
        UserNotice userNotice1 = new UserNotice(nr1, dt1);
        PolicyQualifierInfo qualifierInfo1 = new PolicyQualifierInfo(
                PolicyQualifierInfo.QT_UNOTICE,
                userNotice1
                );
        qualifiers1.add(qualifierInfo0);
        qualifiers1.add(qualifierInfo1);
        CertificatePolicyInfo info1 = new CertificatePolicyInfo(
                plcyId1, qualifiers1);
        Vector<CertificatePolicyInfo> infos = new Vector<CertificatePolicyInfo>();
        infos.addElement(info0);
        infos.addElement(info1);
        try {
            CertificatePoliciesExtension ext =
                    new CertificatePoliciesExtension(infos);

            // BASE64 encode the whole thing and write it to stdout
            System.out.println(Utils.base64encode(ext.getExtensionValue()));
        } catch (IOException e) {
            System.out.println(e.toString());
        }
    }

}
