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

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.BitArray;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

import org.mozilla.jss.asn1.ASN1Util;

/**
 * A critical CRL extension that identifies the CRL distribution point
 * for a particular CRL
 * 
 * <pre>
 * issuingDistributionPoint ::= SEQUENCE {
 *         distributionPoint       [0] DistributionPointName OPTIONAL,
 *         onlyContainsUserCerts   [1] BOOLEAN DEFAULT FALSE,
 *         onlyContainsCACerts     [2] BOOLEAN DEFAULT FALSE,
 *         onlySomeReasons         [3] ReasonFlags OPTIONAL,
 *         indirectCRL             [4] BOOLEAN DEFAULT FALSE }
 * 
 * DistributionPointName ::= CHOICE {
 *         fullName                [0]     GeneralNames,
 *         nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 * 
 * ReasonFlags ::= BIT STRING {
 *         unused                  (0),
 *         keyCompromise           (1),
 *         cACompromise            (2),
 *         affiliationChanged      (3),
 *         superseded              (4),
 *         cessationOfOperation    (5),
 *         certificateHold         (6) }
 * 
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 * 
 * GeneralName ::= CHOICE {
 *         otherName                       [0]     OtherName,
 *         rfc822Name                      [1]     IA5String,
 *         dNSName                         [2]     IA5String,
 *         x400Address                     [3]     ORAddress,
 *         directoryName                   [4]     Name,
 *         ediPartyName                    [5]     EDIPartyName,
 *         uniformResourceIdentifier       [6]     IA5String,
 *         iPAddress                       [7]     OCTET STRING,
 *         registeredID                    [8]     OBJECT IDENTIFIER}
 * 
 * OtherName ::= SEQUENCE {
 *         type-id    OBJECT IDENTIFIER,
 *         value      [0] EXPLICIT ANY DEFINED BY type-id }
 * 
 * EDIPartyName ::= SEQUENCE {
 *         nameAssigner            [0]     DirectoryString OPTIONAL,
 *         partyName               [1]     DirectoryString }
 * 
 * RelativeDistinguishedName ::=
 *         SET OF AttributeTypeAndValue
 * 
 * AttributeTypeAndValue ::= SEQUENCE {
 *         type     AttributeType,
 *         value    AttributeValue }
 * 
 * AttributeType ::= OBJECT IDENTIFIER
 * 
 * AttributeValue ::= ANY DEFINED BY AttributeType
 * </pre>
 */
public class IssuingDistributionPointExtension extends Extension
        implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = -1281544042375527550L;

    /**
     * The Object Identifier for this extension.
     */
    public static final String OID = "2.5.29.28";

    /**
     * Attribute names.
     */
    public static final String NAME = "IssuingDistributionPoint";
    public static final String ISSUING_DISTRIBUTION_POINT = "issuing_distribution_point";

    // Private data members
    private IssuingDistributionPoint issuingDistributionPoint = null;

    // Cached DER-encoding to improve performance.
    private byte[] cachedEncoding = null;

    static {
        try {
            OIDMap.addAttribute(IssuingDistributionPointExtension.class.getName(),
                                OID, NAME);
        } catch (CertificateException e) {
        }
    }

    /**
     * This constructor is very important, since it will be called
     * by the system.
     */
    public IssuingDistributionPointExtension(Boolean critical, Object value)
            throws IOException {

        this.extensionId = PKIXExtensions.IssuingDistributionPoint_Id;
        this.critical = critical.booleanValue();
        this.extensionValue = (byte[]) ((byte[]) value).clone();

        byte[] extValue = this.extensionValue;
        issuingDistributionPoint = new IssuingDistributionPoint();
        DerValue val = new DerValue(extValue);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding of IssuingDistributionPoint");
        }

        while (val.data.available() != 0) {
            DerValue opt = val.data.getDerValue();

            if (opt != null) {
                for (int i = 0; i < 5; i++) {
                    if (opt.isContextSpecific((byte) i)) {
                        if ((i == 0 && opt.isConstructed() && opt.data.available() != 0) ||
                                (i != 0 && (!opt.isConstructed()) && opt.data.available() != 0)) {

                            if (i == 0) {
                                DerValue opt1 = opt.data.getDerValue();
                                if (opt1 != null) {
                                    if (opt1.isContextSpecific((byte) 0)) {
                                        if (opt1.isConstructed() && opt1.data.available() != 0) {
                                            opt1.resetTag(DerValue.tag_Sequence);

                                            try {
                                                GeneralNames fullName = new GeneralNames(opt1);
                                                if (fullName != null) {
                                                    issuingDistributionPoint.setFullName(fullName);
                                                }
                                            } catch (GeneralNamesException e) {
                                                throw new IOException("Invalid encoding of IssuingDistributionPoint " + e);
                                            } catch (IOException e) {
                                                throw new IOException("Invalid encoding of IssuingDistributionPoint " + e);
                                            }
                                        } else {
                                            throw new IOException("Invalid encoding of IssuingDistributionPoint");
                                        }

                                    } else if (opt1.isContextSpecific((byte) 1)) {
                                        if (opt1.isConstructed() && opt1.data.available() != 0) {
                                            opt1.resetTag(DerValue.tag_Set);

                                            try {
                                                RDN relativeName = new RDN(opt1);
                                                if (relativeName != null) {
                                                    issuingDistributionPoint.setRelativeName(relativeName);
                                                }
                                            } catch (IOException e) {
                                                throw new IOException("Invalid encoding of IssuingDistributionPoint " + e);
                                            }
                                        } else {
                                            throw new IOException("Invalid encoding of IssuingDistributionPoint");
                                        }
                                    }
                                }

                            } else if (i == 3) {
                                opt.resetTag(DerValue.tag_BitString);
                                try {
                                    BitArray reasons = opt.getUnalignedBitString();
                                    issuingDistributionPoint.setOnlySomeReasons(reasons);
                                    byte[] a = reasons.toByteArray();
                                } catch (IOException e) {
                                    throw new IOException("Invalid encoding of IssuingDistributionPoint " + e);
                                }

                            } else {
                                opt.resetTag(DerValue.tag_Boolean);
                                try {
                                    boolean b = opt.getBoolean();
                                    if (i == 1) {
                                        issuingDistributionPoint.setOnlyContainsUserCerts(b);
                                    } else if (i == 2) {
                                        issuingDistributionPoint.setOnlyContainsCACerts(b);
                                    } else if (i == 4) {
                                        issuingDistributionPoint.setIndirectCRL(b);
                                    }
                                } catch (IOException e) {
                                    throw new IOException("Invalid encoding of IssuingDistributionPoint " + e);
                                }
                            }
                        } else {
                            throw new IOException("Invalid encoding of IssuingDistributionPoint");
                        }
                    }
                }
            } else {
                throw new IOException("Invalid encoding of IssuingDistributionPoint");
            }
        }

    }

    /**
     * Creates a new IssuingDistributionPoint extension, with the given
     * issuing distribution point as the first element.
     */
    public IssuingDistributionPointExtension(IssuingDistributionPoint idp) {
        this.extensionId = PKIXExtensions.IssuingDistributionPoint_Id;
        this.critical = true;
        issuingDistributionPoint = idp;
    }

    /**
     * Returns the issuing distribution point.
     */
    public IssuingDistributionPoint getIssuingDistributionPoint() {
        return issuingDistributionPoint;
    }

    /**
     * Sets the criticality of this extension. PKIX dictates that this
     * extension SHOULD be critical, so applications can make it not critical
     * if they have a very good reason. By default, the extension is critical.
     */
    public void setCritical(boolean critical) {
        this.critical = critical;
    }

    /**
     * Gets the criticality of this extension. PKIX dictates that this
     * extension SHOULD be critical, so by default, the extension is critical.
     */
    public boolean getCritical(boolean critical) {
        return this.critical;
    }

    /**
     * Encodes this extension to the given DerOutputStream.
     * This method re-encodes each time it is called, so it is not very
     * efficient.
     */
    public void encode(DerOutputStream out) throws IOException {
        extensionValue = ASN1Util.encode(issuingDistributionPoint);
        super.encode(out);
    }

    /**
     * Should be called if any change is made to this data structure
     * so that the cached DER encoding can be discarded.
     */
    public void flushCachedEncoding() {
        cachedEncoding = null;
    }

    /**
     * Returns a printable representation of the IssuingDistributionPointExtension
     */

    public String toString() {
        return NAME;
    }

    /**
     * DER-encodes this extension to the given OutputStream.
     */
    public void encode(OutputStream ostream)
            throws CertificateException, IOException {
        if (cachedEncoding == null) {
            // only re-encode if necessary
            DerOutputStream tmp = new DerOutputStream();
            encode(tmp);
            cachedEncoding = tmp.toByteArray();
        }
        ostream.write(cachedEncoding);
    }

    public void decode(InputStream in)
            throws CertificateException, IOException {
        throw new IOException("Not supported");
    }

    public void set(String name, Object obj)
            throws CertificateException, IOException {
        if (name.equalsIgnoreCase(ISSUING_DISTRIBUTION_POINT)) {
            if (!(obj instanceof IssuingDistributionPoint)) {
                throw new IOException("Attribute value should be of type IssuingDistributionPoint.");
            }
            issuingDistributionPoint = (IssuingDistributionPoint) obj;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:IssuingDistributionPointExtension");
        }
    }

    public Object get(String name)
            throws CertificateException, IOException {
        if (name.equalsIgnoreCase(ISSUING_DISTRIBUTION_POINT)) {
            return issuingDistributionPoint;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:IssuingDistributionPointExtension");
        }
    }

    public void delete(String name)
            throws CertificateException, IOException {
        if (name.equalsIgnoreCase(ISSUING_DISTRIBUTION_POINT)) {
            issuingDistributionPoint = null;
        } else {
            throw new IOException("Attribute name not recognized by " +
                    "CertAttrSet:IssuingDistributionPointExtension");
        }
    }

    public Enumeration<String> getElements() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(ISSUING_DISTRIBUTION_POINT);
        return (elements.elements());
        //        return (new Vector()).elements();
    }

    public String getName() {
        return NAME;
    }

    /**
     * Test driver.
     */
    public static void main(String args[]) {

        try {

            if (args.length != 1) {
                System.out.println("Usage: IssuingDistributionPointExtension " +
                        "<outfile>");
                System.exit(-1);
            }

            BufferedOutputStream bos = new BufferedOutputStream(
                    new FileOutputStream(args[0]));

            // URI only
            IssuingDistributionPoint idp = new IssuingDistributionPoint();
            URIName uri = new URIName("http://www.mycrl.com/go/here");
            GeneralNames generalNames = new GeneralNames();
            generalNames.addElement(uri);
            idp.setFullName(generalNames);
            IssuingDistributionPointExtension idpExt =
                    new IssuingDistributionPointExtension(idp);

            // DN only
            idp = new IssuingDistributionPoint();
            X500Name dn = new X500Name("CN=Otis Smith,E=otis@fedoraproject.org" +
                    ",OU=Certificate Server,O=Fedora,C=US");
            generalNames = new GeneralNames();
            generalNames.addElement(dn);
            idp.setFullName(generalNames);
            idpExt.set(IssuingDistributionPointExtension.ISSUING_DISTRIBUTION_POINT, idp);

            // DN + reason
            BitArray ba = new BitArray(5, new byte[] { (byte) 0x28 });
            idp = new IssuingDistributionPoint();
            idp.setFullName(generalNames);
            idp.setOnlySomeReasons(ba);
            idpExt.set(IssuingDistributionPointExtension.ISSUING_DISTRIBUTION_POINT, idp);

            // relative DN + reason + crlIssuer
            idp = new IssuingDistributionPoint();
            RDN rdn = new RDN("OU=foobar dept");
            idp.setRelativeName(rdn);
            idp.setOnlySomeReasons(ba);
            idp.setOnlyContainsCACerts(true);
            idp.setOnlyContainsUserCerts(true);
            idp.setIndirectCRL(true);
            idpExt.set(IssuingDistributionPointExtension.ISSUING_DISTRIBUTION_POINT, idp);

            idpExt.setCritical(false);
            idpExt.encode(bos);

            bos.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
