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
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import netscape.security.util.BitArray;
import netscape.security.util.DerOutputStream;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BOOLEAN;
import org.mozilla.jss.asn1.EXPLICIT;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
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
 * 
 * See the documentation in <code>CRLDistributionPoint</code> for
 * the <code>DistributionPointName</code> and <code>ReasonFlags</code> ASN.1 types.
 */
public class IssuingDistributionPoint implements ASN1Value {

    // at most one of the following two may be specified.  One or both can
    // be null.
    private GeneralNames fullName = null;
    private RDN relativeName = null;

    private boolean onlyContainsUserCerts = false; // DEFAULT FALSE
    private boolean onlyContainsCACerts = false; // DEFAULT FALSE
    private BitArray onlySomeReasons = null; // optional, may be null
    private boolean indirectCRL = false; // DEFAULT FALSE

    // cache encoding of fullName
    private ANY fullNameEncoding;

    /**
     * Returns the <code>fullName</code> of the <code>DistributionPointName</code>, which may be <code>null</code>.
     */
    public GeneralNames getFullName() {
        return fullName;
    }

    /**
     * Returns the <code>relativeName</code> of the <code>DistributionPointName</code>, which may be <code>null</code>.
     */
    public RDN getRelativeName() {
        return relativeName;
    }

    /**
     * Sets the <code>fullName</code> of the <code>DistributionPointName</code>. It may be set to <code>null</code>.
     * If it is set to a non-null value, <code>relativeName</code> will be
     * set to <code>null</code>, because at most one of these two attributes
     * can be specified at a time.
     * 
     * @exception GeneralNamesException If an error occurs encoding the
     *                name.
     */
    public void setFullName(GeneralNames fullName)
            throws GeneralNamesException, IOException {
        this.fullName = fullName;
        if (fullName != null) {
            // encode the name to catch any problems with it
            DerOutputStream derOut = new DerOutputStream();
            fullName.encode(derOut);
            try {
                ANY raw = new ANY(derOut.toByteArray());
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                raw.encodeWithAlternateTag(Tag.get(0), bos);
                fullNameEncoding = new ANY(bos.toByteArray());
            } catch (InvalidBERException e) {
                // assume this won't happen, since it would imply a bug
                // in DerOutputStream
                throw new GeneralNamesException(e.toString());
            }

            this.relativeName = null;
        }
    }

    /**
     * Sets the <code>relativeName</code> of the <code>DistributionPointName</code>. It may be set to <code>null</code>.
     * If it is set to a non-null value, <code>fullName</code> will be
     * set to <code>null</code>, because at most one of these two attributes
     * can be specified at a time.
     */
    public void setRelativeName(RDN relativeName) {
        this.relativeName = relativeName;
        if (relativeName != null) {
            this.fullName = null;
        }
    }

    public boolean getOnlyContainsUserCerts() {
        return onlyContainsUserCerts;
    }

    public void setOnlyContainsUserCerts(boolean b) {
        onlyContainsUserCerts = b;
    }

    public boolean getOnlyContainsCACerts() {
        return onlyContainsCACerts;
    }

    public void setOnlyContainsCACerts(boolean b) {
        onlyContainsCACerts = b;
    }

    /**
     * Returns the reason flags for this distribution point. May be <code>null</code>.
     */
    public BitArray getOnlySomeReasons() {
        return onlySomeReasons;
    }

    /**
     * Sets the reason flags for this distribution point. May be set to <code>null</code>.
     */
    public void setOnlySomeReasons(BitArray reasons) {
        this.onlySomeReasons = reasons;
    }

    public boolean getIndirectCRL() {
        return indirectCRL;
    }

    public void setIndirectCRL(boolean b) {
        indirectCRL = b;
    }

    /////////////////////////////////////////////////////////////
    // DER encoding
    /////////////////////////////////////////////////////////////
    private static final Tag TAG = SEQUENCE.TAG;

    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {

        SEQUENCE seq = new SEQUENCE();
        DerOutputStream derOut;

        try {

            // Encodes the DistributionPointName.  Because DistributionPointName
            // is a CHOICE, the [0] tag is forced to be EXPLICIT.
            if (fullName != null) {
                EXPLICIT distPoint = new EXPLICIT(Tag.get(0), fullNameEncoding);
                seq.addElement(distPoint);
            } else if (relativeName != null) {
                derOut = new DerOutputStream();
                relativeName.encode(derOut);
                ANY raw = new ANY(derOut.toByteArray());
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                raw.encodeWithAlternateTag(Tag.get(1), bos);
                ANY distPointName = new ANY(bos.toByteArray());
                EXPLICIT distPoint = new EXPLICIT(Tag.get(0), distPointName);
                seq.addElement(distPoint);
            }

            if (onlyContainsUserCerts != false) {
                seq.addElement(Tag.get(1), new BOOLEAN(true));
            }
            if (onlyContainsCACerts != false) {
                seq.addElement(Tag.get(2), new BOOLEAN(true));
            }

            // Encodes the ReasonFlags.
            if (onlySomeReasons != null) {
                derOut = new DerOutputStream();
                derOut.putUnalignedBitString(onlySomeReasons);
                ANY raw = new ANY(derOut.toByteArray());
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                raw.encodeWithAlternateTag(Tag.get(3), bos);
                ANY reasonEncoding = new ANY(bos.toByteArray());
                seq.addElement(reasonEncoding);
            }

            if (indirectCRL != false) {
                seq.addElement(Tag.get(4), new BOOLEAN(true));
            }

            seq.encode(implicitTag, ostream);

        } catch (InvalidBERException e) {
            // this shouldn't happen unless there is a bug in one of
            // the Sun encoding classes
            throw new IOException(e.toString());
        }
    }

    public static void main(String args[]) {

        try {
            if (args.length != 1) {
                System.out.println("Usage: IssuingDistributionPoint <outfile>");
                System.exit(-1);
            }

            BufferedOutputStream bos = new BufferedOutputStream(
                    new FileOutputStream(args[0]));

            SEQUENCE idps = new SEQUENCE();

            IssuingDistributionPoint idp = new IssuingDistributionPoint();

            X500Name dn = new X500Name("CN=Skovw Wjasldk,E=nicolson@netscape.com" +
                    ",OU=Certificate Server,O=Netscape,C=US");
            GeneralNames generalNames = new GeneralNames();
            generalNames.addElement(dn);
            idp.setFullName(generalNames);
            idps.addElement(idp);

            idp = new IssuingDistributionPoint();
            URIName uri = new URIName("http://www.mycrl.com/go/here");
            generalNames = new GeneralNames();
            generalNames.addElement(uri);
            idp.setFullName(generalNames);
            idp.setOnlyContainsUserCerts(true);
            idp.setOnlyContainsCACerts(true);
            idp.setIndirectCRL(true);
            BitArray ba = new BitArray(5, new byte[] { (byte) 0x28 });
            idp.setOnlySomeReasons(ba);
            idps.addElement(idp);

            idps.encode(bos);
            bos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
