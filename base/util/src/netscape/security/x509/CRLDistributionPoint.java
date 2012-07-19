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

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import netscape.security.util.BitArray;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.EXPLICIT;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * <pre>
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
 *      reasons                 [1]     ReasonFlags OPTIONAL,
 *      cRLIssuer               [2]     GeneralNames OPTIONAL }
 *
 * DistributionPointName ::= CHOICE {
 *      fullName                [0]     GeneralNames,
 *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 *
 * ReasonFlags ::= BIT STRING {
 *      unused                  (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6) }
 * </pre>
 */
public class CRLDistributionPoint implements ASN1Value {

    // at most one of the two following may be specified:
    private GeneralNames fullName;
    private RDN relativeName;

    // cache encoding of fullName
    private ANY fullNameEncoding;

    private BitArray reasons; // optional, may be null
    private GeneralNames CRLIssuer; // optional, may be null
    private ANY CRLIssuerEncoding;

    // default constructor does nothing.

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

    /**
     * Returns the reason flags for this distribution point. May be <code>null</code>.
     */
    public BitArray getReasons() {
        return reasons;
    }

    /**
     * Sets the reason flags for this distribution point. May be set to <code>null</code>.
     */
    public void setReasons(BitArray reasons) {
        this.reasons = reasons;
    }

    /**
     * Returns the CRLIssuer for the CRL at this distribution point.
     * May be <code>null</code>.
     */
    public GeneralNames getCRLIssuer() {
        return CRLIssuer;
    }

    /**
     * Sets the CRLIssuer for the CRL at this distribution point.
     * May be set to <code>null</code>.
     *
     * @exception GeneralNamesException If an error occurs encoding the name.
     */
    public void setCRLIssuer(GeneralNames CRLIssuer)
            throws GeneralNamesException, IOException {
        this.CRLIssuer = CRLIssuer;

        if (CRLIssuer != null) {
            // encode the name to catch any problems with it
            DerOutputStream derOut = new DerOutputStream();
            CRLIssuer.encode(derOut);
            try {
                ANY raw = new ANY(derOut.toByteArray());
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                raw.encodeWithAlternateTag(Tag.get(2), bos);
                CRLIssuerEncoding = new ANY(bos.toByteArray());
            } catch (InvalidBERException e) {
                throw new GeneralNamesException(e.toString());
            }
        }
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
                ANY rn = new ANY(derOut.toByteArray());
                EXPLICIT raw = new EXPLICIT(Tag.get(1), rn);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                raw.encode(bos);
                ANY distPointName = new ANY(bos.toByteArray());
                EXPLICIT distPoint = new EXPLICIT(Tag.get(0), distPointName);
                seq.addElement(distPoint);
            }

            // Encodes the ReasonFlags.
            if (reasons != null) {
                derOut = new DerOutputStream();
                derOut.putUnalignedBitString(reasons);
                ANY raw = new ANY(derOut.toByteArray());
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                raw.encodeWithAlternateTag(Tag.get(1), bos);
                ANY reasonEncoding = new ANY(bos.toByteArray());
                seq.addElement(Tag.get(1), reasonEncoding);
            }

            // Encodes the CRLIssuer
            if (CRLIssuer != null) {
                seq.addElement(Tag.get(2), CRLIssuerEncoding);
            }

            seq.encode(implicitTag, ostream);

        } catch (InvalidBERException e) {
            // this shouldn't happen unless there is a bug in one of
            // the Sun encoding classes
            throw new IOException(e.toString());
        }
    }

    // Template singleton
    private static Template templateInstance = new Template();

    /**
     * Returns an instance of a template for decoding a CRLDistributionPoint.
     */
    public static Template getTemplate() {
        return templateInstance;
    }

    public static void main(String args[]) throws GeneralNamesException, IOException, InvalidBERException {
        ByteArrayOutputStream bos = null;
        FileOutputStream fos = null;
        try {
            if (args.length != 1) {
                System.out.println("Usage: CRLDistributionPoint <outfile>");
                System.exit(-1);
            }

            bos = new ByteArrayOutputStream();

            SEQUENCE cdps = new SEQUENCE();

            // URI only
            CRLDistributionPoint cdp = new CRLDistributionPoint();
            URIName uri = new URIName("http://www.mycrl.com/go/here");
            GeneralNames generalNames = new GeneralNames();
            generalNames.addElement(uri);
            cdp.setFullName(generalNames);
            cdps.addElement(cdp);

            // DN only
            cdp = new CRLDistributionPoint();
            X500Name dn = new X500Name("CN=Otis Smith,E=otis@fedoraproject.org" +
                    ",OU=Certificate Server,O=Fedora,C=US");
            generalNames = new GeneralNames();
            generalNames.addElement(dn);
            cdp.setFullName(generalNames);
            cdps.addElement(cdp);

            // DN + reason
            BitArray ba = new BitArray(5, new byte[] { (byte) 0x28 });
            cdp = new CRLDistributionPoint();
            cdp.setFullName(generalNames);
            cdp.setReasons(ba);
            cdps.addElement(cdp);

            // relative DN + reason + crlIssuer
            cdp = new CRLDistributionPoint();
            RDN rdn = new RDN("OU=foobar dept");
            cdp.setRelativeName(rdn);
            cdp.setReasons(ba);
            cdp.setCRLIssuer(generalNames);
            cdps.addElement(cdp);

            cdps.encode(bos);

            byte[] encoded = bos.toByteArray();
            fos = new FileOutputStream(args[0]);
            fos.write(encoded);

            SEQUENCE.OF_Template seqt = new SEQUENCE.OF_Template(getTemplate());

            cdps = (SEQUENCE) ASN1Util.decode(seqt, encoded);

            int size = cdps.size();
            System.out.println("Total number of CDPs: " + size);
            for (int i = 0; i < size; i++) {
                System.out.println("\nCDP " + i);
                cdp = (CRLDistributionPoint) cdps.elementAt(i);
                GeneralNames gn = cdp.getFullName();
                if (gn == null) {
                    System.out.println("No full name");
                } else {
                    System.out.println(gn);
                }
                rdn = cdp.getRelativeName();
                if (rdn == null) {
                    System.out.println("No relative name");
                } else {
                    System.out.println(rdn);
                }
                if (cdp.getReasons() == null) {
                    System.out.println("No reasons");
                } else {
                    System.out.println(cdp.getReasons());
                }
                gn = cdp.getCRLIssuer();
                if (gn == null) {
                    System.out.println("No cRLIssuer");
                } else {
                    System.out.println(gn);
                }
            }
            System.out.println("Done");

        } finally {
            if (bos != null) {
                bos.close();
            }
            if (fos != null) {
                fos.close();
            }
            if (fos != null) {
                fos.close();
            }
        }
    }

    /**
     * Template for decoding CRLDistributionPoint.
     */
    public static class Template implements ASN1Template {

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
                throws IOException, InvalidBERException {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws IOException, InvalidBERException {
            CRLDistributionPoint cdp = new CRLDistributionPoint();

            //
            // construct the top-level sequence
            //

            SEQUENCE.Template seqt = SEQUENCE.getTemplate();

            // distributionPoint
            seqt.addOptionalElement(
                    new EXPLICIT.Template(Tag.get(0), ANY.getTemplate()));

            // reasons
            seqt.addOptionalElement(Tag.get(1), BIT_STRING.getTemplate());

            // cRLIssuer
            // This will have a tag of 2, but we can't say that here
            // because ANYs can't have implicit tags.  We don't need to say
            // it, because we do check the tags on the other two elements
            // in the sequence, so we'll know if we get this one.
            seqt.addOptionalElement(ANY.getTemplate());

            //
            // decode the top-level sequence
            //
            SEQUENCE top = (SEQUENCE) seqt.decode(implicitTag, istream);

            // decode the distribution point name
            if (top.elementAt(0) != null) {
                EXPLICIT exp = (EXPLICIT) top.elementAt(0);
                ANY distPoint = (ANY) exp.getContent();
                if (distPoint.getTag().equals(Tag.get(0))) {
                    // fullName
                    try {
                        DerValue dv = new DerValue(distPoint.getEncoded());
                        //toFile("encodedFullName", distPoint.getEncoded());
                        dv.resetTag(DerValue.tag_Sequence);
                        cdp.setFullName(new GeneralNames(dv));
                    } catch (GeneralNamesException e) {
                        throw new InvalidBERException("fullName: " + e.toString());
                    } catch (IOException e) {
                        throw new InvalidBERException("fullName: " + e.toString());
                    }
                } else if (distPoint.getTag().equals(Tag.get(1))) {
                    // relative name
                    try {
                        DerValue dv = new DerValue(distPoint.getEncoded());
                        /* dv is as follows:
                        0   12: [1] {
                        2   10:   SET {
                        4    8:     SEQUENCE {
                        6    3:       OBJECT IDENTIFIER commonName (2 5 4 3)
                        11    1:       PrintableString 'x'
                        :       }
                        :     }
                        :   }
                         */
                        dv = dv.data.getDerValue(); // skipping the tag
                        /* after the skipping, we have:
                        0   10: SET {
                        2    8:   SEQUENCE {
                        4    3:     OBJECT IDENTIFIER commonName (2 5 4 3)
                        9    1:     PrintableString 'x'
                        :     }
                        :   }
                         */
                        dv.resetTag(DerValue.tag_Set);
                        cdp.setRelativeName(new RDN(dv));
                    } catch (IOException e) {
                        throw new InvalidBERException("relativeName " +
                                e.toString());
                    }
                } else {
                    throw new InvalidBERException(
                            "Unknown tag " + distPoint.getTag() +
                                    " in distributionPoint");
                }
            }

            // decode the reasons
            if (top.elementAt(1) != null) {
                BIT_STRING bs = (BIT_STRING) top.elementAt(1);
                byte[] bits = bs.getBits();
                cdp.setReasons(
                        new BitArray((bits.length * 8) - bs.getPadCount(), bits));
            }

            // decode the cRLIssuer
            if (top.elementAt(2) != null) {
                ANY issuer = (ANY) top.elementAt(2);
                if (!issuer.getTag().equals(Tag.get(2))) {
                    throw new InvalidBERException("Invalid tag " + issuer.getTag());
                }
                try {
                    DerValue dv = new DerValue(issuer.getEncoded());
                    dv.resetTag(DerValue.tag_Sequence);
                    cdp.setCRLIssuer(new GeneralNames(dv));
                } catch (GeneralNamesException e) {
                    throw new InvalidBERException("cRLIssuer " + e.toString());
                } catch (IOException e) {
                    throw new InvalidBERException("cRLIssuer " + e.toString());
                }
            }

            return cdp;

        }
    }

}
