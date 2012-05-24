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
import java.util.Hashtable;
import java.util.Vector;

import netscape.security.util.BitArray;
import netscape.security.util.DerOutputStream;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;

/**
 * An extension that tells applications where to find
 * the latest (freshest) delta CRL for this certificate
 * or full CRL.
 *
 * <pre>
 * cRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 *
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
public class FreshestCRLExtension extends Extension
        implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = -8040203589629281781L;

    // vector of CRLDistributionPoint
    private SEQUENCE distributionPoints = new SEQUENCE();

    public FreshestCRLExtension() {
        this.extensionId = PKIXExtensions.FreshestCRL_Id;
        this.critical = false;
    }

    // Cached DER-encoding to improve performance.
    private byte[] cachedEncoding = null;

    // Attribute name
    public static final String NAME = "FreshestCRL";

    // The Object Identifier for this extension.
    public static final String OID = "2.5.29.46";

    static {
        try {
            OIDMap.addAttribute(FreshestCRLExtension.class.getName(),
                                OID, NAME);
        } catch (CertificateException e) {
        }
    }

    /**
     * This constructor is called by the CertificateExtensions class to decode
     * an extension whose OID indicates it is a CRLDistributionsPoints
     * extension.
     */
    public FreshestCRLExtension(Boolean critical, Object value)
    //throws IOException
    {
        try {
            this.extensionId = PKIXExtensions.FreshestCRL_Id;
            this.critical = critical.booleanValue();
            this.extensionValue = ((byte[]) value).clone();

            // decode the value
            try {
                SEQUENCE.OF_Template seqOfCRLDP =
                        new SEQUENCE.OF_Template(CRLDistributionPoint.getTemplate());

                distributionPoints =
                        (SEQUENCE) ASN1Util.decode(seqOfCRLDP, extensionValue);
            } catch (InvalidBERException e) {
                throw new IOException("Invalid BER-encoding: " + e.toString());
            }
        } catch (IOException e) {
            System.out.println("Big error");
            System.out.println(e);
            e.printStackTrace();
            //throw e;
        }
    }

    /**
     * Creates a new FreshestCRL extension, with the given
     * distribution point as the first element.
     */
    public FreshestCRLExtension(CRLDistributionPoint dp) {
        this.extensionId = PKIXExtensions.FreshestCRL_Id;
        this.critical = false;
        distributionPoints.addElement(dp);
    }

    /**
     * Adds an additional distribution point to the end of the sequence.
     */
    public void addPoint(CRLDistributionPoint dp) {
        distributionPoints.addElement(dp);
        cachedEncoding = null;
    }

    /**
     * Returns the number of distribution points in the sequence.
     */
    public int getNumPoints() {
        return distributionPoints.size();
    }

    /**
     * Returns the DistributionPoint at the given index in the sequence.
     */
    public CRLDistributionPoint getPointAt(int index) {
        return (CRLDistributionPoint) distributionPoints.elementAt(index);
    }

    /**
     * Sets the criticality of this extension. PKIX dictates that this
     * extension SHOULD NOT be critical, so applications can make it critical
     * if they have a very good reason. By default, the extension is not
     * critical.
     */
    public void setCritical(boolean critical) {
        this.critical = critical;
    }

    /**
     * Encodes this extension to the given DerOutputStream.
     * This method re-encodes each time it is called, so it is not very
     * efficient.
     */
    public void encode(DerOutputStream out) throws IOException {
        extensionValue = ASN1Util.encode(distributionPoints);
        super.encode(out);
    }

    /**
     * Should be called if any change is made to this data structure
     * so that the cached DER encoding can be discarded.
     */
    public void flushCachedEncoding() {
        cachedEncoding = null;
    }

    /////////////////////////////////////////////////////////////
    // CertAttrSet interface
    // This interface is not really appropriate for this extension
    // because it is so complicated. Therefore, we only provide a
    // minimal implementation.
    /////////////////////////////////////////////////////////////
    @Override
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
        throw new IOException("Attribute name not recognized by " +
                "CertAttrSet:FreshestCRLExtension");
    }

    public Object get(String name)
            throws CertificateException, IOException {
        throw new IOException("Attribute name not recognized by " +
                "CertAttrSet:FreshestCRLExtension");
    }

    public void delete(String name)
            throws CertificateException, IOException {
        throw new IOException("Attribute name not recognized by " +
                "CertAttrSet:FreshestCRLExtension");
    }

    /*
     * TODO replacewith empty collection
     */
    public Enumeration<String> getAttributeNames() {
        return (new Vector<String>()).elements();
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
                System.out.println("Usage: FreshestCRLExtentions " +
                        "<outfile>");
                System.exit(-1);
            }

            BufferedOutputStream bos = new BufferedOutputStream(
                    new FileOutputStream(args[0]));

            // URI only
            CRLDistributionPoint cdp = new CRLDistributionPoint();
            URIName uri = new URIName("http://www.mycrl.com/go/here");
            GeneralNames generalNames = new GeneralNames();
            generalNames.addElement(uri);
            cdp.setFullName(generalNames);
            FreshestCRLExtension crldpExt =
                    new FreshestCRLExtension(cdp);

            // DN only
            cdp = new CRLDistributionPoint();
            X500Name dn = new X500Name("CN=Otis Smith,E=otis@fedoraproject.org" +
                    ",OU=Certificate Server,O=Fedora,C=US");
            generalNames = new GeneralNames();
            generalNames.addElement(dn);
            cdp.setFullName(generalNames);
            crldpExt.addPoint(cdp);

            // DN + reason
            BitArray ba = new BitArray(5, new byte[] { (byte) 0x28 });
            cdp = new CRLDistributionPoint();
            cdp.setFullName(generalNames);
            cdp.setReasons(ba);
            crldpExt.addPoint(cdp);

            // relative DN + reason + crlIssuer
            cdp = new CRLDistributionPoint();
            RDN rdn = new RDN("OU=foobar dept");
            cdp.setRelativeName(rdn);
            cdp.setReasons(ba);
            cdp.setCRLIssuer(generalNames);
            crldpExt.addPoint(cdp);

            crldpExt.setCritical(true);
            crldpExt.encode(bos);

            bos.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Represents a reason that a cert may be revoked. These reasons are
     * expressed in a ReasonFlags bit string.
     */
    public static class Reason {

        private String name;
        private byte bitMask;

        private Reason() {
        }

        private Reason(String name, byte bitMask) {
            this.name = name;
            this.bitMask = bitMask;
            map.put(name, this);
            list.addElement(this);
        }

        private static Hashtable<String, Reason> map = new Hashtable<String, Reason>();
        private static Vector<Reason> list = new Vector<Reason>();

        public static Reason fromString(String name) {
            return map.get(name);
        }

        public String getName() {
            return name;
        }

        public byte getBitMask() {
            return bitMask;
        }

        /**
         * Given a bit array representing reason flags, extracts the reasons
         * and returns them as an array.
         *
         * @param bitFlags A bit vector containing reason flags.
         * @return An array of reasons contained in the bit vector.
         *         May be zero-length but will not be null.
         */
        public static Reason[] bitArrayToReasonArray(byte bitFlags) {
            return bitArrayToReasonArray(new byte[] { bitFlags });
        }

        /**
         * Given a bit array representing reason flags, extracts the reasons
         * and returns them as an array. Currently, only the first byte
         * of the bitflags are examined.
         *
         * @param bitFlags A bit vector containing reason flags. The format
         *            is big-endian (MSB first). Only the first byte is examined.
         * @return An array of reasons contained in the bit vector.
         *         May be zero-length but will not be null.
         */
        public static Reason[] bitArrayToReasonArray(byte[] bitFlags) {
            byte first = bitFlags[0];
            int size = list.size();
            Vector<Reason> result = new Vector<Reason>();
            for (int i = 0; i < size; i++) {
                Reason r = list.elementAt(i);
                byte b = r.getBitMask();
                if ((first & b) != 0) {
                    result.addElement(r);
                }
            }
            size = result.size();
            Reason[] retval = new Reason[size];
            for (int i = 0; i < size; i++) {
                retval[i] = result.elementAt(i);
            }
            return retval;
        }

        public static final Reason UNUSED =
                new Reason("unused", (byte) 0x80);
        public static final Reason KEY_COMPROMISE =
                new Reason("keyCompromise", (byte) 0x40);
        public static final Reason CA_COMPROMISE =
                new Reason("cACompromise", (byte) 0x20);
        public static final Reason AFFILIATION_CHANGED =
                new Reason("affiliationChanged", (byte) 0x10);
        public static final Reason SUPERSEDED =
                new Reason("superseded", (byte) 0x08);
        public static final Reason CESSATION_OF_OPERATION =
                new Reason("cessationOfOperation", (byte) 0x04);
        public static final Reason CERTIFICATE_HOLD =
                new Reason("certificateHold", (byte) 0x02);
    }

}
