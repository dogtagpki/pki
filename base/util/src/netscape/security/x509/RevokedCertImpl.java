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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Set;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * <p>
 * Abstract class for a revoked certificate in a CRL. This class is for each entry in the
 * <code>revokedCertificates</code>, so it deals with the inner <em>SEQUENCE</em>. The ASN.1 definition for this is:
 *
 * <pre>
 * revokedCertificates    SEQUENCE OF SEQUENCE  {
 *     userCertificate    CertificateSerialNumber,
 *     revocationDate     ChoiceOfTime,
 *     crlEntryExtensions Extensions OPTIONAL
 *                        -- if present, must be v2
 * }  OPTIONAL
 *
 * CertificateSerialNumber  ::=  INTEGER
 *
 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension  ::=  SEQUENCE  {
 *     extnId        OBJECT IDENTIFIER,
 *     critical      BOOLEAN DEFAULT FALSE,
 *     extnValue     OCTET STRING
 *                   -- contains a DER encoding of a value
 *                   -- of the type registered for use with
 *                   -- the extnId object identifier value
 * }
 * </pre>
 *
 * @author Hemma Prafullchandra
 * @version 1.6 97/12/10
 */

public class RevokedCertImpl extends RevokedCertificate implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -3449642360223397701L;

    private SerialNumber serialNumber;
    private Date revocationDate;
    private CRLExtensions extensions = null;
    private byte[] revokedCert;
    private final static boolean isExplicit = false;

    /**
     * Default constructor.
     */
    public RevokedCertImpl() {
    }

    /**
     * Constructs a revoked certificate entry using the serial number and
     * revocation date.
     *
     * @param num
     *            the serial number of the revoked certificate.
     * @param date
     *            the Date on which revocation took place.
     */
    public RevokedCertImpl(BigInteger num, Date date) {
        this.serialNumber = new SerialNumber(num);
        this.revocationDate = date;
    }

    /**
     * Constructs a revoked certificate entry using the serial number,
     * revocation date and the entry extensions.
     *
     * @param num
     *            the serial number of the revoked certificate.
     * @param date
     *            the Date on which revocation took place.
     * @param crlEntryExts
     *            the extensions for this entry.
     */
    public RevokedCertImpl(BigInteger num, Date date, CRLExtensions crlEntryExts) {
        this.serialNumber = new SerialNumber(num);
        this.revocationDate = date;
        this.extensions = crlEntryExts;
    }

    public byte[] getEncoded() throws CRLException {
        // XXX NOT IMPLEMENTED
        if (revokedCert == null) {
            DerOutputStream os = new DerOutputStream();
            try {
                encode(os);
            } catch (Exception e) {
                // revokedCert = null;
            }
            revokedCert = os.toByteArray();
        }
        return revokedCert;
    }

    public boolean hasUnsupportedCriticalExtension() {
        // XXX NOT IMPLEMENTED
        return true;
    }

    /**
     * Sets extensions for this impl.
     *
     * @param crlEntryExts
     *            CRLExtensions
     */
    public void setExtensions(CRLExtensions crlEntryExts) {
        this.extensions = crlEntryExts;
    }

    /**
     * Unmarshals a revoked certificate from its encoded form.
     *
     * @param revokedCert
     *            the encoded bytes.
     * @exception CRLException
     *                on parsing errors.
     * @exception X509ExtensionException
     *                on extension handling errors.
     */
    public RevokedCertImpl(byte[] revokedCert) throws CRLException,
            X509ExtensionException {
        try {
            DerValue derValue = new DerValue(revokedCert);
            parse(derValue);
        } catch (IOException e) {
            throw new CRLException("Parsing error: " + e.toString());
        }
    }

    /**
     * Unmarshals a revoked certificate from its encoded form.
     *
     * @param derValue
     *            the DER value containing the revoked certificate.
     * @exception CRLException
     *                on parsing errors.
     * @exception X509ExtensionException
     *                on extension handling errors.
     */
    public RevokedCertImpl(DerValue derValue) throws CRLException,
            X509ExtensionException {
        parse(derValue);
    }

    /**
     * Returns true if this revoked certificate entry has extensions, otherwise
     * false.
     *
     * @return true if this CRL entry has extensions, otherwise false.
     */
    public boolean hasExtensions() {
        if (extensions == null)
            return false;
        else
            return true;
    }

    /**
     * Decode a revoked certificate from an input stream.
     *
     * @param inStrm
     *            an input stream holding at least one revoked certificate
     * @exception CRLException
     *                on parsing errors.
     * @exception X509ExtensionException
     *                on extension handling errors.
     */
    public void decode(InputStream inStrm) throws CRLException,
            X509ExtensionException {
        try {
            DerValue derValue = new DerValue(inStrm);
            parse(derValue);
        } catch (IOException e) {
            throw new CRLException("Parsing error: " + e.toString());
        }
    }

    /**
     * Encodes the revoked certificate to an output stream.
     *
     * @param outStrm
     *            an output stream to which the encoded revoked certificate is
     *            written.
     * @exception CRLException
     *                on encoding errors.
     * @exception X509ExtensionException
     *                on extension handling errors.
     */
    public void encode(DerOutputStream outStrm) throws CRLException,
            X509ExtensionException {
        try (DerOutputStream seq = new DerOutputStream()) {
            if (revokedCert == null) {
                DerOutputStream tmp = new DerOutputStream();
                // sequence { serialNumber, revocationDate, extensions }
                serialNumber.encode(tmp);

                // from 2050 should encode GeneralizedTime
                tmp.putUTCTime(revocationDate);

                if (extensions != null)
                    extensions.encode(tmp, isExplicit);

                seq.write(DerValue.tag_Sequence, tmp);

                revokedCert = seq.toByteArray();
            }
            outStrm.write(revokedCert);
        } catch (IOException e) {
            throw new CRLException("Encoding error: " + e.toString());
        }
    }

    /**
     * Gets the serial number for this RevokedCertificate, the <em>userCertificate</em>.
     *
     * @return the serial number.
     */
    public BigInteger getSerialNumber() {
        return serialNumber.getNumber().toBigInteger();
    }

    /**
     * Gets the revocation date for this RevokedCertificate, the <em>revocationDate</em>.
     *
     * @return the revocation date.
     */
    public Date getRevocationDate() {
        return (new Date(revocationDate.getTime()));
    }

    /**
     * Returns extensions for this impl.
     *
     * @return the CRLExtensions
     */
    public CRLExtensions getExtensions() {
        return extensions;
    }

    /**
     * Returns a printable string of this revoked certificate.
     *
     * @return value of this revoked certificate in a printable form.
     */
    public String toString() {
        StringBuffer sb = new StringBuffer(serialNumber.toString() + "  On: " + revocationDate.toString());

        if (extensions != null) {
            sb.append("\n");
            for (int i = 0; i < extensions.size(); i++)
                sb.append("Entry Extension[" + i + "]: "
                        + (extensions.elementAt(i)).toString());
        }
        sb.append("\n");
        return (sb.toString());
    }

    /**
     * Gets a Set of the extension(s) marked CRITICAL in the
     * RevokedCertificate by OID strings.
     *
     * @return a set of the extension oid strings in the
     *         Object that are marked critical.
     */
    public Set<String> getCriticalExtensionOIDs() {
        if (extensions == null)
            return null;
        Set<String> extSet = new LinkedHashSet<String>();
        Extension ex;
        for (Enumeration<Extension> e = extensions.getElements(); e.hasMoreElements();) {
            ex = e.nextElement();
            if (ex.isCritical())
                extSet.add(ex.getExtensionId().toString());
        }
        return extSet;
    }

    /**
     * Gets a Set of the extension(s) marked NON-CRITICAL in the
     * RevokedCertificate by OID strings.
     *
     * @return a set of the extension oid strings in the
     *         Object that are marked critical.
     */
    public Set<String> getNonCriticalExtensionOIDs() {
        if (extensions == null)
            return null;
        Set<String> extSet = new LinkedHashSet<String>();
        Extension ex;
        for (Enumeration<Extension> e = extensions.getElements(); e.hasMoreElements();) {
            ex = e.nextElement();
            if (!ex.isCritical())
                extSet.add(ex.getExtensionId().toString());
        }
        return extSet;
    }

    /**
     * Gets the DER encoded OCTET string for the extension value
     * (<em>extnValue</em>) identified by the passed in oid String.
     * The <code>oid</code> string is
     * represented by a set of positive whole number separated
     * by ".", that means,<br>
     * &lt;positive whole number&gt;.&lt;positive whole number&gt;.&lt;positive
     * whole number&gt;.&lt;...&gt;
     *
     * @param oid the Object Identifier value for the extension.
     * @return the DER encoded octet string of the extension value.
     */
    public byte[] getExtensionValue(String oid) {
        if (extensions == null)
            return null;
        try (DerOutputStream out = new DerOutputStream()) {
            String extAlias = OIDMap.getName(new ObjectIdentifier(oid));
            Extension crlExt = null;

            if (extAlias == null) { // may be unknown
                ObjectIdentifier findOID = new ObjectIdentifier(oid);
                Extension ex = null;
                ObjectIdentifier inCertOID;
                for (Enumeration<Extension> e = extensions.getElements(); e.hasMoreElements();) {
                    ex = e.nextElement();
                    inCertOID = ex.getExtensionId();
                    if (inCertOID.equals(findOID)) {
                        crlExt = ex;
                        break;
                    }
                }
            } else
                crlExt = extensions.get(extAlias);
            if (crlExt == null)
                return null;
            byte[] extData = crlExt.getExtensionValue();
            if (extData == null)
                return null;

            out.putOctetString(extData);
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private void parse(DerValue derVal)
            throws CRLException, X509ExtensionException {

        if (derVal.tag != DerValue.tag_Sequence) {
            throw new CRLException("Invalid encoded RevokedCertificate, " +
                                  "starting sequence tag missing.");
        }
        if (derVal.data.available() == 0)
            throw new CRLException("No data encoded for RevokedCertificates");

        // serial number
        try {
            DerInputStream in = derVal.toDerInputStream();
            DerValue val = in.getDerValue();
            this.serialNumber = new SerialNumber(val);
        } catch (IOException e) {
            throw new CRLException("Parsing Serial Number error: "
                                   + e.toString());
        }

        // revocationDate
        try {
            int nextByte = derVal.data.peekByte();
            if ((byte) nextByte == DerValue.tag_UtcTime) {
                this.revocationDate = derVal.data.getUTCTime();
            } else if ((byte) nextByte == DerValue.tag_GeneralizedTime) {
                this.revocationDate = derVal.data.getGeneralizedTime();
            } else {
                throw new CRLException("Invalid encoding for RevokedCertificates");
            }
        } catch (IOException e) {
            throw new CRLException("Parsing Revocation Date error: "
                                   + e.toString());
        }

        if (derVal.data.available() == 0)
            return; // no extensions

        // crlEntryExtensions
        try {
            this.extensions = new CRLExtensions(derVal.toDerInputStream());
        } catch (IOException e) {
            throw new CRLException("Parsing CRL Entry Extensions error: "
                                   + e.toString());
        }
    }

    /**
     * Serialization write ... X.509 certificates serialize as themselves, and
     * they're parsed when they get read back. (Actually they serialize as some
     * type data from the serialization subsystem, then the cert data.)
     */
    private void writeObject(ObjectOutputStream stream) throws CRLException, X509ExtensionException, IOException {
        DerOutputStream dos = new DerOutputStream();
        encode(dos);
        dos.derEncode(stream);
    }

    /**
     * Serialization read ... X.509 certificates serialize as themselves, and
     * they're parsed when they get read back.
     */
    private void readObject(ObjectInputStream stream) throws CRLException, X509ExtensionException, IOException {
        decode(stream);
    }

}
