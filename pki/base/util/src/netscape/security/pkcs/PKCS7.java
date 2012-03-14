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
package netscape.security.pkcs;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Vector;

import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;

/**
 * PKCS7 as defined in RSA Laboratories PKCS7 Technical Note. Profile
 * Supports only <tt>SignedData</tt> ContentInfo
 * type, where to the type of data signed is plain Data.
 * For signedData, <tt>crls</tt>, <tt>attributes</tt> and
 * PKCS#6 Extended Certificates are not supported.
 * 
 * @version 1.33 97/12/10
 * @author Benjamin Renaud
 */
public class PKCS7 {

    private ObjectIdentifier contentType;

    // the ASN.1 members for a signedData (and other) contentTypes
    private BigInt version;
    private AlgorithmId[] digestAlgorithmIds;
    private ContentInfo contentInfo;
    private X509Certificate[] certificates;
    private SignerInfo[] signerInfos;

    /**
     * Unmarshals a PKCS7 block from its encoded form, parsing the
     * encoded bytes from the InputStream.
     * 
     * @param in an input stream holding at least one PKCS7 block.
     * @exception ParsingException on parsing errors.
     * @exception IOException on other errors.
     */
    public PKCS7(InputStream in) throws ParsingException, IOException {
        DataInputStream dis = new DataInputStream(in);

        int len = 0;
        byte[] newbuf = new byte[len];
        byte[] oldbuf = new byte[len];
        byte[] data = new byte[len];

        do {
            newbuf = new byte[dis.available()];
            len += dis.available();
            dis.readFully(newbuf);
            data = new byte[len];

            System.arraycopy(oldbuf, 0, data, 0, oldbuf.length);
            System.arraycopy(newbuf, 0, data, oldbuf.length, newbuf.length);
            oldbuf = new byte[len];
            System.arraycopy(data, 0, oldbuf, 0, data.length);

        } while (dis.available() > 0);

        parse(new DerInputStream(data));
    }

    /**
     * Unmarshals a PKCS7 block from its encoded form, parsing the
     * encoded bytes from the DerInputStream.
     * 
     * @param derin a DerInputStream holding at least one PKCS7 block.
     * @exception ParsingException on parsing errors.
     */
    public PKCS7(DerInputStream derin) throws ParsingException {
        parse(derin);
    }

    /**
     * Unmarshals a PKCS7 block from its encoded form, parsing the
     * encoded bytes.
     * 
     * @param bytes the encoded bytes.
     * @exception ParsingException on parsing errors.
     */
    public PKCS7(byte[] bytes) throws ParsingException {
        DerInputStream derin = new DerInputStream(bytes);
        parse(derin);
    }

    private void parse(DerInputStream derin) throws ParsingException {
        try {
            ContentInfo contentInfo = new ContentInfo(derin);
            contentType = contentInfo.contentType;
            if (contentType.equals(ContentInfo.SIGNED_DATA_OID)) {
                parseSignedData(contentInfo.getContent());
            } else {
                throw new ParsingException("content type " + contentType +
                        " not supported.");
            }
        } catch (IOException e) {
            ParsingException pe =
                    new ParsingException("IOException: " + e.getMessage());
            pe.fillInStackTrace();
            throw pe;
        }
    }

    /**
     * Construct an initialized PKCS7 block.
     * 
     * @param digestAlgorithmIds the message digest algorithm identifiers.
     * @param contentInfo the content information.
     * @param certificates an array of X.509 certificates.
     * @param signerInfos an array of signer information.
     */
    public PKCS7(AlgorithmId[] digestAlgorithmIds,
            ContentInfo contentInfo,
            X509Certificate[] certificates,
            SignerInfo[] signerInfos) {

        version = new BigInt(1);
        this.digestAlgorithmIds = digestAlgorithmIds;
        this.contentInfo = contentInfo;
        this.certificates = certificates;
        this.signerInfos = signerInfos;
    }

    private void parseSignedData(DerValue val)
            throws ParsingException, IOException {

        DerInputStream dis = val.toDerInputStream();

        // Version
        version = dis.getInteger();

        // digestAlgorithmIds
        DerValue[] digestAlgorithmIdVals = dis.getSet(1);
        int len = digestAlgorithmIdVals.length;
        digestAlgorithmIds = new AlgorithmId[len];
        try {
            for (int i = 0; i < len; i++) {
                DerValue oid = digestAlgorithmIdVals[i];
                digestAlgorithmIds[i] = AlgorithmId.parse(oid);
            }

        } catch (IOException e) {
            ParsingException pe =
                    new ParsingException("Error parsing digest AlgorithmId IDs: " +
                            e.getMessage());
            pe.fillInStackTrace();
            throw pe;
        }
        // contentInfo
        contentInfo = new ContentInfo(dis);

        /*
         * check if certificates (implicit tag) are provided
         * (certificates are OPTIONAL)
         */
        if ((byte) (dis.peekByte()) == (byte) 0xA0) {
            DerValue[] certificateVals = dis.getSet(2, true);

            len = certificateVals.length;
            certificates = new X509Certificate[len];

            for (int i = 0; i < len; i++) {
                try {
                    X509Certificate cert = (X509Certificate) new
                                           X509CertImpl(certificateVals[i]);
                    certificates[i] = cert;
                } catch (CertificateException e) {
                    ParsingException pe =
                            new ParsingException("CertificateException: " +
                                    e.getMessage());
                    pe.fillInStackTrace();
                    throw pe;
                }
            }
        }

        // check if crls (implicit tag) are provided (crls are OPTIONAL)
        if ((byte) (dis.peekByte()) == (byte) 0xA1) {
            dis.getSet(0, true);
        }

        // signerInfos
        DerValue[] signerInfoVals = dis.getSet(1);

        len = signerInfoVals.length;
        signerInfos = new SignerInfo[len];

        for (int i = 0; i < len; i++) {
            DerInputStream in = signerInfoVals[i].toDerInputStream();
            signerInfos[i] = new SignerInfo(in);
        }

    }

    /**
     * Encodes the signed data to an output stream.
     * 
     * @param out the output stream to write the encoded data to.
     * @exception IOException on encoding errors.
     */
    public void encodeSignedData(OutputStream out) throws IOException {
        DerOutputStream derout = new DerOutputStream();
        encodeSignedData(derout, true);
        out.write(derout.toByteArray());
    }

    /**
     * Like method above but not sorted.
     */
    public void encodeSignedData(OutputStream out, boolean sort)
            throws IOException {
        DerOutputStream derout = new DerOutputStream();
        encodeSignedData(derout, sort);
        out.write(derout.toByteArray());
    }

    /**
     * encode signed data, sort certs by default.
     */
    public void encodeSignedData(DerOutputStream out)
            throws IOException {
        encodeSignedData(out, true);
    }

    /**
     * Encodes the signed data to a DerOutputStream.
     * 
     * @param out the DerOutputStream to write the encoded data to.
     * @exception IOException on encoding errors.
     */
    public void encodeSignedData(DerOutputStream out, boolean sort)
            throws IOException {

        DerOutputStream signedData = new DerOutputStream();

        // version
        signedData.putInteger(version);

        // digestAlgorithmIds
        signedData.putOrderedSetOf(DerValue.tag_Set, digestAlgorithmIds);

        // contentInfo
        contentInfo.encode(signedData);

        // cast to X509CertImpl[] since X509CertImpl implements DerEncoder
        X509CertImpl implCerts[] = new X509CertImpl[certificates.length];
        try {
            for (int i = 0; i < certificates.length; i++) {
                implCerts[i] = (X509CertImpl) certificates[i];
            }
        } catch (ClassCastException e) {
            IOException ioe =
                    new IOException("Certificates in PKCS7 " +
                            "must be of class " +
                            "netscape.security.X509CertImpl");
            ioe.fillInStackTrace();
        }

        // Add the certificate set (tagged with [0] IMPLICIT)
        // to the signed data
        if (sort) {
            signedData.putOrderedSetOf((byte) 0xA0, implCerts);
        } else {
            signedData.putSet((byte) 0xA0, implCerts);
        }

        // no crls (OPTIONAL field)

        // signerInfos
        signedData.putOrderedSetOf(DerValue.tag_Set, signerInfos);

        // making it a signed data block
        DerValue signedDataSeq = new DerValue(DerValue.tag_Sequence,
                          signedData.toByteArray());

        // making it a content info sequence
        ContentInfo block = new ContentInfo(ContentInfo.SIGNED_DATA_OID,
                        signedDataSeq);

        // writing out the contentInfo sequence
        block.encode(out);
    }

    /**
     * This verifies a given SignerInfo.
     * 
     * @param info the signer information.
     * @param bytes the DER encoded content information.
     * 
     * @exception NoSuchAlgorithmException on unrecognized algorithms.
     * @exception SignatureException on signature handling errors.
     */
    public SignerInfo verify(SignerInfo info, byte[] bytes)
            throws NoSuchAlgorithmException, SignatureException {
        return info.verify(this, bytes);
    }

    /**
     * Returns all signerInfos which self-verify.
     * 
     * @param bytes the DER encoded content information.
     * 
     * @exception NoSuchAlgorithmException on unrecognized algorithms.
     * @exception SignatureException on signature handling errors.
     */
    public SignerInfo[] verify(byte[] bytes)
            throws NoSuchAlgorithmException, SignatureException {

        Vector<SignerInfo> intResult = new Vector<SignerInfo>();
        for (int i = 0; i < signerInfos.length; i++) {

            SignerInfo signerInfo = verify(signerInfos[i], bytes);
            if (signerInfo != null) {
                intResult.addElement(signerInfo);
            }
        }
        if (intResult.size() != 0) {

            SignerInfo[] result = new SignerInfo[intResult.size()];
            intResult.copyInto(result);
            return result;
        }
        return null;
    }

    /**
     * Returns all signerInfos which self-verify.
     * 
     * @exception NoSuchAlgorithmException on unrecognized algorithms.
     * @exception SignatureException on signature handling errors.
     */
    public SignerInfo[] verify()
            throws NoSuchAlgorithmException, SignatureException {
        return verify(null);
    }

    /**
     * Returns the version number of this PKCS7 block.
     */
    public BigInt getVersion() {
        return version;
    }

    /**
     * Returns the message digest algorithms specified in this PKCS7 block.
     */
    public AlgorithmId[] getDigestAlgorithmIds() {
        return digestAlgorithmIds;
    }

    /**
     * Returns the content information specified in this PKCS7 block.
     */
    public ContentInfo getContentInfo() {
        return contentInfo;
    }

    /**
     * Returns the X.509 certificates listed in this PKCS7 block.
     */
    public X509Certificate[] getCertificates() {
        return certificates;
    }

    /**
     * Returns the signer's information specified in this PKCS7 block.
     */
    public SignerInfo[] getSignerInfos() {
        return signerInfos;
    }

    /**
     * Returns the X.509 certificate listed in this PKCS7 block
     * which has a matching serial number and Issuer name, or
     * null if one is not found.
     * 
     * @param serial the serial number of the certificate to retrieve.
     * @param name the Distinguished Name of the Issuer.
     */
    public X509Certificate getCertificate(BigInt serial, X500Name name) {

        for (int i = 0; i < certificates.length; i++) {
            X509Certificate cert = certificates[i];
            X500Name thisName = (X500Name) cert.getIssuerDN();
            BigInteger tmpSerial = (BigInteger) cert.getSerialNumber();
            BigInt thisSerial = new BigInt(tmpSerial);
            if (serial.equals(thisSerial) && name.equals(thisName)) {
                return cert;
            }
        }
        return null;
    }

    /**
     * Returns the PKCS7 block in a printable string form.
     */
    public String toString() {
        String out = "";

        out += "PKCS7 :: version: " + version + "\n";
        out += "PKCS7 :: digest AlgorithmIds: \n";
        for (int i = 0; i < digestAlgorithmIds.length; i++) {
            out += "\t" + digestAlgorithmIds[i] + "\n";
        }
        out += contentInfo + "\n";
        out += "PKCS7 :: certificates: \n";
        for (int i = 0; i < certificates.length; i++) {
            out += "\t" + i + ".   " + certificates[i] + "\n";
        }
        out += "PKCS7 :: signer infos: \n";
        for (int i = 0; i < signerInfos.length; i++) {
            out += ("\t" + i + ".  " + signerInfos[i] + "\n");
        }
        return out;
    }
}
