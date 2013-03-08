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

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import netscape.security.util.BigInt;
import netscape.security.util.DerEncoder;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.X500Name;

/**
 * A SignerInfo, as defined in PKCS#7's signedData type.
 *
 * @author Benjamin Renaud
 * @version 1.27 97/12/10
 */
public class SignerInfo implements DerEncoder {

    BigInt version;
    X500Name issuerName;
    BigInt certificateSerialNumber;
    AlgorithmId digestAlgorithmId;
    AlgorithmId digestEncryptionAlgorithmId;
    byte[] encryptedDigest;

    PKCS9Attributes authenticatedAttributes;
    PKCS9Attributes unauthenticatedAttributes;

    public SignerInfo(X500Name issuerName,
              BigInt serial,
              AlgorithmId digestAlgorithmId,
              AlgorithmId digestEncryptionAlgorithmId,
              byte[] encryptedDigest) {
        this.version = new BigInt(1);
        this.issuerName = issuerName;
        this.certificateSerialNumber = serial;
        this.digestAlgorithmId = digestAlgorithmId;
        this.digestEncryptionAlgorithmId = digestEncryptionAlgorithmId;
        this.encryptedDigest = encryptedDigest;
    }

    public SignerInfo(X500Name issuerName,
              BigInt serial,
              AlgorithmId digestAlgorithmId,
              PKCS9Attributes authenticatedAttributes,
              AlgorithmId digestEncryptionAlgorithmId,
              byte[] encryptedDigest,
              PKCS9Attributes unauthenticatedAttributes) {
        this.version = new BigInt(1);
        this.issuerName = issuerName;
        this.certificateSerialNumber = serial;
        this.digestAlgorithmId = digestAlgorithmId;
        this.authenticatedAttributes = authenticatedAttributes;
        this.digestEncryptionAlgorithmId = digestEncryptionAlgorithmId;
        this.encryptedDigest = encryptedDigest;
        this.unauthenticatedAttributes = unauthenticatedAttributes;
    }

    public SignerInfo(DerInputStream derin)
            throws IOException, ParsingException {

        // version
        version = derin.getInteger();

        // issuerAndSerialNumber
        DerValue[] issuerAndSerialNumber = derin.getSequence(2);
        byte[] issuerBytes = issuerAndSerialNumber[0].toByteArray();
        issuerName = new X500Name(new DerValue(DerValue.tag_Sequence,
                           issuerBytes));
        certificateSerialNumber = issuerAndSerialNumber[1].getInteger();

        // digestAlgorithmId
        DerValue tmp = derin.getDerValue();

        digestAlgorithmId = AlgorithmId.parse(tmp);

        /*
         * check if set of auth attributes (implicit tag) is provided
         * (auth attributes are OPTIONAL)
         */
        if ((byte) (derin.peekByte()) == (byte) 0xA0) {
            authenticatedAttributes = new PKCS9Attributes(derin);
        }

        // digestEncryptionAlgorithmId - little RSA naming scheme -
        // signature == encryption...
        tmp = derin.getDerValue();

        digestEncryptionAlgorithmId = AlgorithmId.parse(tmp);

        // encryptedDigest
        encryptedDigest = derin.getOctetString();

        /*
         * check if set of unauth attributes (implicit tag) is provided
         * (unauth attributes are OPTIONAL)
         */
        if (derin.available() != 0 && (byte) (derin.peekByte()) == (byte) 0xA1) {
            unauthenticatedAttributes = new PKCS9Attributes(derin);
        }

        // all done
        if (derin.available() != 0) {
            throw new ParsingException("extra data at the end");
        }
    }

    public void encode(DerOutputStream out) throws IOException {

        derEncode(out);
    }

    /**
     * DER encode this object onto an output stream.
     * Implements the <code>DerEncoder</code> interface.
     *
     * @param out
     *            the output stream on which to write the DER encoding.
     *
     * @exception IOException on encoding error.
     */
    public void derEncode(OutputStream out) throws IOException {
        try (DerOutputStream tmp = new DerOutputStream()) {
            DerOutputStream seq = new DerOutputStream();
            seq.putInteger(version);
            DerOutputStream issuerAndSerialNumber = new DerOutputStream();
            issuerName.encode(issuerAndSerialNumber);
            issuerAndSerialNumber.putInteger(certificateSerialNumber);
            seq.write(DerValue.tag_Sequence, issuerAndSerialNumber);

            digestAlgorithmId.encode(seq);

            // encode authenticated attributes if there are any
            if (authenticatedAttributes != null)
                authenticatedAttributes.encode((byte) 0xA0, seq);

            digestEncryptionAlgorithmId.encode(seq);

            seq.putOctetString(encryptedDigest);

            // encode unauthenticated attributes if there are any
            if (unauthenticatedAttributes != null)
                unauthenticatedAttributes.encode((byte) 0xA1, seq);

            tmp.write(DerValue.tag_Sequence, seq);

            out.write(tmp.toByteArray());
        }
    }

    public X509Certificate getCertificate(PKCS7 block)
            throws IOException {
        return block.getCertificate(certificateSerialNumber, issuerName);
    }

    /* Returns null if verify fails, this signerInfo if
       verify succeeds. */
    SignerInfo verify(PKCS7 block, byte[] data)
            throws NoSuchAlgorithmException, SignatureException {

        try {

            ContentInfo content = block.getContentInfo();
            if (data == null) {
                data = content.getContentBytes();
            }

            String digestAlgname =
                    getDigestAlgorithmId().getName();

            byte[] dataSigned;

            // if there are authenticate attributes, get the message
            // digest and compare it with the digest of data
            if (authenticatedAttributes == null) {
                dataSigned = data;
            } else {

                // first, check content type
                ObjectIdentifier contentType = (ObjectIdentifier)
                        authenticatedAttributes.getAttributeValue(
                                PKCS9Attribute.CONTENT_TYPE_OID);
                if (contentType == null ||
                        !contentType.equals(content.contentType))
                    return null; // contentType does not match, bad SignerInfo

                // now, check message digest
                byte[] messageDigest = (byte[])
                        authenticatedAttributes.getAttributeValue(
                                PKCS9Attribute.MESSAGE_DIGEST_OID);

                if (messageDigest == null) // fail if there is no message digest
                    return null;

                MessageDigest md = MessageDigest.getInstance(digestAlgname);
                byte[] computedMessageDigest = md.digest(data);

                if (messageDigest.length != computedMessageDigest.length)
                    return null;
                for (int i = 0; i < messageDigest.length; i++) {
                    if (messageDigest[i] != computedMessageDigest[i])
                        return null;
                }

                // message digest attribute matched
                // digest of original data

                // the data actually signed is the DER encoding of
                // the authenticated attributes (tagged with
                // the "SET OF" tag, not 0xA0).
                dataSigned = authenticatedAttributes.getDerEncoding();
            }

            // put together digest algorithm and encryption algorithm
            // to form signing algorithm
            String encryptionAlgname =
                    getDigestEncryptionAlgorithmId().getName();

            String algname;
            if (encryptionAlgname.equals("DSA") ||
                    encryptionAlgname.equals("SHA1withDSA")) {
                algname = "DSA";
            } else {
                algname = digestAlgname + "/" + encryptionAlgname;
            }

            Signature sig = Signature.getInstance(algname);
            X509Certificate cert = getCertificate(block);

            if (cert == null) {
                return null;
            }

            PublicKey key = cert.getPublicKey();
            sig.initVerify(key);

            sig.update(dataSigned);

            if (sig.verify(encryptedDigest)) {
                return this;
            }

        } catch (IOException e) {
            throw new SignatureException("IO error verifying signature:\n" +
                     e.getMessage());

        } catch (InvalidKeyException e) {
            throw new SignatureException("InvalidKey: " + e.getMessage());

        }
        return null;
    }

    /* Verify the content of the pkcs7 block. */
    SignerInfo verify(PKCS7 block)
            throws NoSuchAlgorithmException, SignatureException {
        return verify(block, null);
    }

    public BigInt getVersion() {
        return version;
    }

    public X500Name getIssuerName() {
        return issuerName;
    }

    public BigInt getCertificateSerialNumber() {
        return certificateSerialNumber;
    }

    public AlgorithmId getDigestAlgorithmId() {
        return digestAlgorithmId;
    }

    public PKCS9Attributes getAuthenticatedAttributes() {
        return authenticatedAttributes;
    }

    public AlgorithmId getDigestEncryptionAlgorithmId() {
        return digestEncryptionAlgorithmId;
    }

    public byte[] getEncryptedDigest() {
        return encryptedDigest;
    }

    public PKCS9Attributes getUnauthenticatedAttributes() {
        return unauthenticatedAttributes;
    }

    public String toString() {
        netscape.security.util.PrettyPrintFormat pp =
                new netscape.security.util.PrettyPrintFormat(" ", 20);
        String digestbits = pp.toHexString(encryptedDigest);

        String out = "";

        out += "Signer Info for (issuer): " + issuerName + "\n";
        out += "\tversion: " + version + "\n";
        out += "\tcertificateSerialNumber: " + certificateSerialNumber +
                "\n";
        out += "\tdigestAlgorithmId: " + digestAlgorithmId + "\n";
        if (authenticatedAttributes != null) {
            out += "\tauthenticatedAttributes: " + authenticatedAttributes +
                    "\n";
        }
        out += "\tdigestEncryptionAlgorithmId: " + digestEncryptionAlgorithmId +
                "\n";

        out += "\tencryptedDigest: " + "\n" +
                digestbits + "\n";
        if (unauthenticatedAttributes != null) {
            out += "\tunauthenticatedAttributes: " +
                    unauthenticatedAttributes + "\n";
        }
        return out;
    }

}
