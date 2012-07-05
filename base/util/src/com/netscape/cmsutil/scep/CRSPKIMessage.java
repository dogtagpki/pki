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
package com.netscape.cmsutil.scep;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Hashtable;

import netscape.security.pkcs.PKCS10;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.NULL;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkcs7.Attribute;
import org.mozilla.jss.pkcs7.ContentInfo;
import org.mozilla.jss.pkcs7.EncryptedContentInfo;
import org.mozilla.jss.pkcs7.EnvelopedData;
import org.mozilla.jss.pkcs7.IssuerAndSerialNumber;
import org.mozilla.jss.pkcs7.RecipientInfo;
import org.mozilla.jss.pkcs7.SignedData;
import org.mozilla.jss.pkcs7.SignerInfo;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

public class CRSPKIMessage {

    // OIDs for authenticated attributes
    public static OBJECT_IDENTIFIER CRS_MESSAGETYPE =
            new OBJECT_IDENTIFIER(new long[] { 2, 16, 840, 1, 113733, 1, 9, 2 }
            );
    public static OBJECT_IDENTIFIER CRS_PKISTATUS =
            new OBJECT_IDENTIFIER(new long[] { 2, 16, 840, 1, 113733, 1, 9, 3 }
            );
    public static OBJECT_IDENTIFIER CRS_FAILINFO =
            new OBJECT_IDENTIFIER(new long[] { 2, 16, 840, 1, 113733, 1, 9, 4 }
            );
    public static OBJECT_IDENTIFIER CRS_SENDERNONCE =
            new OBJECT_IDENTIFIER(new long[] { 2, 16, 840, 1, 113733, 1, 9, 5 }
            );
    public static OBJECT_IDENTIFIER CRS_RECIPIENTNONCE =
            new OBJECT_IDENTIFIER(new long[] { 2, 16, 840, 1, 113733, 1, 9, 6 }
            );
    public static OBJECT_IDENTIFIER CRS_TRANSID =
            new OBJECT_IDENTIFIER(new long[] { 2, 16, 840, 1, 113733, 1, 9, 7 }
            );
    public static OBJECT_IDENTIFIER CRS_EXTENSIONREQ =
            new OBJECT_IDENTIFIER(new long[] { 2, 16, 840, 1, 113733, 1, 9, 8 }
            );

    // PKCS9 defined OIDs

    public static OBJECT_IDENTIFIER PKCS9_CONTENT_TYPE =
            new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 9, 3 }
            );

    public static OBJECT_IDENTIFIER PKCS9_MESSAGE_DIGEST =
            new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 9, 4 }
            );

    /* PKCS 1 - rsaEncryption */
    public static OBJECT_IDENTIFIER RSA_ENCRYPTION =
            new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 1, 1 }
            );

    public static OBJECT_IDENTIFIER DES_CBC_ENCRYPTION =
            new OBJECT_IDENTIFIER(new long[] { 1, 3, 14, 3, 2, 7 }
            );

    public static OBJECT_IDENTIFIER DES_EDE3_CBC_ENCRYPTION =
            new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 3, 7 }
            );

    public static OBJECT_IDENTIFIER MD5_DIGEST =
            new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 2, 5 }
            );

    public static OBJECT_IDENTIFIER SHA1_DIGEST =
            new OBJECT_IDENTIFIER(new long[] { 1, 3, 14, 3, 2, 26 }
            );

    public static OBJECT_IDENTIFIER SHA256_DIGEST =
            new OBJECT_IDENTIFIER(new long[] { 2, 16, 840, 1, 101, 3, 4, 2, 1 }
            );

    public static OBJECT_IDENTIFIER SHA512_DIGEST =
            new OBJECT_IDENTIFIER(new long[] { 2, 16, 840, 1, 101, 3, 4, 2, 3 }
            );

    // Strings given in 'messageType' authenticated attribute
    public final static String mType_PKCSReq = "19";
    public final static String mType_CertRep = "3";
    public final static String mType_GetCertInitial = "20";
    public final static String mType_GetCert = "21";
    public final static String mType_GetCRL = "22";

    // Strings given in 'PKIStatus' authenticated attribute
    public final static String mStatus_SUCCESS = "0";
    public final static String mStatus_FAILURE = "2";
    public final static String mStatus_PENDING = "3";

    // Strings given in 'failInfo' authenticated attribute
    public final static String mFailInfo_badAlg = "0";
    public final static String mFailInfo_badMessageCheck = "1";
    public final static String mFailInfo_badRequest = "2";
    public final static String mFailInfo_badTime = "3";
    public final static String mFailInfo_badCertId = "4";
    public final static String mFailInfo_unsupportedExt = "5";
    public final static String mFailInfo_mustArchiveKeys = "6";
    public final static String mFailInfo_badIdentity = "7";
    public final static String mFailInfo_popRequired = "8";
    public final static String mFailInfo_popFailed = "9";
    public final static String mFailInfo_noKeyReuse = "10";
    public final static String mFailInfo_internalCAError = "11";
    public final static String mFailInfo_tryLater = "12";

    // ************************************************************************
    // These private members represent the flattened structure of the PKIMessage
    // ************************************************************************

    // top level is just a ContentInfo
    private ContentInfo crsci;
    // it's content is a signedData
    private SignedData sd;

    // In the signed data, we have:
    private ContentInfo data; // The data to be digested
    private EnvelopedData sded; // Enveloped data inside of signed data
    private byte[] signerCertBytes;
    org.mozilla.jss.pkix.cert.Certificate signerCert;

    private SET sis; // set of SignerInfos
    private SignerInfo si; // First SignerInfo
    private AlgorithmIdentifier digestAlgorithmId = null;
    private SET aa; // Authenticated Attributes
    private SET aa_old; // Authenticated Attributes
    private IssuerAndSerialNumber sgnIASN; // Signer's Issuer Name and Serialnum
    private OCTET_STRING aa_digest; // digest of the authenticated attrs

    private String messageType; // these are all authenticated attributes
    private String failInfo;
    private String pkiStatus;
    private String transactionID;
    private byte[] senderNonce;
    private byte[] recipientNonce;
    private OCTET_STRING msg_digest; // digest of the message

    // Inside the sded Enveloped data
    private RecipientInfo ri; // First RecipientInfo
    private int riv; // Version
    private AlgorithmIdentifier riAlgid; // alg that the bulk key is wrapped with
    private byte[] riKey; // bulk key, wrapped with above algorithm
    private IssuerAndSerialNumber rcpIASN; // Recipient's Issuer Name and Serial Number

    private EncryptedContentInfo eci;
    private byte[] iv; // initialization vector for above key
    private byte[] ec; // encrypted content (P10, in case of request)
    private String encryptionAlgorithm = null;

    // For the CertRep, the enveloped content is another signed Data:
    private SignedData crsd;
    @SuppressWarnings("unused")
    private int rsdVersion;
    @SuppressWarnings("unused")
    private byte[] rsdCert; // certificate to send in response

    private PKCS10 myP10;

    private Hashtable<String, Object> attrs; // miscellanous

    //   *** END *** //

    public void debug() {
    }

    public void put(String a, Object b) {
        attrs.put(a, b);
    }

    public Object get(Object a) {
        return attrs.get(a);
    }

    private SignatureAlgorithm getSignatureAlgorithm(String hashAlgorithm) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSASignatureWithMD5Digest;
        if (hashAlgorithm != null) {
            if (hashAlgorithm.equals("SHA1")) {
                signatureAlgorithm = SignatureAlgorithm.RSASignatureWithSHA1Digest;
            } else if (hashAlgorithm.equals("SHA256")) {
                signatureAlgorithm = SignatureAlgorithm.RSASignatureWithSHA256Digest;
            } else if (hashAlgorithm.equals("SHA512")) {
                signatureAlgorithm = SignatureAlgorithm.RSASignatureWithSHA512Digest;
            }
        }
        return signatureAlgorithm;
    }

    private OBJECT_IDENTIFIER getAlgorithmOID(String hashAlgorithm) {
        OBJECT_IDENTIFIER oid = MD5_DIGEST;
        if (hashAlgorithm != null) {
            if (hashAlgorithm.equals("SHA1")) {
                oid = SHA1_DIGEST;
            } else if (hashAlgorithm.equals("SHA256")) {
                oid = SHA256_DIGEST;
            } else if (hashAlgorithm.equals("SHA512")) {
                oid = SHA512_DIGEST;
            }
        }
        return oid;
    }

    // getHashAlgorithm is added to work around issue 636217
    private String getHashAlgorithm(OBJECT_IDENTIFIER algorithmOID) {
        String hashAlgorithm = null;
        if (algorithmOID != null) {
            if (algorithmOID.equals(MD5_DIGEST)) {
                hashAlgorithm = "MD5";
            } else if (algorithmOID.equals(SHA1_DIGEST)) {
                hashAlgorithm = "SHA1";
            } else if (algorithmOID.equals(SHA256_DIGEST)) {
                hashAlgorithm = "SHA256";
            } else if (algorithmOID.equals(SHA512_DIGEST)) {
                hashAlgorithm = "SHA512";
            }
        }
        return hashAlgorithm;
    }

    // These functions are used to initialize the various blobs

    public void makeSignedData(int version, byte[] certificate, String hashAlgorithm) {

        SET digest_algs = new SET();

        digest_algs.addElement(new AlgorithmIdentifier(getAlgorithmOID(hashAlgorithm), new NULL()));

        //      SET certs = new SET();
        //      certs.addElement(new ANY(certificate));

        SET sis = new SET();

        sis.addElement(si);

        ContentInfo data = this.data;

        this.sd = new SignedData(
                digest_algs,
                data,
                null, // don't send the certs, he already has them
                null, // crl's
                sis);

    }

    public byte[] getResponse() throws IOException, InvalidBERException {

        crsci = new ContentInfo(ContentInfo.SIGNED_DATA,
                    sd);

        return ASN1Util.encode(crsci);

        // ANY a = crsci.getContent();
        // return a.getEncoded();
    }

    /*
     public void makeSignerInfo_old(int version,
     // issuer and serialnumber
     byte[] digest) {

     si = new SignerInfo(new INTEGER(version),
     sgnIASN,                   // issuer and serialnum
     new AlgorithmIdentifier(MD5_DIGEST, new NULL()),       // digest algorithm
     this.aa,         // Authenticated Attributes
     new AlgorithmIdentifier(RSA_ENCRYPTION,new NULL()),       // digest encryption algorithm
     new OCTET_STRING(digest),  // digest
     null);           // unauthenticated attributes

     }
     */

    public void makeSignerInfo(int version,
            // issuer and serialnumber
            org.mozilla.jss.crypto.PrivateKey pk, String hashAlgorithm)
            throws java.security.NoSuchAlgorithmException,
            TokenException,
            java.security.InvalidKeyException,
            java.security.SignatureException,
            org.mozilla.jss.CryptoManager.NotInitializedException {

        si = new SignerInfo(sgnIASN, // issuer and serialnum
                this.aa, // Authenticated Attributes
                null, // Unauthenticated Attrs
                ContentInfo.ENVELOPED_DATA, // content type
                msg_digest.toByteArray(), // digest
                getSignatureAlgorithm(hashAlgorithm),
                    pk);
    }

    public void makeAuthenticatedAttributes() {

        aa = new SET();

        try {
            if (transactionID != null) {
                SET tidset = new SET();

                tidset.addElement((new PrintableString(transactionID)));
                aa.addElement(new Attribute(CRS_TRANSID, tidset));
            }

            if (pkiStatus != null) {
                SET pkistatusset = new SET();

                pkistatusset.addElement(new PrintableString(pkiStatus));
                aa.addElement(new Attribute(CRS_PKISTATUS, pkistatusset));
            }

            if (messageType != null) {
                SET aaset = new SET();

                aaset.addElement(new PrintableString(messageType));
                aa.addElement(new Attribute(CRS_MESSAGETYPE, aaset));
            }

            if (failInfo != null) {
                SET fiset = new SET();

                fiset.addElement(new PrintableString(failInfo));
                aa.addElement(new Attribute(CRS_FAILINFO, fiset));
            }

            if (senderNonce != null) {
                SET snset = new SET();

                snset.addElement(new OCTET_STRING(senderNonce));
                aa.addElement(new Attribute(CRS_SENDERNONCE, snset));
            }

            if (recipientNonce != null) {
                SET rnset = new SET();

                rnset.addElement(new OCTET_STRING(recipientNonce));
                aa.addElement(new Attribute(CRS_RECIPIENTNONCE, rnset));
            }

            // XXX sender nonce

        } catch (CharConversionException e) {
        }
    }

    public byte[] makeEnvelopedData(int version) {

        byte[] r;

        try {

            if (this.ri != null) {
                ContentInfo ci;

                SET ris = new SET();

                ris.addElement(this.ri);

                this.sded = new EnvelopedData(
                            new INTEGER(version),
                            ris,
                            eci);

                ci = new ContentInfo(ContentInfo.ENVELOPED_DATA,
                            sded);
                ByteArrayOutputStream ba = new ByteArrayOutputStream();

                ci.encode(ba);
                r = ba.toByteArray();
            } else {
                r = new byte[0];
            }

            this.data = new ContentInfo(ContentInfo.DATA,
                        new OCTET_STRING(r));

            return r;

            //            return this.sded.getEncodedContents();
        } catch (Exception e) {
            return null;
        }

    }

    public void makeRecipientInfo(int version, byte[] riKey) {
        this.riv = version;

        this.riAlgid = new AlgorithmIdentifier(RSA_ENCRYPTION, new NULL());
        this.riKey = riKey;

        this.ri = new RecipientInfo(
                    new INTEGER(this.riv),
                    rcpIASN,
                    this.riAlgid,
                    new OCTET_STRING(this.riKey)
                );
    }

    public void makeEncryptedContentInfo(byte[] iv, byte[] ec, String algorithm) {
        this.iv = iv;
        this.ec = ec;

        try {
            OBJECT_IDENTIFIER oid = DES_CBC_ENCRYPTION;
            if (algorithm != null && algorithm.equals("DES3"))
                oid = DES_EDE3_CBC_ENCRYPTION;

            AlgorithmIdentifier aid = new AlgorithmIdentifier(oid, new OCTET_STRING(iv));

            //eci =  EncryptedContentInfo.createCRSCompatibleEncryptedContentInfo(
            eci = new EncryptedContentInfo(ContentInfo.DATA,
                        aid,
                        new OCTET_STRING(ec)
                    );

        } catch (Exception e) {
        }
    }

    public byte[] makeSignedRep(int v, byte[] certificate) {
        rsdVersion = v;
        rsdCert = certificate;
        try {
            SET certs = new SET();
            ANY cert = new ANY(certificate);

            certs.addElement(cert);

            crsd = new SignedData(
                        new SET(), // empty set of digestAlgorithmID's
                    new ContentInfo(
                            new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 7, 1 }
                            ),
                            null), //empty content
                    certs,
                        null, // no CRL's
                    new SET() // empty SignerInfos
                    );
            ContentInfo wrap = new ContentInfo(ContentInfo.SIGNED_DATA,
                    crsd);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            wrap.encode(baos);

            return baos.toByteArray();
            //            return crsd.getEncodedContents();
        } catch (InvalidBERException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("{ messageType=");
        sb.append(getMessageType());
        sb.append(", failInfo=");
        sb.append(getFailInfo());
        sb.append(", pkiStatus=");
        sb.append(getPKIStatus());
        sb.append(", transactionID=");
        sb.append(getTransactionID());
        sb.append(", senderNonce=");
        sb.append(Arrays.toString(getSenderNonce()));
        sb.append(", recipientNonce=");
        sb.append(Arrays.toString(getRecipientNonce()));
        sb.append(" }");

        String s = sb.toString();
        return s;
    }

    public String getMessageType() {
        return messageType;
    }

    public String getFailInfo() {
        return failInfo;
    }

    public String getPKIStatus() {
        return pkiStatus;
    }

    public String getTransactionID() {
        return transactionID;
    }

    public byte[] getSenderNonce() {
        return senderNonce;
    }

    public byte[] getRecipientNonce() {
        return recipientNonce;
    }

    public byte[] getWrappedKey() {
        return riKey;
    }

    public byte[] getEncryptedPkcs10() {
        return ec;
    }

    public byte[] getIV() {
        return iv;
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public String getDigestAlgorithmName() {
        String name = null;
        if (digestAlgorithmId != null) {
            name = getHashAlgorithm(digestAlgorithmId.getOID());
        }
        return name;
    }

    public PublicKey getSignerPublicKey() {
        try {

            org.mozilla.jss.pkix.cert.Certificate.Template ct = new
                    org.mozilla.jss.pkix.cert.Certificate.Template();

            ByteArrayInputStream bais = new ByteArrayInputStream(this.signerCertBytes);

            signerCert = (org.mozilla.jss.pkix.cert.Certificate) ct.decode(bais);
            return signerCert.getInfo().getSubjectPublicKeyInfo().toPublicKey();
        } catch (Exception e) {
            return null;
        }
    }

    public byte[] getAA() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            aa.encode(baos);
            return baos.toByteArray();
        } catch (Exception e) {
            return null;
        }

    }

    public void setAA_old(SET auth_attrs) {
        aa_old = auth_attrs;
    }

    // SWP
    public byte[] getAA_old() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            aa_old.encode(baos);
            return baos.toByteArray();
        } catch (Exception e) {
            return null;
        }

    }

    public byte[] getAADigest() {
        return aa_digest.toByteArray();
    }

    public PKCS10 getP10() {
        return myP10;
    }

    public void setP10(PKCS10 p10) {
        myP10 = p10;
    }

    public void setSgnIssuerAndSerialNumber(IssuerAndSerialNumber iasn) {
        this.sgnIASN = iasn;
    }

    public void setRcpIssuerAndSerialNumber(IssuerAndSerialNumber iasn) {
        this.rcpIASN = iasn;
    }

    public IssuerAndSerialNumber getSgnIssuerAndSerialNumber() {
        return this.sgnIASN;
    }

    public IssuerAndSerialNumber getRcpIssuerAndSerialNumber() {
        return this.rcpIASN;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }

    public void setPKIStatus(String pkiStatus) {
        this.pkiStatus = pkiStatus;
    }

    public void setFailInfo(String failInfo) {
        this.failInfo = failInfo;
    }

    public void setTransactionID(String tid) {
        this.transactionID = tid;
    }

    public void setRecipientNonce(byte[] rn) {
        this.recipientNonce = rn;
    }

    public void setSenderNonce(byte[] sn) {
        this.senderNonce = sn;
    }

    //    public void setCertificate(byte [] cert)       { this.certificate = cert; }

    public void setMsgDigest(byte[] digest) {
        this.msg_digest = new OCTET_STRING(digest);
    }

    public void setAADigest(byte[] digest) {
        this.aa_digest = new OCTET_STRING(digest);
    }

    public void setPending() {
        // setIssuerAndSerialNumber();

        setMessageType(mType_CertRep);
        setPKIStatus(mStatus_PENDING);
    };

    public void setFailure(String failInfo) {
        setMessageType(mType_CertRep);
        setPKIStatus(mStatus_FAILURE);
        setFailInfo(failInfo);
    }

    // Should add a Certificate to this call
    public void setSuccess() {
        setMessageType(mType_CertRep);
        setPKIStatus(mStatus_SUCCESS);
    }

    /**
     * Gets a byte array which is the der-encoded blob
     * which gets sent back to the router.
     */

    public byte[] getEncoded() {
        //Assert.assert(messageType != null);
        //Assert.assert(pkiStatus != null);

        return new byte[1]; // blagh
    }

    private void decodeCRSPKIMessage(ByteArrayInputStream bais) throws InvalidBERException, Exception {

        org.mozilla.jss.pkcs7.ContentInfo.Template crscit;

        crscit = new ContentInfo.Template();
        crsci = (ContentInfo) crscit.decode(bais);

        if (!ContentInfo.SIGNED_DATA.equals(crsci.getContentType())) {
            throw new Exception("ContentType wasn't signed data, it was" + crsci.getContentType());
        }

        // Now that we know that the contentInfo is a SignedData, we can decode it
        SignedData.Template sdt = new SignedData.Template();

        sd = (SignedData) sdt.decode(
                    new ByteArrayInputStream(
                            crsci.getContent().getEncoded()
                    ));
        this.decodeSD();
    }

    public CRSPKIMessage() {
        attrs = new Hashtable<String, Object>();
    }

    public CRSPKIMessage(ByteArrayInputStream bais) throws InvalidBERException, Exception {
        attrs = new Hashtable<String, Object>();
        decodeCRSPKIMessage(bais);
    }

    private void decodeSD() throws Exception {
        ContentInfo sdci;

        sis = sd.getSignerInfos();

        decodeSI();

        sdci = sd.getContentInfo();

        // HACK to work with CRS
        ANY a = sdci.getContent();
        ByteArrayInputStream s = new ByteArrayInputStream(a.getEncoded());
        OCTET_STRING os = (OCTET_STRING) (new OCTET_STRING.Template()).decode(s);

        ByteArrayInputStream s2 = new ByteArrayInputStream(os.toByteArray());
        ContentInfo ci = (ContentInfo) (new ContentInfo.Template()).decode(s2);
        ByteArrayInputStream s3 = new ByteArrayInputStream(ci.getContent().getEncoded());

        EnvelopedData.Template edt = new EnvelopedData.Template();

        sded = (EnvelopedData) edt.decode(s3);

        SET signerCerts = sd.getCertificates();
        Certificate firstCert = (Certificate) signerCerts.elementAt(0);

        signerCertBytes = ASN1Util.encode(firstCert);

        CertificateInfo firstCertInfo = firstCert.getInfo();

        sgnIASN = new IssuerAndSerialNumber(firstCertInfo.getIssuer(),
                    firstCertInfo.getSerialNumber());

        decodeED();
    }

    private void decodeSI() throws Exception {
        if (sis.size() == 0) {
            throw new Exception("SignerInfos is empty");
        }
        si = (SignerInfo) sis.elementAt(0);

        digestAlgorithmId = si.getDigestAlgorithmIdentifer();

        decodeAA();

        aa_digest = new OCTET_STRING(si.getEncryptedDigest());
    }

    private void decodeED() throws Exception {
        SET ris;

        ris = sded.getRecipientInfos();

        if (ris.size() == 0) {
            throw new Exception("RecipientInfos is empty");
        }
        ri = (RecipientInfo) ris.elementAt(0);
        eci = sded.getEncryptedContentInfo();

        if (eci.getContentEncryptionAlgorithm().getOID().equals(DES_EDE3_CBC_ENCRYPTION)) {
            encryptionAlgorithm = "DES3";
        } else if (eci.getContentEncryptionAlgorithm().getOID().equals(DES_CBC_ENCRYPTION)) {
            encryptionAlgorithm = "DES";
        } else {
            throw new Exception("P10 encrypted alg is not supported (not DES): "
                    + eci.getContentEncryptionAlgorithm().getOID());
        }

        ec = eci.getEncryptedContent().toByteArray();

        OCTET_STRING.Template ost = new OCTET_STRING.Template();

        OCTET_STRING os = (OCTET_STRING)
                ost.decode(new ByteArrayInputStream(
                        ((ANY) eci.getContentEncryptionAlgorithm().getParameters()).getEncoded()
                        )
                        );

        iv = os.toByteArray();

        decodeRI();
    }

    /**
     * The PKCS10 request is encrypt with a symmetric key.
     * This key in turn is encrypted with the RSA key in the
     * CA certificate.
     *
     * riAlgid is the algorithm the symm key is encrypted with. It had
     * better be RSA
     * riKey is the encrypted symmetric key
     */

    private void decodeRI() throws Exception {

        // really should get issuer and serial number of our RI, as this
        // indicates the key we should use to decrypt with. However, we're just
        // going to assume that the key is the Signing cert for the server.

        riAlgid = ri.getKeyEncryptionAlgorithmID();

        if (!riAlgid.getOID().equals(RSA_ENCRYPTION)) {
            throw new Exception("Request is protected by a key which we can't decrypt");
        }

        riKey = ri.getEncryptedKey().toByteArray();

    }

    private void decodeAA() throws InvalidBERException, IOException {
        aa = si.getAuthenticatedAttributes();

        int count;

        for (count = 0; count < aa.size(); count++) {
            Attribute a = (Attribute) aa.elementAt(count);
            SET s = a.getValues();
            ANY f = (ANY) s.elementAt(0);
            PrintableString ps;
            PrintableString.Template pst = new PrintableString.Template();
            OCTET_STRING.Template ost = new OCTET_STRING.Template();

            OBJECT_IDENTIFIER oid = a.getType();

            if (oid.equals(CRS_MESSAGETYPE)) {
                ps = (PrintableString) pst.decode(new ByteArrayInputStream(f.getEncoded()));
                // We make a new string here
                messageType = ps.toString();

            } else if (oid.equals(CRS_PKISTATUS)) {
                ps = (PrintableString) pst.decode(new ByteArrayInputStream(f.getEncoded()));
                pkiStatus = ps.toString();
            } else if (oid.equals(CRS_FAILINFO)) {
                ps = (PrintableString) pst.decode(new ByteArrayInputStream(f.getEncoded()));
                failInfo = ps.toString();
            } else if (oid.equals(CRS_SENDERNONCE)) {
                OCTET_STRING oss = (OCTET_STRING) ost.decode(new ByteArrayInputStream(f.getEncoded()));

                senderNonce = oss.toByteArray();
            } else if (oid.equals(CRS_RECIPIENTNONCE)) {
                OCTET_STRING osr = (OCTET_STRING) ost.decode(new ByteArrayInputStream(f.getEncoded()));

                recipientNonce = osr.toByteArray();
            } else if (oid.equals(CRS_TRANSID)) {
                ps = (PrintableString) pst.decode(new ByteArrayInputStream(f.getEncoded()));
                transactionID = ps.toString();
            }

        }

    } // end of decodeAA();

    public String getMessageTypeString() {
        if (messageType == null) {
            return null;
        }

        if (messageType.equals(mType_PKCSReq)) {
            return "PKCSReq";
        }
        if (messageType.equals(mType_CertRep)) {
            return "CertRep";
        }
        if (messageType.equals(mType_GetCertInitial)) {
            return "GetCertInitial";
        }
        if (messageType.equals(mType_GetCert)) {
            return "GetCert";
        }
        if (messageType.equals(mType_GetCRL)) {
            return "GetCRL";
        }
        // messageType should match one of the above
        //Assert.assert(false);
        return null;
    }
}
