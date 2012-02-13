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
package com.netscape.cmstools;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;

import netscape.security.pkcs.PKCS10;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs10.CertificationRequest;
import org.mozilla.jss.pkix.cmc.PKIData;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cmc.TaggedCertificationRequest;
import org.mozilla.jss.pkix.cmc.TaggedRequest;
import org.mozilla.jss.pkix.cms.ContentInfo;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;
import org.mozilla.jss.pkix.cms.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cms.SignedData;
import org.mozilla.jss.pkix.cms.SignerIdentifier;
import org.mozilla.jss.pkix.cms.SignerInfo;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.util.Password;

/**
 * Tool for signing PKCS #10 , return CMC enrollment request
 * 
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public class CMCEnroll {

    public static final String PR_REQUEST_CMC = "CMC";
    public static final String PR_REQUEST_PKCS10 = "PKCS10";

    public static final int ARGC = 4;
    private static final String CERTDB = "cert8.db";
    private static final String KEYDB = "key3.db";
    public static final String HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String TRAILER = "-----END NEW CERTIFICATE REQUEST-----";

    void cleanArgs(String[] s) {

    }

    public static X509Certificate getCertificate(String tokenname,
            String nickname) throws Exception {
        CryptoManager manager = CryptoManager.getInstance();
        CryptoToken token = null;

        if (tokenname.equals("internal")) {
            token = manager.getInternalKeyStorageToken();
        } else {
            token = manager.getTokenByName(tokenname);
        }
        StringBuffer certname = new StringBuffer();

        if (!token.equals(manager.getInternalKeyStorageToken())) {
            certname.append(tokenname);
            certname.append(":");
        }
        certname.append(nickname);
        try {
            return manager.findCertByNickname(certname.toString());
        } catch (ObjectNotFoundException e) {
            throw new IOException("Signing Certificate not found");
        }
    }

    public static java.security.PrivateKey getPrivateKey(String tokenname, String nickname)
            throws Exception {

        X509Certificate cert = getCertificate(tokenname, nickname);

        return CryptoManager.getInstance().findPrivKeyByCert(cert);
    }

    /**
     * getCMCBlob create and return the enrollent request.
     * <P>
     * 
     * @param signerCert the certificate of the authorized signer of the CMC revocation request.
     * @param manager the crypto manger.
     * @param nValue the nickname of the certificate inside the token.
     * @param rValue request PKCS#10 file name.
     * @return the CMC revocation request encoded in base64
     */
    static String getCMCBlob(X509Certificate signerCert, CryptoManager manager, String nValue, String rValue) {

        String asciiBASE64Blob = rValue; // input pkcs10 blob
        String tokenname = "internal";

        try {

            java.security.PrivateKey privKey = null;
            PKCS10 pkcs = null;
            SignerIdentifier si = null;
            ContentInfo fullEnrollmentReq = null;

            try {
                byte[] decodedBytes = com.netscape.osutil.OSUtil.AtoB(asciiBASE64Blob);

                pkcs = new PKCS10(decodedBytes);
            } catch (IOException e) {
                throw new IOException("Internal Error - " + e.toString());
            } catch (SignatureException e) {
                throw new IOException("Internal Error - " + e.toString());
            } catch (NoSuchAlgorithmException e) {
                throw new IOException("Internal Error - " + e.toString());
            }

            BigInteger serialno = signerCert.getSerialNumber();
            byte[] certB = signerCert.getEncoded();
            X509CertImpl impl = new X509CertImpl(certB);
            X500Name issuerName = (X500Name) impl.getIssuerDN();
            byte[] issuerByte = issuerName.getEncoded();
            ByteArrayInputStream istream = new ByteArrayInputStream(issuerByte);

            Name issuer = (Name) Name.getTemplate().decode(istream);
            IssuerAndSerialNumber ias = new IssuerAndSerialNumber(issuer, new INTEGER(serialno.toString()));

            si = new SignerIdentifier(SignerIdentifier.ISSUER_AND_SERIALNUMBER, ias, null);
            privKey = getPrivateKey(tokenname, nValue);

            // create CMC req
            // transfer pkcs10 to jss class
            int bpid = 1;
            ByteArrayInputStream crInputStream = new ByteArrayInputStream(pkcs.toByteArray());
            CertificationRequest cr = (CertificationRequest) CertificationRequest.getTemplate().decode(crInputStream);

            TaggedCertificationRequest tcr = new
                    TaggedCertificationRequest(new
                            INTEGER(bpid++), cr);
            TaggedRequest trq = new
                    TaggedRequest(TaggedRequest.PKCS10, tcr,
                            null);

            SEQUENCE reqSequence = new SEQUENCE();

            reqSequence.addElement(trq);

            // Add some control sequence
            // Verisign has transactionID,senderNonce
            SEQUENCE controlSeq = new SEQUENCE();

            Date date = new Date();
            String salt = "lala123" + date.toString();
            byte[] dig;

            try {
                MessageDigest SHA1Digest = MessageDigest.getInstance("SHA1");

                dig = SHA1Digest.digest(salt.getBytes());
            } catch (NoSuchAlgorithmException ex) {
                dig = salt.getBytes();
            }

            String sn = com.netscape.osutil.OSUtil.BtoA(dig);

            TaggedAttribute senderNonce = new TaggedAttribute(new
                    INTEGER(bpid++),
                    OBJECT_IDENTIFIER.id_cmc_senderNonce,
                    new OCTET_STRING(sn.getBytes()));

            controlSeq.addElement(senderNonce);

            // Verisign recommend transactionId be MD5 hash of publicKey
            byte[] transId;

            try {
                MessageDigest MD5Digest = MessageDigest.getInstance("MD5");

                transId = MD5Digest.digest(pkcs.getSubjectPublicKeyInfo().getKey());
            } catch (Exception ex) {
                transId = salt.getBytes();
            }

            TaggedAttribute transactionId = new TaggedAttribute(new
                    INTEGER(bpid++),
                    OBJECT_IDENTIFIER.id_cmc_transactionId,
                    new INTEGER(1, transId));

            controlSeq.addElement(transactionId);

            PKIData pkidata = new PKIData(controlSeq, reqSequence, new SEQUENCE(), new SEQUENCE());

            EncapsulatedContentInfo ci = new
                    EncapsulatedContentInfo(OBJECT_IDENTIFIER.id_cct_PKIData,
                            pkidata);
            // SHA1 is the default digest Alg for now.
            DigestAlgorithm digestAlg = null;
            SignatureAlgorithm signAlg = SignatureAlgorithm.RSASignatureWithSHA1Digest;
            org.mozilla.jss.crypto.PrivateKey.Type signingKeyType =
                    ((org.mozilla.jss.crypto.PrivateKey) privKey).getType();

            if (signingKeyType.equals(org.mozilla.jss.crypto.PrivateKey.Type.DSA))
                signAlg = SignatureAlgorithm.DSASignatureWithSHA1Digest;
            MessageDigest SHADigest = null;
            byte[] digest = null;

            try {
                SHADigest = MessageDigest.getInstance("SHA1");
                digestAlg = DigestAlgorithm.SHA1;

                ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                pkidata.encode((OutputStream) ostream);
                digest = SHADigest.digest(ostream.toByteArray());
            } catch (NoSuchAlgorithmException e) {
            }
            SignerInfo signInfo = new
                    SignerInfo(si, null, null, OBJECT_IDENTIFIER.id_cct_PKIData, digest, signAlg,
                            (org.mozilla.jss.crypto.PrivateKey) privKey);
            SET signInfos = new SET();

            signInfos.addElement(signInfo);

            SET digestAlgs = new SET();

            if (digestAlg != null) {
                AlgorithmIdentifier ai = new AlgorithmIdentifier(digestAlg.toOID(), null);

                digestAlgs.addElement(ai);
            }

            org.mozilla.jss.crypto.X509Certificate[] agentChain = manager.buildCertificateChain(signerCert);
            SET certs = new SET();

            for (int i = 0; i < agentChain.length; i++) {
                ANY cert = new ANY(agentChain[i].getEncoded());

                certs.addElement(cert);
            }
            SignedData req = new SignedData(digestAlgs, ci, certs, null, signInfos);

            fullEnrollmentReq = new
                    ContentInfo(req);

            ByteArrayOutputStream bs = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(bs);

            // format is PR_REQUEST_CMC
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            fullEnrollmentReq.encode(os);
            ps.print(com.netscape.osutil.OSUtil.BtoA(os.toByteArray()));
            //fullEnrollmentReq.print(ps); // no header/trailer
            asciiBASE64Blob = bs.toString();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        return asciiBASE64Blob;
    }

    /** Creates a new instance of CMCEnroll */
    public static void main(String[] s) {

        String dValue = null, nValue = null, rValue = null, pValue = null;
        FileOutputStream outputBlob = null;

        // default path is "."
        String mPath = ".";
        // default prefix is ""
        String mPrefix = "";

        boolean bWrongParam = false;

        // (1) Check that two arguments were submitted to the program
        if (s.length != (ARGC * 2)) {
            System.out.println("Wrong number of parameters:" + s.length);
            System.out.println("Usage:  CMCEnroll " +
                    "-d <dir to cert8.db, key3.db> " +
                    "-n <nickname> " +
                    "-r <request PKCS#10 file name> " +
                    "-p <password>"
                    );
            bWrongParam = true;
        } else {
            int length;
            int i;

            length = s.length;
            for (i = 0; i < length; i++) {
                if (s[i].equals("-d")) {
                    dValue = s[i + 1];
                } else if (s[i].equals("-n")) {
                    nValue = s[i + 1];
                } else if (s[i].equals("-r")) {
                    rValue = s[i + 1];
                } else if (s[i].equals("-p")) {
                    pValue = s[i + 1];
                }
                if (s[i].equals(""))
                    bWrongParam = true;

            }

            if (dValue == null || nValue == null || rValue == null || pValue == null)
                bWrongParam = true;
            else if (dValue.length() == 0 || nValue.length() == 0 || rValue.length() == 0 ||
                    pValue.length() == 0)
                bWrongParam = true;
            if (bWrongParam == true) {
                System.out.println("Usage:  CMCEnroll " +
                        "-d <dir to cert8.db, key3.db> " +
                        "-n <nickname> " +
                        "-r <request PKCS#10 file name> " +
                        "-p <password>"
                        );
                System.exit(0);
            }

            try {
                // initialize CryptoManager
                mPath = dValue;
                System.out.println("cert/key prefix = " + mPrefix);
                System.out.println("path = " + mPath);
                CryptoManager.InitializationValues vals =
                        new CryptoManager.InitializationValues(mPath, mPrefix,
                                mPrefix, "secmod.db");

                CryptoManager.initialize(vals);

                CryptoManager cm = CryptoManager.getInstance();
                CryptoToken token = cm.getInternalKeyStorageToken();
                Password pass = new Password(pValue.toCharArray());

                token.login(pass);
                X509Certificate signerCert = null;

                signerCert = cm.findCertByNickname(nValue);

                BufferedReader inputBlob = null;

                try {
                    inputBlob = new BufferedReader(new InputStreamReader(
                                    new BufferedInputStream(
                                            new FileInputStream(
                                                    rValue))));
                } catch (FileNotFoundException e) {
                    System.out.println("CMCEnroll:  can''t find file " +
                            rValue + ":\n" + e);
                    return;
                } catch (Exception e) {
                    e.printStackTrace();
                    System.exit(1);
                }
                // (3) Read the entire contents of the specified BASE 64 encoded
                //     blob into a String() object throwing away any
                //     headers beginning with HEADER and any trailers beginning
                //     with TRAILER
                String asciiBASE64BlobChunk = new String();
                String asciiBASE64Blob = new String();

                try {
                    while ((asciiBASE64BlobChunk = inputBlob.readLine()) != null) {
                        if (!(asciiBASE64BlobChunk.startsWith(HEADER)) &&
                                !(asciiBASE64BlobChunk.startsWith(TRAILER))) {
                            asciiBASE64Blob += asciiBASE64BlobChunk.trim();
                        }
                    }
                } catch (IOException e) {
                    System.out.println("CMCEnroll:  Unexpected BASE64 " +
                            "encoded error encountered in readLine():\n" +
                            e);
                }
                // (4) Close the DataInputStream() object
                try {
                    inputBlob.close();
                } catch (IOException e) {
                    System.out.println("CMCEnroll():  Unexpected BASE64 " +
                            "encoded error encountered in close():\n" + e);
                }

                asciiBASE64Blob = getCMCBlob(signerCert, cm, nValue, asciiBASE64Blob);
                // (5) Decode the ASCII BASE 64 blob enclosed in the
                //     String() object into a BINARY BASE 64 byte[] object

                @SuppressWarnings("unused")
                byte binaryBASE64Blob[] =
                        com.netscape.osutil.OSUtil.AtoB(asciiBASE64Blob); // check for errors

                // (6) Finally, print the actual CMCEnroll blob to the
                //     specified output file
                try {
                    outputBlob = new FileOutputStream(rValue + ".out");
                } catch (IOException e) {
                    System.out.println("CMCEnroll:  unable to open file " +
                            rValue + ".out" + " for writing:\n" + e);
                    return;
                }

                System.out.println(HEADER);
                System.out.println(asciiBASE64Blob + TRAILER);
                try {
                    asciiBASE64Blob = HEADER + "\n" + asciiBASE64Blob + TRAILER;
                    outputBlob.write(asciiBASE64Blob.getBytes());
                } catch (IOException e) {
                    System.out.println("CMCEnroll:  I/O error " +
                            "encountered during write():\n" +
                            e);
                }

                try {
                    outputBlob.close();
                } catch (IOException e) {
                    System.out.println("CMCEnroll:  Unexpected error " +
                            "encountered while attempting to close() " +
                            "\n" + e);
                }

            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }

            return;
        }
    }
}
