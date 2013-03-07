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
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.StringTokenizer;

import netscape.security.pkcs.PKCS10;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.ENUMERATED;
import org.mozilla.jss.asn1.GeneralizedTime;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs10.CertificationRequest;
import org.mozilla.jss.pkix.cmc.CMCCertId;
import org.mozilla.jss.pkix.cmc.GetCert;
import org.mozilla.jss.pkix.cmc.LraPopWitness;
import org.mozilla.jss.pkix.cmc.OtherMsg;
import org.mozilla.jss.pkix.cmc.PKIData;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cmc.TaggedCertificationRequest;
import org.mozilla.jss.pkix.cmc.TaggedRequest;
import org.mozilla.jss.pkix.cmmf.RevRequest;
import org.mozilla.jss.pkix.cms.ContentInfo;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;
import org.mozilla.jss.pkix.cms.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cms.SignedData;
import org.mozilla.jss.pkix.cms.SignerIdentifier;
import org.mozilla.jss.pkix.cms.SignerInfo;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.util.HMACDigest;
import com.netscape.cmsutil.util.Utils;

/**
 * Tool for creating CMC full request
 *
 * <P>
 *
 * @version $Revision$, $Date$
 *
 */
public class CMCRequest {

    public static final String PR_REQUEST_CMC = "CMC";
    public static final String PR_REQUEST_CRMF = "CRMF";
    public static final String PR_INTERNAL_TOKEN_NAME = "internal";

    public static final int ARGC = 1;
    public static final String HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String TRAILER = "-----END NEW CERTIFICATE REQUEST-----";

    void cleanArgs(String[] s) {

    }

    public static X509Certificate getCertificate(String tokenName,
            String nickname) throws Exception {
        CryptoManager manager = CryptoManager.getInstance();
        CryptoToken token = null;

        if (tokenName.equals(PR_INTERNAL_TOKEN_NAME)) {
            token = manager.getInternalKeyStorageToken();
        } else {
            token = manager.getTokenByName(tokenName);
        }
        StringBuffer certname = new StringBuffer();

        if (!token.equals(manager.getInternalKeyStorageToken())) {
            certname.append(tokenName);
            certname.append(":");
        }
        certname.append(nickname);
        try {
            return manager.findCertByNickname(certname.toString());
        } catch (ObjectNotFoundException e) {
            throw new IOException("Signing Certificate not found");
        }
    }

    public static java.security.PrivateKey getPrivateKey(String tokenName, String nickname)
            throws Exception {

        X509Certificate cert = getCertificate(tokenName, nickname);
        if (cert != null)
            System.out.println("got signing cert");

        return CryptoManager.getInstance().findPrivKeyByCert(cert);
    }

    /**
     * getCMCBlob create and return the enrollment request.
     * <P>
     *
     * @param signerCert the certificate of the authorized signer of the CMC revocation request.
     * @param nickname the nickname of the certificate inside the token.
     * @param rValue CRMF/PKCS10 request.
     * @param format either crmf or pkcs10
     * @return the CMC enrollment request encoded in base64
     */
    static ContentInfo getCMCBlob(X509Certificate signerCert, String tokenName, String nickname,
            String[] rValue, String format, CryptoManager manager, String transactionMgtEnable,
            String transactionMgtId, String identityProofEnable, String identityProofSharedSecret,
            SEQUENCE controlSeq, SEQUENCE otherMsgSeq, int bpid) {

        System.out.println("in getCMCBlob");

        ContentInfo fullEnrollmentReq = null;
        try {
            java.security.PrivateKey privKey = null;
            SignerIdentifier si = null;

            BigInteger serialno = signerCert.getSerialNumber();
            byte[] certB = signerCert.getEncoded();
            X509CertImpl impl = new X509CertImpl(certB);
            X500Name issuerName = (X500Name) impl.getIssuerDN();
            byte[] issuerByte = issuerName.getEncoded();
            ByteArrayInputStream istream = new ByteArrayInputStream(issuerByte);

            Name issuer = (Name) Name.getTemplate().decode(istream);
            IssuerAndSerialNumber ias = new IssuerAndSerialNumber(
                    issuer, new INTEGER(serialno.toString()));

            si = new SignerIdentifier(
                    SignerIdentifier.ISSUER_AND_SERIALNUMBER, ias, null);
            privKey = getPrivateKey(tokenName, nickname);
            if (privKey != null)
                System.out.println("getCMCBlob: got privKey");

            TaggedRequest trq = null;
            PKCS10 pkcs = null;
            CertReqMsg certReqMsg = null;

            // create CMC req
            SEQUENCE reqSequence = new SEQUENCE();
            try {
                for (int k = 0; k < rValue.length; k++) {
                    System.out.println("k="+ k);
                    String asciiBASE64Blob = rValue[k];
                    byte[] decodedBytes = Utils.base64decode(asciiBASE64Blob);

                    if (format.equals("crmf")) {
                        System.out.println("getCMCBlob: format: crmf");
                        ByteArrayInputStream reqBlob =
                                new ByteArrayInputStream(decodedBytes);
                        SEQUENCE crmfMsgs = null;
                        try {
                            crmfMsgs = (SEQUENCE) new SEQUENCE.OF_Template(new
                                    CertReqMsg.Template()).decode(reqBlob);
                        } catch (InvalidBERException ee) {
                            System.out.println("getCMCBlob: This is not a crmf request. Or this request has an error.");
                            System.exit(1);
                        }
                        certReqMsg = (CertReqMsg) crmfMsgs.elementAt(0);
                        trq = new TaggedRequest(TaggedRequest.CRMF, null,
                                certReqMsg);
                    } else if (format.equals("pkcs10")) {
                        try {
                            pkcs = new PKCS10(decodedBytes, true);
                        } catch (Exception e2) {
                            System.out.println("getCMCBlob: Excception:"+e2.toString());
                            System.exit(1);
                        }
                        ByteArrayInputStream crInputStream = new ByteArrayInputStream(
                                pkcs.toByteArray());
                        CertificationRequest cr = (CertificationRequest)
                                CertificationRequest.getTemplate().decode(crInputStream);
                        TaggedCertificationRequest tcr = new TaggedCertificationRequest(
                                new INTEGER(bpid++), cr);
                        trq = new
                                TaggedRequest(TaggedRequest.PKCS10, tcr, null);
                    } else {
                        System.out.println("getCMCBlob: Unrecognized request format: " + format);
                        System.exit(1);
                    }
                    reqSequence.addElement(trq);
                }
            } catch (Exception e) {
                System.out.println("getCMCBlob: Exception:"+ e.toString());
                System.exit(1);
            }

            if (transactionMgtEnable.equals("true"))
                bpid = addTransactionAttr(bpid, controlSeq, transactionMgtId, format,
                        pkcs, certReqMsg);

            if (identityProofEnable.equals("true"))
                bpid = addIdentityProofAttr(bpid, controlSeq, reqSequence,
                        identityProofSharedSecret);

            PKIData pkidata = new PKIData(controlSeq, reqSequence, new SEQUENCE(), otherMsgSeq);

            EncapsulatedContentInfo ci = new
                    EncapsulatedContentInfo(OBJECT_IDENTIFIER.id_cct_PKIData, pkidata);
            // SHA1 is the default digest Alg for now.
            DigestAlgorithm digestAlg = null;
            SignatureAlgorithm signAlg = null;
            org.mozilla.jss.crypto.PrivateKey.Type signingKeyType = ((org.mozilla.jss.crypto.PrivateKey) privKey).getType();
            if (signingKeyType.equals(org.mozilla.jss.crypto.PrivateKey.Type.RSA)) {
                signAlg = SignatureAlgorithm.RSASignatureWithSHA1Digest;
            } else if (signingKeyType.equals(org.mozilla.jss.crypto.PrivateKey.Type.EC)) {
                signAlg = SignatureAlgorithm.ECSignatureWithSHA1Digest;
            } else if (signingKeyType.equals(org.mozilla.jss.crypto.PrivateKey.Type.DSA)) {
                signAlg = SignatureAlgorithm.DSASignatureWithSHA1Digest;
            }

            MessageDigest SHADigest = null;

            byte[] digest = null;
            try {
                SHADigest = MessageDigest.getInstance("SHA1");
                digestAlg = DigestAlgorithm.SHA1;

                ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                pkidata.encode(ostream);
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
            fullEnrollmentReq = new ContentInfo(req);
            ByteArrayOutputStream bs = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(bs);

            if (fullEnrollmentReq != null) {
                ByteArrayOutputStream os = new ByteArrayOutputStream();

                fullEnrollmentReq.encode(os);
                ps.print(Utils.base64encode(os.toByteArray()));
            }
            String asciiBASE64Blob = bs.toString();

            System.out.println("");
            System.out.println("The CMC enrollment request in base-64 encoded format:");
            System.out.println("");
            System.out.println(asciiBASE64Blob);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        return fullEnrollmentReq;
    }

    static void printUsage() {
        System.out.println("");
        System.out.println("Usage: CMCRequest <configuration file>");
        System.out.println("For example, CMCRequest CMCRequest.cfg");
        System.out.println("");
        System.out.println("The configuration file should look like as follows:");
        System.out.println("");
        System.out.println("#numRequests: Total number of PKCS10 requests or CRMF requests.");
        System.out.println("numRequests=1");
        System.out.println("");
        System.out.println("#input: full path for the PKCS10 request or CRMF request,");
        System.out.println("#the content must be in Base-64 encoded format");
        System.out.println("#Multiple files are supported. They must be separated by space.");
        System.out.println("input=crmf1");
        System.out.println("");
        System.out.println("#output: full path for the CMC request in binary format");
        System.out.println("output=/u/doc/cmcReq");
        System.out.println("");
        System.out.println("#tokenname: name of token where agent signing cert can be found (default is internal)");
        System.out.println("tokenname=internal");
        System.out.println("");
        System.out.println("#nickname: nickname for agent certificate which will be used");
        System.out.println("#to sign the CMC full request.");
        System.out.println("nickname=CMS Agent Certificate");
        System.out.println("");
        System.out.println("#dbdir: directory for cert8.db, key3.db and secmod.db");
        System.out.println("dbdir=/u/smith/.netscape");
        System.out.println("");
        System.out.println("#password: password for cert8.db which stores the agent");
        System.out.println("#certificate");
        System.out.println("password=pass");
        System.out.println("");
        System.out.println("#format: request format, either pkcs10 or crmf");
        System.out.println("format=crmf");
        System.out.println("");
        System.out.println("#confirmCertAcceptance.enable: if true, then the request will");
        System.out.println("#contain this control. Otherwise, false.");
        System.out.println("confirmCertAcceptance.enable=true");
        System.out.println("");
        System.out.println("#confirmCertAcceptance.serial: The serial number for");
        System.out.println("#confirmCertAcceptance control");
        System.out.println("confirmCertAcceptance.serial=3");
        System.out.println("");
        System.out.println("#confirmCertAcceptance.issuer: The issuer name for");
        System.out.println("#confirmCertAcceptance control");
        System.out.println("confirmCertAcceptance.issuer=cn=Certificate Manager,c=us");
        System.out.println("");
        System.out.println("#getCert.enable: if true, then the request will contain this");
        System.out.println("#control. Otherwise, false.");
        System.out.println("getCert.enable=true");
        System.out.println("");
        System.out.println("#getCert.serial: The serial number for getCert control");
        System.out.println("getCert.serial=3");
        System.out.println("");
        System.out.println("#getCert.issuer: The issuer name for getCert control");
        System.out.println("getCert.issuer=cn=Certificate Manager,c=us");
        System.out.println("");
        System.out.println("#dataReturn.enable: if true, then the request will contain");
        System.out.println("#this control. Otherwise, false.");
        System.out.println("dataReturn.enable=true");
        System.out.println("");
        System.out.println("#dataReturn.data: data contained in the control.");
        System.out.println("dataReturn.data=test");
        System.out.println("");
        System.out.println("#transactionMgt.enable: if true, then the request will contain");
        System.out.println("#this control. Otherwise, false.");
        System.out.println("transactionMgt.enable=true");
        System.out.println("");
        System.out.println("#transactionMgt.id: transaction identifier. Verisign recommend");
        System.out.println("#transactionId to be MD5 hash of publicKey.");
        System.out.println("transactionMgt.id=");
        System.out.println("");
        System.out.println("#senderNonce.enable: if true, then the request will contain this");
        System.out.println("#control. Otherwise, false.");
        System.out.println("senderNonce.enable=true");
        System.out.println("");
        System.out.println("#senderNonce.id: sender nonce");
        System.out.println("senderNonce.id=");
        System.out.println("");
        System.out.println("#revRequest.enable: if true, then the request will contain this");
        System.out.println("#control. Otherwise, false.");
        System.out.println("revRequest.enable=true");
        System.out.println("");
        System.out.println("#revRequest.nickname: The nickname for the revoke certificate");
        System.out.println("revRequest.nickname=newuser's 102504a ID");
        System.out.println("");
        System.out.println("#revRequest.issuer: The issuer name for the certificate being");
        System.out.println("#revoked.");
        System.out.println("revRequest.issuer=cn=Certificate Manager,c=us");
        System.out.println("");
        System.out.println("#revRequest.serial: The serial number for the certificate being");
        System.out.println("#revoked.");
        System.out.println("revRequest.serial=61");
        System.out.println("");
        System.out.println("#revRequest.reason: The reason for revoking this certificate: ");
        System.out.println("#                   unspecified, keyCompromise, caCompromise,");
        System.out.println("#                   affiliationChanged, superseded, cessationOfOperation,");
        System.out.println("#                   certificateHold, removeFromCRL");
        System.out.println("revRequest.reason=unspecified");
        System.out.println("");
        System.out.println("#revRequest.sharedSecret: The sharedSecret");
        System.out.println("revRequest.sharedSecret=");
        System.out.println("");
        System.out.println("#revRequest.comment: The human readable comment");
        System.out.println("revRequest.comment=");
        System.out.println("");
        System.out.println("#revRequest.invalidityDatePresent: if true, the current time will be the");
        System.out.println("#                                  invalidityDate. If false, no invalidityDate");
        System.out.println("#                                  is present.");
        System.out.println("revRequest.invalidityDatePresent=false");
        System.out.println("");
        System.out.println("#identityProof.enable: if true, then the request will contain");
        System.out.println("#this control. Otherwise, false.");
        System.out.println("identityProof.enable=true");
        System.out.println("");
        System.out.println("#identityProof.sharedSecret: Shared Secret");
        System.out.println("identityProof.sharedSecret=testing");
        System.out.println("");
        System.out.println("#popLinkWitness.enable:  if true, then the request will contain");
        System.out.println("#this control. Otherwise, false.");
        System.out.println("#If you want to test this control, make sure to use CRMFPopClient ");
        System.out.println("# to generate the CRMF request which will include the ");
        System.out.println("#idPOPLinkWitness attribute in the controls section of the ");
        System.out.println("#CertRequest structure.");
        System.out.println("popLinkWitness.enable=false");
        System.out.println("");
        System.out.println("#LraPopWitness.enable: if true, then the request will contain this");
        System.out.println("#control. Otherwise, false.");
        System.out.println("LraPopWitness.enable=true");
        System.out.println("");
        System.out.println("#LraPopWitness.bodyPartIDs: List of body part IDs");
        System.out.println("#Each id is separated by space.");
        System.out.println("LraPopWitness.bodyPartIDs=1");
        System.exit(1);
    }

    private static int addLraPopWitnessAttr(int bpid, SEQUENCE seq, String bodyPartIDs) {
        StringTokenizer tokenizer = new StringTokenizer(bodyPartIDs, " ");
        SEQUENCE bodyList = new SEQUENCE();
        while (tokenizer.hasMoreTokens()) {
            String s = tokenizer.nextToken();
            bodyList.addElement(new INTEGER(s));
        }
        LraPopWitness lra = new LraPopWitness(new INTEGER(0), bodyList);
        TaggedAttribute cont = new TaggedAttribute(new
                INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_lraPOPWitness, lra);
        System.out.println("Successfully create LRA POP witness control. bpid = " + (bpid - 1));
        System.out.println("");
        seq.addElement(cont);
        return bpid;
    }

    private static int addConfirmCertAttr(int bpid, SEQUENCE seq, String confirmCertIssuer,
            String confirmCertSerial) {
        try {
            INTEGER serial = new INTEGER(confirmCertSerial);
            X500Name issuername = new X500Name(confirmCertIssuer);
            byte[] issuerbyte = issuername.getEncoded();
            ANY issuern = new ANY(issuerbyte);
            CMCCertId cmcCertId = new CMCCertId(issuern, serial, null);
            TaggedAttribute cmcCertIdControl = new TaggedAttribute(new
                    INTEGER(bpid++),
                    OBJECT_IDENTIFIER.id_cmc_idConfirmCertAcceptance, cmcCertId);
            System.out.println("Successfully create confirm certificate acceptance control. bpid = " + (bpid - 1));
            System.out.println("");
            seq.addElement(cmcCertIdControl);
        } catch (Exception e) {
            System.out.println("Error in creating confirm certificate acceptance control. Check the parameters.");
            System.exit(1);
        }
        return bpid;
    }

    private static ENUMERATED toCRLReason(String str) {
        if (str.equalsIgnoreCase("unspecified")) {
            return RevRequest.unspecified;
        } else if (str.equalsIgnoreCase("keyCompromise")) {
            return RevRequest.keyCompromise;
        } else if (str.equalsIgnoreCase("caCompromise")) {
            return RevRequest.cACompromise;
        } else if (str.equalsIgnoreCase("affiliationChanged")) {
            return RevRequest.affiliationChanged;
        } else if (str.equalsIgnoreCase("superseded")) {
            return RevRequest.superseded;
        } else if (str.equalsIgnoreCase("cessationOfOperation")) {
            return RevRequest.cessationOfOperation;
        } else if (str.equalsIgnoreCase("certificateHold")) {
            return RevRequest.certificateHold;
        } else if (str.equalsIgnoreCase("removeFromCRL")) {
            return RevRequest.removeFromCRL;
        }

        System.out.println("Unrecognized CRL reason");
        System.exit(1);

        return RevRequest.unspecified;
    }

    private static int addIdentityProofAttr(int bpid, SEQUENCE seq, SEQUENCE reqSequence,
            String sharedSecret) {
        byte[] b = ASN1Util.encode(reqSequence);
        byte[] key = null;
        byte[] finalDigest = null;
        try {
            MessageDigest SHA1Digest = MessageDigest.getInstance("SHA1");
            key = SHA1Digest.digest(sharedSecret.getBytes());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("CMCRequest::addIdentityProofAttr() - "
                              + "No such algorithm!");
            return -1;
        }

        try {
            MessageDigest SHA1Digest = MessageDigest.getInstance("SHA1");
            HMACDigest hmacDigest = new HMACDigest(SHA1Digest, key);
            hmacDigest.update(b);
            finalDigest = hmacDigest.digest();
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("CMCRequest::addIdentityProofAttr() - "
                    + "No such algorithm!");
            return -1;
        }

        TaggedAttribute identityProof = new TaggedAttribute(new
                INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_identityProof,
                new OCTET_STRING(finalDigest));
        seq.addElement(identityProof);
        System.out.println("Identity Proof control: ");
        System.out.print("   Value: ");
        for (int i = 0; i < finalDigest.length; i++) {
            System.out.print(finalDigest[i] + " ");
        }
        System.out.println("");
        System.out.println("Successfully create identityProof control. bpid = " + (bpid - 1));
        System.out.println("");
        return bpid;
    }

    private static int addRevRequestAttr(int bpid, SEQUENCE seq, SEQUENCE otherMsgSeq, CryptoToken token, String tokenName, String nickname,
            String revRequestIssuer, String revRequestSerial, String revRequestReason,
            String revRequestSharedSecret, String revRequestComment, String invalidityDatePresent,
            CryptoManager manager) {
        try {
            if (nickname.length() <= 0) {
                System.out.println("The nickname for the certificate being revoked is null");
                System.exit(1);
            }
            String nickname1 = nickname;
            UTF8String comment = null;
            OCTET_STRING sharedSecret = null;
            GeneralizedTime d = null;
            X500Name subjectname = new X500Name(revRequestIssuer);
            INTEGER snumber = new INTEGER(revRequestSerial);
            ENUMERATED reason = toCRLReason(revRequestReason);
            if (revRequestSharedSecret.length() > 0)
                sharedSecret = new OCTET_STRING(revRequestSharedSecret.getBytes());
            if (revRequestComment.length() > 0)
                comment = new UTF8String(revRequestComment);
            if (invalidityDatePresent.equals("true"))
                d = new GeneralizedTime(new Date());
            RevRequest revRequest =
                    new RevRequest(new ANY(subjectname.getEncoded()), snumber,
                            reason, d, sharedSecret, comment);
            int revokeBpid = bpid;
            TaggedAttribute revRequestControl = new TaggedAttribute(
                    new INTEGER(bpid++),
                    OBJECT_IDENTIFIER.id_cmc_revokeRequest, revRequest);
            seq.addElement(revRequestControl);

            if (sharedSecret != null) {
                System.out.println("Successfully create revRequest control. bpid = " + (bpid - 1));
                System.out.println("");
                return bpid;
            }

            EncapsulatedContentInfo revokeContent = new EncapsulatedContentInfo(
                    OBJECT_IDENTIFIER.id_cct_PKIData, revRequestControl);

            StringBuffer certname = new StringBuffer();

            if (!token.equals(manager.getInternalKeyStorageToken())) {
                certname.append(tokenName);
                certname.append(":");
            }
            certname.append(nickname);
            java.security.PrivateKey revokePrivKey = null;
            X509Certificate revokeCert = null;
            System.out.println("finding cert:"+certname.toString());
            try {
                revokeCert = manager.findCertByNickname(certname.toString());
            } catch (ObjectNotFoundException e) {
                System.out.println("Certificate not found: "+nickname1);
                System.exit(1);
            } catch (Exception e2) {
                System.out.println("Certificate not found: "+e2.toString());
                System.exit(1);
            }
            System.out.println("finding private key for cert:"+certname.toString());
            revokePrivKey = manager.findPrivKeyByCert(revokeCert);
            org.mozilla.jss.crypto.PrivateKey.Type signingKeyType1 =
              ((org.mozilla.jss.crypto.PrivateKey) revokePrivKey).getType();
            SignatureAlgorithm signAlg1 = null;
            if (signingKeyType1.equals(org.mozilla.jss.crypto.PrivateKey.Type.RSA)) {
                signAlg1 = SignatureAlgorithm.RSASignatureWithSHA1Digest;
            } else if (signingKeyType1.equals(org.mozilla.jss.crypto.PrivateKey.Type.EC)) {
                signAlg1 = SignatureAlgorithm.ECSignatureWithSHA1Digest;
            } else if (signingKeyType1.equals(org.mozilla.jss.crypto.PrivateKey.Type.DSA)) {
                signAlg1 = SignatureAlgorithm.DSASignatureWithSHA1Digest;
            }

            MessageDigest rSHADigest = null;
            byte[] rdigest = null;
            DigestAlgorithm digestAlg1 = null;
            try {
                rSHADigest = MessageDigest.getInstance("SHA1");
                digestAlg1 = DigestAlgorithm.SHA1;

                ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                revRequestControl.encode(ostream);
                rdigest = rSHADigest.digest(ostream.toByteArray());
            } catch (NoSuchAlgorithmException e) {
            }

            ByteArrayInputStream bistream =
                    new ByteArrayInputStream(subjectname.getEncoded());
            Name iname = (Name) Name.getTemplate().decode(bistream);
            IssuerAndSerialNumber ias1 = new IssuerAndSerialNumber(iname, snumber);

            SignerIdentifier rsi = new SignerIdentifier(
                    SignerIdentifier.ISSUER_AND_SERIALNUMBER, ias1, null);

            SignerInfo signInfo1 = new SignerInfo(rsi, null, null,
                    OBJECT_IDENTIFIER.id_cct_PKIData, rdigest, signAlg1,
                    (org.mozilla.jss.crypto.PrivateKey) revokePrivKey);

            SET signInfos1 = new SET();
            signInfos1.addElement(signInfo1);
            SET digestAlgs1 = new SET();
            if (digestAlg1 != null) {
                AlgorithmIdentifier ai1 = new AlgorithmIdentifier(digestAlg1.toOID(), null);
                digestAlgs1.addElement(ai1);
            }

            org.mozilla.jss.crypto.X509Certificate[] revokeCertChain =
                    manager.buildCertificateChain(revokeCert);
            SET certs1 = new SET();
            for (int i = 0; i < revokeCertChain.length; i++) {
                ANY cert1 = new ANY(revokeCertChain[i].getEncoded());
                certs1.addElement(cert1);
            }

            SignedData sData = new SignedData(digestAlgs1, revokeContent, certs1, null, signInfos1);
            OBJECT_IDENTIFIER signedDataOID = new OBJECT_IDENTIFIER("1.2.840.113549.1.7.2");
            ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
            sData.encode(bos1);
            OtherMsg otherMsg = new OtherMsg(new INTEGER(revokeBpid), signedDataOID, new ANY(bos1.toByteArray()));
            otherMsgSeq.addElement(otherMsg);
            System.out.println("Successfully create revRequest control. bpid = " + (bpid - 1));
            System.out.println("");
        } catch (Exception e) {
            System.out.println("Error in creating revRequest control. Check the parameters. Exception="+ e.toString());
            System.exit(1);
        }

        return bpid;
    }

    private static int addGetCertAttr(int bpid, SEQUENCE seq, String issuer, String serial) {
        try {
            INTEGER serialno = new INTEGER(serial);
            X500Name issuername = new X500Name(issuer);
            byte[] issuerbyte = issuername.getEncoded();
            ANY issuern = new ANY(issuerbyte);
            GetCert getCert = new GetCert(issuern, serialno);
            TaggedAttribute getCertControl = new TaggedAttribute(new
                    INTEGER(bpid++),
                    OBJECT_IDENTIFIER.id_cmc_getCert, getCert);
            System.out.println("Successfully create get certificate control. bpid = " + (bpid - 1));
            System.out.println("");
            seq.addElement(getCertControl);
        } catch (Exception e) {
            System.out.println("Error in creating get certificate control. Check the parameters.");
            System.exit(1);
        }

        return bpid;
    }

    private static int addDataReturnAttr(int bpid, SEQUENCE seq, String str) {
        try {
            byte bvalue[] = str.getBytes();
            System.out.println("Data Return Control: ");
            StringBuffer ss = new StringBuffer("   Value: ");
            for (int m = 0; m < bvalue.length; m++) {
                ss.append(bvalue[m] + " ");
            }
            System.out.println(ss.toString());
            OCTET_STRING s = new OCTET_STRING(bvalue);
            TaggedAttribute dataReturnControl = new TaggedAttribute(new
                    INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_dataReturn, s);
            seq.addElement(dataReturnControl);
            System.out.println("Successfully create data return control. bpid = " + (bpid - 1));
            System.out.println("");
        } catch (Exception e) {
            System.out.println("Error in creating data return control. Check the parameters.");
            System.exit(1);
        }

        return bpid;
    }

    private static int addTransactionAttr(int bpid, SEQUENCE seq, String id, String format,
            PKCS10 pkcs, CertReqMsg certReqMsg) {
        byte[] transId = null;
        Date date = new Date();
        String salt = "lala123" + date.toString();
        if (id == null || id.equals("")) {
            try {
                MessageDigest MD5Digest = MessageDigest.getInstance("MD5");
                if (format.equals("crmf")) {
                    CertRequest certreq = certReqMsg.getCertReq();
                    CertTemplate certTemplate = certreq.getCertTemplate();
                    SubjectPublicKeyInfo pkinfo = certTemplate.getPublicKey();
                    BIT_STRING bitString = pkinfo.getSubjectPublicKey();
                    byte[] b = bitString.getBits();
                    transId = MD5Digest.digest(b);
                } else if (format.equals("pkcs10")) {
                    transId = MD5Digest.digest(pkcs.getSubjectPublicKeyInfo().getKey());
                }
            } catch (Exception ex) {
                transId = salt.getBytes();
            }
        } else {
            transId = id.getBytes();
        }

        if (transId == null) {
            System.out.println("CMCRequest::addTransactionAttr() - "
                              + "transId is null!");
            return -1;
        }

        INTEGER ii = new INTEGER(1, transId);
        TaggedAttribute transactionId = new TaggedAttribute(new
                INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_transactionId, ii);
        System.out.println("Transaction ID control: ");
        System.out.println("   Value: " + ii.toString());
        System.out.println("Successfully create transaction management control. bpid = " + (bpid - 1));
        System.out.println("");

        seq.addElement(transactionId);

        return bpid;
    }

    private static int addSenderNonceAttr(int bpid, SEQUENCE seq, String nonce) {
        byte[] dig;
        String sn = nonce;
        if (nonce == null || nonce.equals("")) {
            // Verisign has transactionID,senderNonce
            Date date = new Date();
            String salt = "lala123" + date.toString();

            try {
                MessageDigest SHA1Digest = MessageDigest.getInstance("SHA1");

                dig = SHA1Digest.digest(salt.getBytes());
            } catch (NoSuchAlgorithmException ex) {
                dig = salt.getBytes();
            }

            sn = Utils.base64encode(dig);
        }
        byte bb[] = sn.getBytes();
        System.out.println("SenderNonce control: ");

        StringBuffer ss = new StringBuffer("   Value: ");

        for (int m = 0; m < bb.length; m++) {
            ss.append(bb[m] + " ");
        }
        System.out.println(ss.toString());
        TaggedAttribute senderNonce = new TaggedAttribute(new
                INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_senderNonce,
                new OCTET_STRING(sn.getBytes()));
        System.out.println("Successfully create sender nonce control. bpid = " + (bpid - 1));
        System.out.println("");
        seq.addElement(senderNonce);
        return bpid;
    }

    private static int addPopLinkWitnessAttr(int bpid, SEQUENCE controlSeq) {
        byte[] seed =
        { 0x10, 0x53, 0x42, 0x24, 0x1a, 0x2a, 0x35, 0x3c,
                0x7a, 0x52, 0x54, 0x56, 0x71, 0x65, 0x66, 0x4c,
                0x51, 0x34, 0x35, 0x23, 0x3c, 0x42, 0x43, 0x45,
                0x61, 0x4f, 0x6e, 0x43, 0x1e, 0x2a, 0x2b, 0x31,
                0x32, 0x34, 0x35, 0x36, 0x55, 0x51, 0x48, 0x14,
                0x16, 0x29, 0x41, 0x42, 0x43, 0x7b, 0x63, 0x44,
                0x6a, 0x12, 0x6b, 0x3c, 0x4c, 0x3f, 0x00, 0x14,
                0x51, 0x61, 0x15, 0x22, 0x23, 0x5f, 0x5e, 0x69 };

        TaggedAttribute idPOPLinkRandom = new TaggedAttribute(new
                INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_idPOPLinkRandom,
                new OCTET_STRING(seed));
        controlSeq.addElement(idPOPLinkRandom);
        System.out.println("Successfully create PopLinkWitness control. bpid = " + (bpid - 1));
        System.out.println("");
        return bpid;
    }

    public static void main(String[] s) {
        String numRequests = null;
        String dbdir = null, nickname = null;
        String tokenName = PR_INTERNAL_TOKEN_NAME;
        String ifilename = null, ofilename = null, password = null, format = null;
        String confirmCertEnable = "false", confirmCertIssuer = null, confirmCertSerial = null;
        String getCertEnable = "false", getCertIssuer = null, getCertSerial = null;
        String dataReturnEnable = "false", dataReturnData = null;
        String transactionMgtEnable = "false", transactionMgtId = null;
        String senderNonceEnable = "false", senderNonce = null;
        String revCertNickname = "";
        String revRequestEnable = "false", revRequestIssuer = null, revRequestSerial = null;
        String revRequestReason = null, revRequestSharedSecret = null, revRequestComment = null;
        String revRequestInvalidityDatePresent = "false";
        String identityProofEnable = "false", identityProofSharedSecret = null;
        String popLinkWitnessEnable = "false";
        String bodyPartIDs = null, lraPopWitnessEnable = "false";

        System.out.println("");

        // Check that the correct # of arguments were submitted to the program
        if (s.length != (ARGC)) {
            System.out.println("Wrong number of parameters:" + s.length);
            printUsage();
        }

        String configFile = s[0];
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(
                            new BufferedInputStream(
                                    new FileInputStream(
                                            configFile))));
        } catch (FileNotFoundException e) {
            System.out.println("CMCRequest:  can't find configuration file: " + configFile);
            printUsage();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        try {
            String str = "";
            while ((str = reader.readLine()) != null) {
                str = str.trim();
                if (!str.startsWith("#") && str.length() > 0) {
                    int index = str.indexOf("=");
                    String name = "";
                    String val = "";
                    if (index == -1) {
                        System.out.println("Error in configuration file: " + str);
                        System.exit(1);
                    }
                    name = str.substring(0, index);
                    if (index != str.length() - 1)
                        val = str.substring(index + 1);

                    if (name.equals("format")) {
                        format = val;
                    } else if (name.equals("dbdir")) {
                        dbdir = val;
                    } else if (name.equals("tokenname")) {
                        tokenName = val;
                    } else if (name.equals("nickname")) {
                        nickname = val;
                    } else if (name.equals("password")) {
                        password = val;
                    } else if (name.equals("output")) {
                        ofilename = val;
                    } else if (name.equals("input")) {
                        ifilename = val;
                    } else if (name.equals("confirmCertAcceptance.serial")) {
                        confirmCertSerial = val;
                    } else if (name.equals("confirmCertAcceptance.issuer")) {
                        confirmCertIssuer = val;
                    } else if (name.equals("confirmCertAcceptance.enable")) {
                        confirmCertEnable = val;
                    } else if (name.equals("getCert.enable")) {
                        getCertEnable = val;
                    } else if (name.equals("getCert.issuer")) {
                        getCertIssuer = val;
                    } else if (name.equals("getCert.serial")) {
                        getCertSerial = val;
                    } else if (name.equals("dataReturn.enable")) {
                        dataReturnEnable = val;
                    } else if (name.equals("dataReturn.data")) {
                        dataReturnData = val;
                    } else if (name.equals("transactionMgt.enable")) {
                        transactionMgtEnable = val;
                    } else if (name.equals("transactionMgt.id")) {
                        transactionMgtId = val;
                    } else if (name.equals("senderNonce.enable")) {
                        senderNonceEnable = val;
                    } else if (name.equals("senderNonce")) {
                        senderNonce = val;
                    } else if (name.equals("revRequest.enable")) {
                        revRequestEnable = val;
                    } else if (name.equals("revRequest.issuer")) {
                        revRequestIssuer = val;
                    } else if (name.equals("revRequest.serial")) {
                        revRequestSerial = val;
                    } else if (name.equals("revRequest.reason")) {
                        revRequestReason = val;
                    } else if (name.equals("revRequest.sharedSecret")) {
                        revRequestSharedSecret = val;
                    } else if (name.equals("revRequest.comment")) {
                        revRequestComment = val;
                    } else if (name.equals("revRequest.invalidityDatePresent")) {
                        revRequestInvalidityDatePresent = val;
                    } else if (name.equals("revRequest.nickname")) {
                        revCertNickname = val;
                    } else if (name.equals("identityProof.enable")) {
                        identityProofEnable = val;
                    } else if (name.equals("identityProof.sharedSecret")) {
                        identityProofSharedSecret = val;
                    } else if (name.equals("popLinkWitness.enable")) {
                        popLinkWitnessEnable = val;
                    } else if (name.equals("LraPopWitness.enable")) {
                        lraPopWitnessEnable = val;
                    } else if (name.equals("LraPopWitness.bodyPartIDs")) {
                        bodyPartIDs = val;
                    } else if (name.equals("numRequests")) {
                        numRequests = val;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            printUsage();
        }

        if (ifilename == null) {
            System.out.println("Missing input filename for PKCS10 or CRMF.");
            printUsage();
        }

        int num = 0;
        if (numRequests == null) {
            System.out.println("Missing numRequests.");
            printUsage();
        } else {
            try {
                num = Integer.parseInt(numRequests);
            } catch (Exception ee) {
                System.out.println("numRequests must be integer");
                System.exit(1);
            }
        }

        StringTokenizer tokenizer = new StringTokenizer(ifilename, " ");
        String[] ifiles = new String[num];
        for (int i = 0; i < num; i++) {
            String ss = tokenizer.nextToken();
            ifiles[i] = ss;
            if (ss == null) {
                System.out.println("Missing input file for the request.");
                System.exit(1);
            }
        }

        if (ofilename == null) {
            System.out.println("Missing output filename for the CMC request.");
            printUsage();
        }

        if (format == null) {
            System.out.println("Missing format.");
            printUsage();
        }

        if (password == null) {
            System.out.println("Missing password.");
            printUsage();
        }

        if (nickname == null) {
            System.out.println("Missing nickname.");
            printUsage();
        }

        try {
            // initialize CryptoManager
            if (dbdir == null)
                dbdir = ".";
            String mPrefix = "";
            System.out.println("cert/key prefix = " + mPrefix);
            System.out.println("path = " + dbdir);
/*
            CryptoManager.InitializationValues vals =
                    new CryptoManager.InitializationValues(dbdir, mPrefix,
                            mPrefix, "secmod.db");
*/
            CryptoManager.initialize(dbdir);
            CryptoToken token = null;
            CryptoManager cm = CryptoManager.getInstance();
            System.out.println("CryptoManger initialized");

            if ((tokenName == null) || (tokenName.equals(""))) {
                token = cm.getInternalKeyStorageToken();
                tokenName = PR_INTERNAL_TOKEN_NAME;
            } else {
                token = cm.getTokenByName(tokenName);
            }
            cm.setThreadToken(token);

            Password pass = new Password(password.toCharArray());

            try {
                token.login(pass);
                System.out.println("token "+ tokenName + " logged in...");
            } catch (Exception e) {
                System.out.println("login Exception: " + e.toString());
                System.exit(1);
            }

            X509Certificate signerCert = null;

            StringBuffer certname = new StringBuffer();
            if (!token.equals(cm.getInternalKeyStorageToken())) {
                certname.append(tokenName);
                certname.append(":");
            }
            certname.append(nickname);
            signerCert = cm.findCertByNickname(certname.toString());
            if (signerCert != null) {
                System.out.println("got signerCert: "+ certname.toString());
            }

            String[] requests = new String[num];
            for (int i = 0; i < num; i++) {
                BufferedReader inputBlob = null;
                try {
                    inputBlob = new BufferedReader(new InputStreamReader(
                            new BufferedInputStream(new FileInputStream(ifiles[i]))));
                } catch (FileNotFoundException e) {
                    System.out.println("CMCRequest:  can't find file " +
                            ifiles[i] + ":\n" + e);
                } catch (Exception e) {
                    e.printStackTrace();
                    System.exit(1);
                }
                // (3) Read the entire contents of the specified BASE 64 encoded
                //     blob into a String() object throwing away any
                //     headers beginning with HEADER and any trailers beginning
                //     with TRAILER
                String asciiBASE64BlobChunk = "";
                StringBuffer asciiBASE64Blob = new StringBuffer();

                try {
                    while ((asciiBASE64BlobChunk = inputBlob.readLine()) != null) {
                        if (!(asciiBASE64BlobChunk.startsWith(HEADER)) &&
                                !(asciiBASE64BlobChunk.startsWith(TRAILER))) {
                            asciiBASE64Blob.append(asciiBASE64BlobChunk.trim());
                        }
                    }
                    requests[i] = asciiBASE64Blob.toString();
                } catch (IOException e) {
                    System.out.println("CMCRequest:  Unexpected BASE64 " +
                            "encoded error encountered in readLine():\n" +
                            e);
                }
                // (4) Close the DataInputStream() object
                try {
                    inputBlob.close();
                } catch (IOException e) {
                    System.out.println("CMCRequest():  Unexpected BASE64 " +
                            "encoded error encountered in close():\n" + e);
                }
            }

            SEQUENCE controlSeq = new SEQUENCE();
            int bpid = 1;
            if (confirmCertEnable.equalsIgnoreCase("true")) {
                if (confirmCertIssuer.length() == 0 || confirmCertSerial.length() == 0) {
                    System.out.println("Illegal parameters for confirm certificate acceptance control");
                    printUsage();
                    System.exit(1);
                }
                bpid = addConfirmCertAttr(bpid, controlSeq, confirmCertIssuer, confirmCertSerial);
            }

            if (lraPopWitnessEnable.equalsIgnoreCase("true")) {
                if (bodyPartIDs.length() == 0) {
                    System.out.println("Illegal parameters for Lra Pop Witness control");
                    printUsage();
                    System.exit(1);
                }

                bpid = addLraPopWitnessAttr(bpid, controlSeq, bodyPartIDs);
            }

            if (getCertEnable.equalsIgnoreCase("true")) {
                if (getCertIssuer.length() == 0 || getCertSerial.length() == 0) {
                    System.out.println("Illegal parameters for get certificate control");
                    printUsage();
                    System.exit(1);
                }

                bpid = addGetCertAttr(bpid, controlSeq, getCertIssuer, getCertSerial);
            }

            if (dataReturnEnable.equalsIgnoreCase("true")) {
                if (dataReturnData.length() == 0) {
                    System.out.println("Illegal parameters for data return control");
                    printUsage();
                    System.exit(1);
                }

                bpid = addDataReturnAttr(bpid, controlSeq, dataReturnData);
            }

            if (senderNonceEnable.equalsIgnoreCase("true"))
                bpid = addSenderNonceAttr(bpid, controlSeq, senderNonce);

            if (popLinkWitnessEnable.equalsIgnoreCase("true"))
                bpid = addPopLinkWitnessAttr(bpid, controlSeq);

            SEQUENCE otherMsgSeq = new SEQUENCE();
            if (revRequestEnable.equalsIgnoreCase("true")) {
                if (revRequestIssuer.length() == 0 || revRequestSerial.length() == 0 ||
                        revRequestReason.length() == 0) {
                    System.out.println("Illegal parameters for revRequest control");
                    printUsage();
                    System.exit(1);
                }

                bpid = addRevRequestAttr(bpid, controlSeq, otherMsgSeq, token, tokenName, revCertNickname,
                        revRequestIssuer, revRequestSerial, revRequestReason, revRequestSharedSecret,
                        revRequestComment, revRequestInvalidityDatePresent, cm);
            }

            ContentInfo cmcblob = getCMCBlob(signerCert, tokenName, nickname, requests, format,
                    cm, transactionMgtEnable, transactionMgtId, identityProofEnable,
                    identityProofSharedSecret, controlSeq, otherMsgSeq, bpid);

            // (6) Finally, print the actual CMC blob to the
            //     specified output file
            FileOutputStream os = null;
            try {
                os = new FileOutputStream(ofilename);
                cmcblob.encode(os);
                System.out.println("");
                System.out.println("");
                System.out.println("The CMC enrollment request in binary format is stored in " +
                        ofilename + ".");
            } catch (IOException e) {
                System.out.println("CMCRequest:  unable to open file " + ofilename +
                        " for writing:\n" + e);
            }

            try {
                os.close();
            } catch (IOException e) {
                System.out.println("CMCRequest:  Unexpected error " +
                        "encountered while attempting to close() " +
                        "\n" + e);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
