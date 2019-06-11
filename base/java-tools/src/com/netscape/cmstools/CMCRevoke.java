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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ENUMERATED;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkix.cmc.PKIData;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cms.ContentInfo;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;
import org.mozilla.jss.pkix.cms.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cms.SignedData;
import org.mozilla.jss.pkix.cms.SignerIdentifier;
import org.mozilla.jss.pkix.cms.SignerInfo;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;

import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

/**
 * Tool for signing a CMC revocation request with an agent's certificate.
 *
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class CMCRevoke {
    public static final int ARGC = 8;

    static String dValue = null, nValue = null, iValue = null, sValue = null, mValue = null, hValue = null,
            pValue = null, cValue = null;
    static String tValue = null;

    public static final String CMS_BASE_CA_SIGNINGCERT_NOT_FOUND = "CA signing certificate not found";
    public static final String PR_REQUEST_CMC = "CMC";

    static String cleanArgs(String s) {
        if (s.startsWith("\"") && s.endsWith("\""))
            return s.substring(1, s.length() - 2);
        else if (s.startsWith("\'") && s.endsWith("\'"))
            return s.substring(1, s.length() - 2);
        else
            return s;
    }

    /**
     * Creates a new instance of CMCRevoke.
     */
    public static void main(String[] s) {

        // default path is "."
        String mPath = ".";
        // default prefix is ""
        String mPrefix = "";

        boolean bWrongParam = false;

        // (1) Check that two arguments were submitted to the program
        if (s.length != (ARGC) && s.length != (ARGC - 1)) {

            bWrongParam = true;
            System.out.println("Wrong number of parameters:" + s.length);
            System.out.println("Usage:  CMCRevoke " +
                    "-d<dir to NSS database> " +
                    "-n<nickname> " +
                    "-i<issuerName> " +
                    "-s<serialNumber> " +
                    "-m<reason to revoke> " +
                    "-t<shared secret> " +
                    "-p<password to db> " +
                    "-h<tokenname> " +
                    "-c<comment> ");
            System.out.println("\nNOTE: You can alternatively use CMCRequest instead for better usability.");
            for (int i = 0; i < s.length; i++) {
                System.out.println(i + ":" + s[i]);
            }
        } else {
            int length;
            int i;

            length = s.length;
            for (i = 0; i < length; i++) {
                if (s[i].startsWith("-d")) {
                    dValue = cleanArgs(s[i].substring(2));
                } else if (s[i].startsWith("-n")) {
                    nValue = cleanArgs(s[i].substring(2));
                } else if (s[i].startsWith("-i")) {
                    iValue = cleanArgs(s[i].substring(2));
                } else if (s[i].startsWith("-s")) {
                    sValue = cleanArgs(s[i].substring(2));
                } else if (s[i].startsWith("-m")) {
                    mValue = cleanArgs(s[i].substring(2));
                } else if (s[i].startsWith("-p")) {
                    pValue = cleanArgs(s[i].substring(2));
                } else if (s[i].startsWith("-t")) {
                    tValue = cleanArgs(s[i].substring(2));
                } else if (s[i].startsWith("-h")) {
                    hValue = cleanArgs(s[i].substring(2));
                } else if (s[i].startsWith("-c")) {
                    cValue = cleanArgs(s[i].substring(2));
                }

            }
            // optional parameters
            if (hValue == null)
                hValue = "";

            if (dValue == null
                    || nValue == null || iValue == null || sValue == null || mValue == null || pValue == null)
                bWrongParam = true;
            else if (dValue.length() == 0 || nValue.length() == 0 || iValue.length() == 0 ||
                    sValue.length() == 0 || mValue.length() == 0 || pValue.length() == 0)
                bWrongParam = true;

            if (bWrongParam == true) {
                System.out.println("Usage:  CMCRevoke " +
                        "-d<dir to NSS database> " +
                        "-n<nickname> " +
                        "-i<issuerName> " +
                        "-s<serialNumber> " +
                        "-m<reason to revoke> " +
                        "-p<password to db> " +
                        "-h<tokenname> " +
                        "-c<comment> ");
                for (i = 0; i < s.length; i++) {
                    System.out.println(i + ":" + s[i]);
                }
                System.exit(0);
            }

            try {
                // initialize CryptoManager
                mPath = dValue;
                System.out.println("cert/key prefix = " + mPrefix);
                System.out.println("path = " + mPath);
                InitializationValues vals =
                    new InitializationValues(mPath, mPrefix, mPrefix, "secmod.db");

                CryptoManager.initialize(vals);

                CryptoManager cm = CryptoManager.getInstance();
                CryptoToken token = CryptoUtil.getKeyStorageToken(hValue);
                if (CryptoUtil.isInternalToken(hValue)) {
                    hValue = CryptoUtil.INTERNAL_TOKEN_NAME;
                }

                Password pass = new Password(pValue.toCharArray());

                token.login(pass);
                X509Certificate signerCert = getCertificate(cm, hValue, nValue);
                ContentInfo fullEnrollmentRequest = createRevokeReq(hValue, signerCert, cm);

                printCMCRevokeRequest(fullEnrollmentRequest);
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }

            return;
        }
    }

    /**
     * printout CMC revoke request in Base64 encoding to a file CMCRevoke.out
     * <P>
     *
     * @param asciiBASE64Blob the ascii string of the request
     */
    static void printCMCRevokeRequest(ContentInfo fullEnrollmentReq) {
        String method = "printCMCRevokeRequest: ";

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);

        if (fullEnrollmentReq == null) {
            System.out.println(method + "param fullEnrollmentRequest is null");
            System.exit(1);
        }
        // format is PR_REQUEST_CMC
        try {
            fullEnrollmentReq.encode(os);
        } catch (IOException e) {
            System.out.println("CMCSigning:  I/O error " +
                    "encountered during write():\n" +
                    e);
            System.exit(1);
        }
        //ps.print(Utils.base64encode(os.toByteArray()));
        // no line breaks for ease of copy/paste for CA acceptance
        ps.print(Utils.base64encode(os.toByteArray(), false));
        ////fullEnrollmentReq.print(ps); // no header/trailer

        String asciiBASE64Blob = bs.toString();
        System.out.println(Cert.REQUEST_HEADER);
        System.out.println(asciiBASE64Blob + "\n" + Cert.REQUEST_FOOTER);

        // (6) Finally, print the actual CMCSigning binary blob to the
        //     specified output file
        FileOutputStream outputBlob = null;

        try {
            outputBlob = new FileOutputStream("CMCRevoke.out");
            fullEnrollmentReq.encode(outputBlob);
        } catch (IOException e) {
            System.out.println("CMCSigning:  unable to open file CMCRevoke.out for writing:\n" + e);
            return;
        }

        System.out.println("\nCMC revocation binary blob written to CMCRevoke.out\n");

        try {
            outputBlob.close();
        } catch (IOException e) {
            System.out.println("CMCSigning:  Unexpected error " +
                    "encountered while attempting to close() " +
                    "\n" + e);
        }
    }

    /**
     * getCertificate find the certicate inside the token by its nickname.
     * <P>
     *
     * @param manager the CrytoManager
     * @param tokenname the name of the token. it's set to "internal".
     * @param nickname the nickname of the certificate inside the token.
     * @return the X509Certificate.
     */
    public static X509Certificate getCertificate(CryptoManager manager, String tokenname,
            String nickname) throws NoSuchTokenException,
            Exception, TokenException {
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenname);

        StringBuffer certname = new StringBuffer();

        if (!token.equals(manager.getInternalKeyStorageToken())) {
            certname.append(tokenname);
            certname.append(":");
        }
        certname.append(nickname);
        System.out.println("CMCRevoke: searching for certificate nickname:"+
                certname.toString());
        try {
            return manager.findCertByNickname(certname.toString());
        } catch (ObjectNotFoundException e) {
            throw new Exception("Signing Certificate not found");
        }
    }

    /**
     * createRevokeReq create and return the revocation request.
     * <P>
     * @tokenname name of the token
     * @param signerCert the certificate of the authorized signer of the CMC revocation request.
     * @param manager the crypto manger.
     * @return the CMC revocation request encoded in base64
     */
    static ContentInfo createRevokeReq(String tokenname, X509Certificate signerCert, CryptoManager manager) {

        java.security.PrivateKey privKey = null;
        SignerIdentifier si = null;
        ContentInfo fullEnrollmentReq = null;

        try {

            BigInteger serialno = signerCert.getSerialNumber();
            byte[] certB = signerCert.getEncoded();
            X509CertImpl impl = new X509CertImpl(certB);
            X500Name issuerName = (X500Name) impl.getIssuerDN();
            byte[] issuerByte = issuerName.getEncoded();
            ByteArrayInputStream istream = new ByteArrayInputStream(issuerByte);

            Name issuer = (Name) Name.getTemplate().decode(istream);
            IssuerAndSerialNumber ias = new IssuerAndSerialNumber(issuer, new INTEGER(serialno.toString()));

            si = new SignerIdentifier(SignerIdentifier.ISSUER_AND_SERIALNUMBER, ias, null);

            privKey = manager.findPrivKeyByCert(signerCert);

            if (privKey == null) {
                System.out.println("CMCRevoke::createRevokeReq() - " +
                        "privKey is null!");
                return null;
            }

            int bpid = 1;
            // Add some control sequence
            // Verisign has transactionID,senderNonce
            SEQUENCE controlSeq = new SEQUENCE();

            Date date = new Date();
            String salt = "lala123" + date.toString();
            byte[] dig;

            try {
                MessageDigest SHA2Digest = MessageDigest.getInstance("SHA256");

                dig = SHA2Digest.digest(salt.getBytes());
            } catch (NoSuchAlgorithmException ex) {
                dig = salt.getBytes();
            }
            String sn = Utils.base64encode(dig, true);

            TaggedAttribute senderNonce = new TaggedAttribute(new INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_senderNonce,
                    new OCTET_STRING(sn.getBytes()));

            controlSeq.addElement(senderNonce);

            Name subjectName = new Name();

            subjectName.addCommonName(iValue);
            org.mozilla.jss.pkix.cmc.RevokeRequest lRevokeRequest = new org.mozilla.jss.pkix.cmc.RevokeRequest(
                    new ANY((new X500Name(iValue)).getEncoded()),
                    new INTEGER(sValue),
                    //org.mozilla.jss.pkix.cmc.RevokeRequest.unspecified,
                    new ENUMERATED((new Integer(mValue)).longValue()),
                    null,
                    (tValue != null) ? new OCTET_STRING(tValue.getBytes()) : null,
                    (cValue != null) ? new UTF8String(cValue.toCharArray()) : null);
            //byte[] encoded = ASN1Util.encode(lRevokeRequest);
            //org.mozilla.jss.asn1.ASN1Template template = new  org.mozilla.jss.pkix.cmc.RevokeRequest.Template();
            //org.mozilla.jss.pkix.cmc.RevokeRequest revRequest = (org.mozilla.jss.pkix.cmc.RevokeRequest)
            //                                                               template.decode(new java.io.ByteArrayInputStream(
            //                                                               encoded));

            TaggedAttribute revokeRequestTag = new TaggedAttribute(new INTEGER(bpid++),
                    OBJECT_IDENTIFIER.id_cmc_revokeRequest,
                    lRevokeRequest);

            controlSeq.addElement(revokeRequestTag);
            PKIData pkidata = new PKIData(controlSeq, new SEQUENCE(), new SEQUENCE(), new SEQUENCE());

            EncapsulatedContentInfo ci = new EncapsulatedContentInfo(OBJECT_IDENTIFIER.id_cct_PKIData, pkidata);
            DigestAlgorithm digestAlg = null;
            SignatureAlgorithm signAlg = null;
            org.mozilla.jss.crypto.PrivateKey.Type signingKeyType = ((org.mozilla.jss.crypto.PrivateKey) privKey)
                    .getType();
            if (signingKeyType.equals(org.mozilla.jss.crypto.PrivateKey.Type.RSA)) {
                signAlg = SignatureAlgorithm.RSASignatureWithSHA256Digest;
            } else if (signingKeyType.equals(org.mozilla.jss.crypto.PrivateKey.Type.EC)) {
                signAlg = SignatureAlgorithm.ECSignatureWithSHA256Digest;
            } else {
                System.out.println("Algorithm not supported:" +
                        signingKeyType);
                return null;
            }

            MessageDigest SHADigest = null;
            byte[] digest = null;

            try {
                SHADigest = MessageDigest.getInstance("SHA256");
                digestAlg = DigestAlgorithm.SHA256;

                ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                pkidata.encode(ostream);
                digest = SHADigest.digest(ostream.toByteArray());
            } catch (NoSuchAlgorithmException e) {
            }
            SignerInfo signInfo = new SignerInfo(si, null, null, OBJECT_IDENTIFIER.id_cct_PKIData, digest, signAlg,
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
                ANY certificate = new ANY(agentChain[i].getEncoded());

                certs.addElement(certificate);
            }
            SignedData req = new SignedData(digestAlgs, ci, certs, null, signInfos);

            fullEnrollmentReq = new ContentInfo(req);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        return fullEnrollmentReq;
    }
}
