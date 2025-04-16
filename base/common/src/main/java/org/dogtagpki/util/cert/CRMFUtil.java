//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.util.cert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.util.WrappingParams;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.crmf.POPOSigningKey;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CRMFUtil {

    public final static Logger logger = LoggerFactory.getLogger(CRMFUtil.class);

    public static SEQUENCE parseCRMFMsgs(byte[] request) throws IOException, InvalidBERException {

        if (request == null) {
            throw new IOException("Missing CRMF request");
        }

        ByteArrayInputStream crmfBlobIn = new ByteArrayInputStream(request);
        return (SEQUENCE) new SEQUENCE.OF_Template(new CertReqMsg.Template()).decode(crmfBlobIn);
    }

    public static CertReqMsg[] parseCRMF(String request) throws Exception {

        if (request == null) {
            logger.error("CRMFUtil: Missing CRMF request");
            throw new EProfileException("Missing CRMF request");
        }

        byte[] data = CertUtil.parseCSR(request);

        try {
            ByteArrayInputStream crmfBlobIn = new ByteArrayInputStream(data);
            SEQUENCE crmfMsgs = (SEQUENCE) new SEQUENCE.OF_Template(
                    new CertReqMsg.Template()).decode(crmfBlobIn);

            int size = crmfMsgs.size();
            if (size <= 0) {
                return null;
            }

            CertReqMsg[] msgs = new CertReqMsg[crmfMsgs.size()];
            for (int i = 0; i < size; i++) {
                msgs[i] = (CertReqMsg) crmfMsgs.elementAt(i);
            }

            return msgs;

        } catch (Exception e) {
            logger.error("Unable to parse CRMF request: " + e.getMessage(), e);
            throw new EProfileException("Unable to parse CRMF request: " + e.getMessage(), e);
        }
    }

    public static String encodeCRMF(byte[] request) throws Exception {
        StringWriter sw = new StringWriter();
        try (PrintWriter out = new PrintWriter(sw)) {
            out.println(Cert.REQUEST_HEADER);
            out.print(Utils.base64encode(request, true));
            out.println(Cert.REQUEST_FOOTER);
        }
        return sw.toString();
    }

    public static X509Key getX509KeyFromCRMFMsg(CertReqMsg crmfMsg)
            throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeyFormatException {
        CertRequest certRequest = crmfMsg.getCertReq();
        CertTemplate certTemplate = certRequest.getCertTemplate();
        SubjectPublicKeyInfo subjectPublicKeyInfo = certTemplate.getPublicKey();
        PublicKey publicKey = subjectPublicKeyInfo.toPublicKey();
        return CryptoUtil.createX509Key(publicKey);
    }

    public static X509Key getX509KeyFromCRMFMsgs(SEQUENCE crmfMsgs)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeyException, InvalidKeyFormatException {

        if (crmfMsgs == null) {
            throw new IOException("Missing CRMF requests");
        }

        int size = crmfMsgs.size();
        if (size <= 0) {
            throw new IOException("Missing CRMF requests");
        }

        CertReqMsg msg = (CertReqMsg) crmfMsgs.elementAt(0);
        return getX509KeyFromCRMFMsg(msg);
    }

    public static X500Name getSubjectName(SEQUENCE crmfMsgs) throws IOException {

        int size = crmfMsgs.size();
        if (size <= 0) {
            throw new IOException("Missing CRMF requests");
        }

        CertReqMsg msg = (CertReqMsg) crmfMsgs.elementAt(0);
        CertRequest certreq = msg.getCertReq();
        CertTemplate certTemplate = certreq.getCertTemplate();

        Name name = certTemplate.getSubject();
        ByteArrayOutputStream subjectEncStream = new ByteArrayOutputStream();
        name.encode(subjectEncStream);

        byte[] bytes = subjectEncStream.toByteArray();
        return new X500Name(bytes);
    }

    /**
     * Get extension from CRMF request (CertTemplate)
     */
    public static Extension getExtensionFromCertTemplate(
            CertTemplate certTemplate,
            ObjectIdentifier csOID) throws IOException {

        if (!certTemplate.hasExtensions()) {
            return null;
        }

        OBJECT_IDENTIFIER jssOID = new OBJECT_IDENTIFIER(csOID.toString());

        // There seems to be an issue with constructor in Extension
        // when feeding SubjectKeyIdentifierExtension;
        // Special-case it
        OBJECT_IDENTIFIER skiOID = new OBJECT_IDENTIFIER(PKIXExtensions.SubjectKey_Id.toString());

        int size = certTemplate.numExtensions();
        for (int i = 0; i < size; i++) {
            org.mozilla.jss.pkix.cert.Extension ext = certTemplate.extensionAt(i);

            OBJECT_IDENTIFIER extOID = ext.getExtnId();
            if (!extOID.equals(jssOID)) {
                continue;
            }

            if (jssOID.equals(skiOID)) {
                return new SubjectKeyIdentifierExtension(false, ext.getExtnValue().toByteArray());
            }

            return new Extension(csOID, false, ext.getExtnValue().toByteArray());
        }

        return null;
    }

    public static CertTemplate createCertTemplate(Name subject, PublicKey publicKey) throws Exception {

        CertTemplate template = new CertTemplate();
        template.setVersion(new INTEGER(2));
        template.setSubject(subject);
        template.setPublicKey(new SubjectPublicKeyInfo(publicKey));

        return template;
    }

    public static CertRequest createCertRequest(
            boolean useSharedSecret,
            CryptoToken token,
            X509Certificate transportCert,
            KeyPair keyPair,
            Name subject,
            KeyWrapAlgorithm keyWrapAlgorithm,
            boolean useOAEP) throws Exception {

        CertTemplate certTemplate = createCertTemplate(subject, keyPair.getPublic());

        SEQUENCE seq = new SEQUENCE();

        if (transportCert != null) { // add key archive Option
            byte[] iv = CryptoUtil.getNonceData(keyWrapAlgorithm.getBlockSize());
            OBJECT_IDENTIFIER kwOID = CryptoUtil.getOID(keyWrapAlgorithm);

            // TODO(alee)
            //
            // HACK HACK!
            // algorithms like AES KeyWrap do not require an IV, but we need to include one
            // in the AlgorithmIdentifier above, or the creation and parsing of the
            // PKIArchiveOptions options will fail.  So we include an IV in aid, but null it
            // later to correctly encrypt the data
            AlgorithmIdentifier aid = new AlgorithmIdentifier(kwOID, new OCTET_STRING(iv));

            Class<?>[] iv_classes = keyWrapAlgorithm.getParameterClasses();
            if (iv_classes == null || iv_classes.length == 0)
                iv = null;

            WrappingParams params = CryptoUtil.getWrappingParams(keyWrapAlgorithm, iv, useOAEP);

            PKIArchiveOptions opts = CryptoUtil.createPKIArchiveOptions(
                    token,
                    transportCert.getPublicKey(),
                    (PrivateKey) keyPair.getPrivate(),
                    params,
                    aid);

            seq.addElement(new AVA(new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.5.1.4"), opts));
        } // key archival option

        // OCTET_STRING ostr = createIDPOPLinkWitness();
        // seq.addElement(new AVA(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness, ostr));

        if (useSharedSecret) { // RFC 5272
            logger.debug("CRMFUtil: Generating SubjectKeyIdentifier extension");
            KeyIdentifier subjKeyId = CryptoUtil.createKeyIdentifier(keyPair);
            OBJECT_IDENTIFIER oid = new OBJECT_IDENTIFIER(PKIXExtensions.SubjectKey_Id.toString());
            SEQUENCE extns = new SEQUENCE();
            extns.addElement(new AVA(oid, new OCTET_STRING(subjKeyId.getIdentifier())));
            certTemplate.setExtensions(extns);
        }

        return new CertRequest(new INTEGER(1), certTemplate, seq);
    }

    public static ProofOfPossession createPop(
            SignatureAlgorithm signatureAlgorithm,
            byte[] signature) throws Exception {

        AlgorithmIdentifier algorithmID = new AlgorithmIdentifier(signatureAlgorithm.toOID(), null);
        POPOSigningKey popoKey = new POPOSigningKey(null, algorithmID, new BIT_STRING(signature, 0));
        return ProofOfPossession.createSignature(popoKey);
    }

    public static byte[] createCRMFRequest(
            CertRequest certRequest,
            ProofOfPossession pop) throws Exception {

        CertReqMsg crmfMessage = new CertReqMsg(certRequest, pop, null);
        // crmfMessage.verify();

        SEQUENCE seq = new SEQUENCE();
        seq.addElement(crmfMessage);

        return ASN1Util.encode(seq);
    }
}
