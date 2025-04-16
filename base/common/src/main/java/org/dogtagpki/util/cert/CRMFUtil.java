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
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
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
    public static Extension getExtensionFromCertTemplate(CertTemplate certTemplate, ObjectIdentifier csOID) {

        // ObjectIdentifier csOID = PKIXExtensions.SubjectKey_Id;
        OBJECT_IDENTIFIER jssOID = new OBJECT_IDENTIFIER(csOID.toString());
        String method = "CRMFUtil: getSKIExtensionFromCertTemplate: ";
        Extension extn = null;

        // There seems to be an issue with constructor in Extension
        // when feeding SubjectKeyIdentifierExtension;
        // Special-case it
        OBJECT_IDENTIFIER SKIoid = new OBJECT_IDENTIFIER(PKIXExtensions.SubjectKey_Id.toString());

        if (certTemplate.hasExtensions()) {
            int numexts = certTemplate.numExtensions();
            for (int j = 0; j < numexts; j++) {
                org.mozilla.jss.pkix.cert.Extension jssext = certTemplate.extensionAt(j);
                OBJECT_IDENTIFIER extnoid = jssext.getExtnId();
                logger.debug(method + "checking extension in request:" + extnoid);
                if (extnoid.equals(jssOID)) {
                    logger.debug(method + "extension found");
                    try {
                        if (jssOID.equals(SKIoid)) {
                            logger.debug(method + "SKIoid == jssOID");
                            extn = new SubjectKeyIdentifierExtension(false, jssext.getExtnValue().toByteArray());
                        } else {
                            logger.debug(method + "SKIoid != jssOID");
                            extn = new Extension(csOID, false, jssext.getExtnValue().toByteArray());
                        }
                    } catch (IOException e) {
                        logger.warn(method + e, e);
                    }
                }
            }
        } else {
            logger.debug(method + "no extension found");
        }

        return extn;
    }

    public static CertTemplate createCertTemplate(Name subject, PublicKey publicKey) throws Exception {
    
        CertTemplate template = new CertTemplate();
        template.setVersion(new INTEGER(2));
        template.setSubject(subject);
        template.setPublicKey(new SubjectPublicKeyInfo(publicKey));
    
        return template;
    }
}
