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
package com.netscape.cms.servlet.processors;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;

import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.Extension;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Process CRMF requests, according to RFC 2511
 * See http://www.ietf.org/rfc/rfc2511.txt
 *
 * @version $Revision$, $Date$
 */
public class CRMFProcessor extends PKIProcessor {

    @SuppressWarnings("unused")
    private ICMSRequest mRequest;

    private boolean enforcePop = false;

    private final static String LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION =
            "LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION_2";

    public CRMFProcessor() {
        super();
    }

    public CRMFProcessor(ICMSRequest cmsReq, CMSServlet servlet, boolean doEnforcePop) {
        super(cmsReq, servlet);

        enforcePop = doEnforcePop;
        mRequest = cmsReq;
    }

    public void process(ICMSRequest cmsReq)
            throws EBaseException {
    }

    /**
     * Verify Proof of Possession (POP)
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION used when proof of possession is checked during
     * certificate enrollment
     * </ul>
     *
     * @param certReqMsg the certificate request message
     * @exception EBaseException an error has occurred
     */
    private void verifyPOP(CertReqMsg certReqMsg)
            throws EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        try {
            CMS.debug("CRMFProcessor: verifyPOP");

            if (certReqMsg.hasPop()) {
                ProofOfPossession pop = certReqMsg.getPop();

                ProofOfPossession.Type popType = pop.getType();

                if (popType == ProofOfPossession.SIGNATURE) {
                    CMS.debug("CRMFProcessor: Request has pop.");
                    try {
                        certReqMsg.verify();

                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION,
                                auditSubjectID,
                                ILogger.SUCCESS);

                        audit(auditMessage);
                    } catch (Exception e) {
                        CMS.debug("CRMFProcessor: Failed POP verify!");

                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSGW_ERROR_POP_VERIFY"));

                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION,
                                auditSubjectID,
                                ILogger.FAILURE);

                        audit(auditMessage);

                        throw new ECMSGWException(
                                CMS.getLogMessage("CMSGW_ERROR_POP_VERIFY"));
                    }
                }
            } else {
                if (enforcePop == true) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_ERROR_NO_POP"));

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION,
                            auditSubjectID,
                            ILogger.FAILURE);

                    audit(auditMessage);

                    throw new ECMSGWException(
                            CMS.getLogMessage("CMSGW_ERROR_NO_POP"));
                }
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION,
                    auditSubjectID,
                    ILogger.FAILURE);

            audit(auditMessage);
        }
    }

    public X509CertInfo processIndividualRequest(CertReqMsg certReqMsg, IAuthToken authToken, IArgBlock httpParams)
            throws EBaseException {
        CMS.debug("CRMFProcessor::processIndividualRequest!");

        try {

            verifyPOP(certReqMsg);

            CertRequest certReq = certReqMsg.getCertReq();

            CertTemplate certTemplate = certReq.getCertTemplate();
            X509CertInfo certInfo = CMS.getDefaultX509CertInfo();

            // get key
            SubjectPublicKeyInfo spki = certTemplate.getPublicKey();
            ByteArrayOutputStream keyout = new ByteArrayOutputStream();

            spki.encode(keyout);
            byte[] keybytes = keyout.toByteArray();
            X509Key key = new X509Key();

            key.decode(keybytes);
            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(key));

            // field suggested notBefore and notAfter in CRMF
            // Tech Support #383184
            if (certTemplate.getNotBefore() != null || certTemplate.getNotAfter() != null) {
                CertificateValidity certValidity =
                        new CertificateValidity(certTemplate.getNotBefore(), certTemplate.getNotAfter());

                certInfo.set(X509CertInfo.VALIDITY, certValidity);
            }

            if (certTemplate.hasSubject()) {
                Name subjectdn = certTemplate.getSubject();
                ByteArrayOutputStream subjectEncStream =
                        new ByteArrayOutputStream();

                subjectdn.encode(subjectEncStream);
                byte[] subjectEnc = subjectEncStream.toByteArray();
                X500Name subject = new X500Name(subjectEnc);

                certInfo.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(subject));
            } else if (authToken == null ||
                    authToken.getInString(AuthToken.TOKEN_CERT_SUBJECT) == null) {
                // No subject name - error!
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
            }

            // get extensions
            CertificateExtensions extensions = null;

            try {
                extensions = (CertificateExtensions)
                        certInfo.get(X509CertInfo.EXTENSIONS);
            } catch (CertificateException e) {
                extensions = null;
            } catch (IOException e) {
                extensions = null;
            }
            if (certTemplate.hasExtensions()) {
                // put each extension from CRMF into CertInfo.
                // index by extension name, consistent with
                // CertificateExtensions.parseExtension() method.
                if (extensions == null)
                    extensions = new CertificateExtensions();
                int numexts = certTemplate.numExtensions();

                for (int j = 0; j < numexts; j++) {
                    org.mozilla.jss.pkix.cert.Extension jssext =
                            certTemplate.extensionAt(j);
                    boolean isCritical = jssext.getCritical();
                    org.mozilla.jss.asn1.OBJECT_IDENTIFIER jssoid =
                            jssext.getExtnId();
                    long[] numbers = jssoid.getNumbers();
                    int[] oidNumbers = new int[numbers.length];

                    for (int k = numbers.length - 1; k >= 0; k--) {
                        oidNumbers[k] = (int) numbers[k];
                    }
                    ObjectIdentifier oid =
                            new ObjectIdentifier(oidNumbers);
                    org.mozilla.jss.asn1.OCTET_STRING jssvalue =
                            jssext.getExtnValue();
                    ByteArrayOutputStream jssvalueout =
                            new ByteArrayOutputStream();

                    jssvalue.encode(jssvalueout);
                    byte[] extValue = jssvalueout.toByteArray();

                    Extension ext =
                            new Extension(oid, isCritical, extValue);

                    extensions.parseExtension(ext);
                }

                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);

            }

            // Added a new configuration parameter
            // eeGateway.Enrollment.authTokenOverride=[true|false]
            // By default, it is set to true. In most
            // of the case, administrator would want
            // to have the control of the subject name
            // formulation.
            // -- CRMFfillCert
            if (authToken != null &&
                    authToken.getInString(AuthToken.TOKEN_CERT_SUBJECT) != null) {
                // if authenticated override subect name, validity and
                // extensions if any from authtoken.
                fillCertInfoFromAuthToken(certInfo, authToken);
            }

            // SPECIAL CASE:
            // if it is adminEnroll servlet, get the validity
            // from the http parameters.
            if (mServletId.equals(PKIProcessor.ADMIN_ENROLL_SERVLET_ID)) {
                fillValidityFromForm(certInfo, httpParams);
            }

            return certInfo;

        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"));
        } /* catch (InvalidBERException e) {
          log(ILogger.LL_FAILURE,
          CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1",e.toString()));
          throw new ECMSGWException(
          CMSGWResources.ERROR_CRMF_TO_CERTINFO);
          } */catch (InvalidKeyException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"));
        }

    }

    public X509CertInfo[] fillCertInfoArray(
            String protocolString, IAuthToken authToken, IArgBlock httpParams, IRequest req)
            throws EBaseException {

        CMS.debug("CRMFProcessor.fillCertInfoArray!");

        String crmf = protocolString;

        try {
            byte[] crmfBlob = CMS.AtoB(crmf);
            ByteArrayInputStream crmfBlobIn =
                    new ByteArrayInputStream(crmfBlob);

            SEQUENCE crmfMsgs = (SEQUENCE)
                    new SEQUENCE.OF_Template(new CertReqMsg.Template()).decode(crmfBlobIn);

            int nummsgs = crmfMsgs.size();
            X509CertInfo[] certInfoArray = new X509CertInfo[nummsgs];

            for (int i = 0; i < nummsgs; i++) {
                // decode message.
                CertReqMsg certReqMsg = (CertReqMsg) crmfMsgs.elementAt(i);

                CertRequest certReq = certReqMsg.getCertReq();
                INTEGER certReqId = certReq.getCertReqId();
                int srcId = certReqId.intValue();

                req.setExtData(IRequest.CRMF_REQID, String.valueOf(srcId));

                certInfoArray[i] = processIndividualRequest(certReqMsg, authToken, httpParams);

            }

            //do_testbed_hack(nummsgs, certInfoArray, httpParams);

            return certInfoArray;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"));
        } catch (InvalidBERException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"));
        }
    }
}
