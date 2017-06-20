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
package com.netscape.cms.servlet.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.util.Date;
import java.util.Hashtable;

import javax.servlet.http.HttpServletResponse;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ENUMERATED;
import org.mozilla.jss.asn1.GeneralizedTime;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cmc.CMCCertId;
import org.mozilla.jss.pkix.cmc.CMCStatusInfoV2;
import org.mozilla.jss.pkix.cmc.EncryptedPOP;
import org.mozilla.jss.pkix.cmc.GetCert;
import org.mozilla.jss.pkix.cmc.OtherInfo;
import org.mozilla.jss.pkix.cmc.OtherMsg;
import org.mozilla.jss.pkix.cmc.PendInfo;
import org.mozilla.jss.pkix.cmc.ResponseBody;
import org.mozilla.jss.pkix.cmc.RevokeRequest;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cmc.TaggedRequest;
import org.mozilla.jss.pkix.cms.ContentInfo;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;
import org.mozilla.jss.pkix.cms.EnvelopedData;
import org.mozilla.jss.pkix.cms.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cms.SignedData;
import org.mozilla.jss.pkix.cms.SignerIdentifier;
import org.mozilla.jss.pkix.cms.SignerInfo;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CertStatusChangeRequestProcessedEvent;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.InvalidityDateExtension;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;

/**
 * Utility CMCOutputTemplate
 *
 * @version $ $, $Date$
 */
public class CMCOutputTemplate {

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public CMCOutputTemplate() {
    }

    public void createFullResponseWithFailedStatus(HttpServletResponse resp,
            SEQUENCE bpids, int code, UTF8String s) {
        SEQUENCE controlSeq = new SEQUENCE();
        SEQUENCE cmsSeq = new SEQUENCE();
        SEQUENCE otherMsgSeq = new SEQUENCE();

        int bpid = 1;
        OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                new INTEGER(code), null, null);
        CMCStatusInfoV2 cmcStatusInfoV2 = new CMCStatusInfoV2(
                new INTEGER(CMCStatusInfoV2.FAILED),
                bpids, s, otherInfo);
        TaggedAttribute tagattr = new TaggedAttribute(
                new INTEGER(bpid++),
                OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
        controlSeq.addElement(tagattr);

        try {
            ResponseBody respBody = new ResponseBody(controlSeq,
                    cmsSeq, otherMsgSeq);

            SET certs = new SET();
            ContentInfo contentInfo = getContentInfo(respBody, certs);
            if (contentInfo == null)
                return;
            ByteArrayOutputStream fos = new ByteArrayOutputStream();
            contentInfo.encode(fos);
            fos.close();
            byte[] contentBytes = fos.toByteArray();

            resp.setContentType("application/pkcs7-mime");
            resp.setContentLength(contentBytes.length);
            OutputStream os = resp.getOutputStream();
            os.write(contentBytes);
            os.flush();
        } catch (Exception e) {
            CMS.debug("CMCOutputTemplate createFullResponseWithFailedStatus Exception: " + e.toString());
            return;
        }
    }

    public void createFullResponse(HttpServletResponse resp, IRequest[] reqs,
            String cert_request_type, int[] error_codes) {
        String method = "CMCOutputTemplate: createFullResponse: ";
        CMS.debug(method +
                "begins with cert_request_type=" +
                cert_request_type);

        SEQUENCE controlSeq = new SEQUENCE();
        SEQUENCE cmsSeq = new SEQUENCE();
        SEQUENCE otherMsgSeq = new SEQUENCE();
        SessionContext context = SessionContext.getContext();

        // set status info control for simple enrollment request
        // in rfc 2797: body list value is 1
        int bpid = 1;
        SEQUENCE pending_bpids = null;
        SEQUENCE popRequired_bpids = null;
        SEQUENCE success_bpids = null;
        SEQUENCE failed_bpids = null;
        if (cert_request_type.equals("crmf") ||
                cert_request_type.equals("pkcs10")) {
            String reqId = reqs[0].getRequestId().toString();
            OtherInfo otherInfo = null;
            if (error_codes[0] == 2) {
                PendInfo pendInfo = new PendInfo(reqId, new Date());
                otherInfo = new OtherInfo(OtherInfo.PEND, null,
                        pendInfo, null);
            } else {
                otherInfo = new OtherInfo(OtherInfo.FAIL,
                        new INTEGER(OtherInfo.BAD_REQUEST), null, null);
            }

            SEQUENCE bpids = new SEQUENCE();
            bpids.addElement(new INTEGER(1));
            CMCStatusInfoV2 cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.PENDING,
                    bpids, (String) null, otherInfo);
            TaggedAttribute tagattr = new TaggedAttribute(
                    new INTEGER(bpid++),
                    OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
            controlSeq.addElement(tagattr);
        } else if (cert_request_type.equals("cmc")) {
            CMS.debug(method + " processing cmc");
            pending_bpids = new SEQUENCE();
            popRequired_bpids = new SEQUENCE();
            success_bpids = new SEQUENCE();
            failed_bpids = new SEQUENCE();
            EncryptedPOP encPop = null;
            if (reqs != null) {
                for (int i = 0; i < reqs.length; i++) {
                    CMS.debug(method + " error_codes[" +i+"]="
                            + error_codes[i]);
                    if (error_codes[i] == 0) {
                        success_bpids.addElement(new INTEGER(
                                reqs[i].getExtDataInBigInteger("bodyPartId")));
                    } else if (error_codes[i] == 2) {
                        pending_bpids.addElement(new INTEGER(
                                reqs[i].getExtDataInBigInteger("bodyPartId")));
                    } else if (error_codes[i] == 4) {
                        popRequired_bpids.addElement(new INTEGER(
                                reqs[i].getExtDataInBigInteger("bodyPartId")));
                        try {
                            encPop = constructEncryptedPop(reqs[i]);
                        } catch (Exception e) {
                            CMS.debug(method + e);
                            failed_bpids.addElement(new INTEGER(
                                    reqs[i].getExtDataInBigInteger("bodyPartId")));
                        }
                    } else {
                        failed_bpids.addElement(new INTEGER(
                                reqs[i].getExtDataInBigInteger("bodyPartId")));
                    }
                }
            } else {
                CMS.debug(method + " reqs null. could be revocation");
            }

            TaggedAttribute tagattr = null;
            CMCStatusInfoV2 cmcStatusInfoV2 = null;

            SEQUENCE decryptedPOPBpids = (SEQUENCE) context.get("decryptedPOP");
            if (decryptedPOPBpids != null && decryptedPOPBpids.size() > 0) {
                OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                        new INTEGER(OtherInfo.POP_FAILED), null, null);
                cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED,
                        decryptedPOPBpids, (String) null, otherInfo);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);
            }

            SEQUENCE identificationBpids = (SEQUENCE) context.get("identification");
            if (identificationBpids != null && identificationBpids.size() > 0) {
                OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                        new INTEGER(OtherInfo.BAD_IDENTITY), null, null);
                cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED,
                        identificationBpids, (String) null, otherInfo);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);
            }

            SEQUENCE identityV2Bpids = (SEQUENCE) context.get("identityProofV2");
            if (identityV2Bpids != null && identityV2Bpids.size() > 0) {
                OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                        new INTEGER(OtherInfo.BAD_IDENTITY), null, null);
                cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED,
                        identityV2Bpids, (String) null, otherInfo);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);
            }


            SEQUENCE identityBpids = (SEQUENCE) context.get("identityProof");
            if (identityBpids != null && identityBpids.size() > 0) {
                OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                        new INTEGER(OtherInfo.BAD_IDENTITY), null, null);
                cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED,
                        identityBpids, (String) null, otherInfo);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);
            }

            SEQUENCE POPLinkWitnessV2Bpids = (SEQUENCE) context.get("POPLinkWitnessV2");
            if (POPLinkWitnessV2Bpids != null && POPLinkWitnessV2Bpids.size() > 0) {
                OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                        new INTEGER(OtherInfo.BAD_REQUEST), null, null);
                cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED,
                        POPLinkWitnessV2Bpids, (String) null, otherInfo);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);
            }

            SEQUENCE POPLinkWitnessBpids = (SEQUENCE) context.get("POPLinkWitness");
            if (POPLinkWitnessBpids != null && POPLinkWitnessBpids.size() > 0) {
                OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                        new INTEGER(OtherInfo.BAD_REQUEST), null, null);
                cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED,
                        POPLinkWitnessBpids, (String) null, otherInfo);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);
            }

            if (popRequired_bpids.size() > 0) {
                // handle encryptedPOP control

                if (encPop != null) {
                    CMS.debug(method + "adding encPop");
                    tagattr = new TaggedAttribute(
                            new INTEGER(bpid++),
                            OBJECT_IDENTIFIER.id_cmc_encryptedPOP,
                            encPop);
                    controlSeq.addElement(tagattr);
                    CMS.debug(method + "encPop added");
                }

                OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                       new INTEGER(OtherInfo.POP_REQUIRED), null, null);
                cmcStatusInfoV2 =
                        new CMCStatusInfoV2(CMCStatusInfoV2.POP_REQUIRED,
                        popRequired_bpids, (String) null, otherInfo);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);

                // add request id
                byte[] reqId = reqs[0].getRequestId().toBigInteger().toByteArray();
                TaggedAttribute reqIdTA =
                        new TaggedAttribute(new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_responseInfo,
                        new OCTET_STRING(reqId));
                controlSeq.addElement(reqIdTA);
            }

            if (pending_bpids.size() > 0) {
                String reqId = reqs[0].getRequestId().toString();
                PendInfo pendInfo = new PendInfo(reqId, new Date());
                OtherInfo otherInfo = new OtherInfo(OtherInfo.PEND, null,
                        pendInfo, null);
                cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.PENDING,
                        pending_bpids, (String) null, otherInfo);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);
            }

            if (success_bpids.size() > 0) {
                boolean confirmRequired = false;
                try {
                    confirmRequired =
                            CMS.getConfigStore().getBoolean("cmc.cert.confirmRequired",
                                    false);
                } catch (Exception e) {
                }
                if (confirmRequired) {
                    CMS.debug(method + " confirmRequired in the request");
                    cmcStatusInfoV2 =
                            new CMCStatusInfoV2(CMCStatusInfoV2.CONFIRM_REQUIRED,
                                    success_bpids, (String) null, null);
                } else {
                    cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.SUCCESS,
                            success_bpids, (String) null, null);
                }
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);
            }

            if (failed_bpids.size() > 0) {
                OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                        new INTEGER(OtherInfo.BAD_REQUEST), null, null);
                cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED,
                        failed_bpids, (String) null, otherInfo);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                controlSeq.addElement(tagattr);
            }
        }

        SET certs = new SET();

        try {
            // deal with controls
            Integer nums = (Integer) (context.get("numOfControls"));
            if (nums != null && nums.intValue() > 0) {
                CMS.debug(method + " processing controls");
                TaggedAttribute attr =
                        (TaggedAttribute) (context.get(OBJECT_IDENTIFIER.id_cmc_getCert));
                if (attr != null) {
                    try {
                        processGetCertControl(attr, certs);
                    } catch (EBaseException ee) {
                        CMS.debug(method + ee.toString());
                        OtherInfo otherInfo1 = new OtherInfo(OtherInfo.FAIL,
                                new INTEGER(OtherInfo.BAD_CERT_ID), null, null);
                        SEQUENCE bpids1 = new SEQUENCE();
                        bpids1.addElement(attr.getBodyPartID());
                        CMCStatusInfoV2 cmcStatusInfoV2 = new CMCStatusInfoV2(
                                new INTEGER(CMCStatusInfoV2.FAILED),
                                bpids1, null, otherInfo1);
                        TaggedAttribute tagattr1 = new TaggedAttribute(
                                new INTEGER(bpid++),
                                OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                        controlSeq.addElement(tagattr1);
                    }
                }

                attr =
                        (TaggedAttribute) (context.get(OBJECT_IDENTIFIER.id_cmc_dataReturn));
                if (attr != null)
                    bpid = processDataReturnControl(attr, controlSeq, bpid);

                attr =
                        (TaggedAttribute) context.get(OBJECT_IDENTIFIER.id_cmc_transactionId);
                if (attr != null)
                    bpid = processTransactionControl(attr, controlSeq, bpid);

                attr =
                        (TaggedAttribute) context.get(OBJECT_IDENTIFIER.id_cmc_senderNonce);
                if (attr != null)
                    bpid = processSenderNonceControl(attr, controlSeq, bpid);

                attr =
                        (TaggedAttribute) context.get(OBJECT_IDENTIFIER.id_cmc_QueryPending);
                if (attr != null)
                    bpid = processQueryPendingControl(attr, controlSeq, bpid);

                attr =
                        (TaggedAttribute) context.get(OBJECT_IDENTIFIER.id_cmc_idConfirmCertAcceptance);

                if (attr != null)
                    bpid = processConfirmCertAcceptanceControl(attr, controlSeq,
                            bpid);

                attr =
                        (TaggedAttribute) context.get(OBJECT_IDENTIFIER.id_cmc_revokeRequest);

                if (attr != null)
                    bpid = processRevokeRequestControl(attr, controlSeq,
                            bpid);
            }

            if (success_bpids != null && success_bpids.size() > 0) {
                for (int i = 0; i < reqs.length; i++) {
                    if (error_codes[i] == 0) {
                        X509CertImpl impl =
                                (reqs[i].getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT));
                        byte[] bin = impl.getEncoded();
                        Certificate.Template certTemplate = new Certificate.Template();
                        Certificate cert = (Certificate) certTemplate.decode(
                                new ByteArrayInputStream(bin));
                        certs.addElement(cert);
                    }
                }
            }

            ResponseBody respBody = new ResponseBody(controlSeq,
                    cmsSeq, otherMsgSeq);
            CMS.debug(method + " after new ResponseBody, respBody not null");

            ContentInfo contentInfo = getContentInfo(respBody, certs);
            ByteArrayOutputStream fos = new ByteArrayOutputStream();
            contentInfo.encode(fos);
            fos.close();
            byte[] contentBytes = fos.toByteArray();

            resp.setContentType("application/pkcs7-mime");
            resp.setContentLength(contentBytes.length);
            OutputStream os = resp.getOutputStream();
            os.write(contentBytes);
            os.flush();
            CMS.debug(method + "ends");
        } catch (java.security.cert.CertificateEncodingException e) {
            CMS.debug(method + e.toString());
        } catch (InvalidBERException e) {
            CMS.debug(method + e.toString());
        } catch (IOException e) {
            CMS.debug(method + e.toString());
        } catch (Exception e) {
            CMS.debug(method + e.toString());
        }
    }

    /**
     * constructEncryptedPop pulls cmc pop challenge fields out of the request
     * and constructs an EncryptedPOP
     * to be included in the response later
     *
     * @author cfu
     */
    public EncryptedPOP constructEncryptedPop(IRequest req)
            throws EBaseException {
        String method = "CMCOutputTemplate: constructEncryptedPop: ";
        String msg = "";
        CMS.debug(method + "begins");
        EncryptedPOP encPop = null;

        if (req == null) {
            msg = method + "method parameters cannot be null";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }

        boolean popChallengeRequired = req.getExtDataInBoolean("cmc_POPchallengeRequired", false);
        if (!popChallengeRequired) {
            CMS.debug(method + "popChallengeRequired false");
            return null;
        }
        CMS.debug(method + "popChallengeRequired true");

        byte[] cmc_msg = req.getExtDataInByteArray(IEnrollProfile.CTX_CERT_REQUEST);
        byte[] pop_encryptedData = req.getExtDataInByteArray("pop_encryptedData");
        //don't need this for encryptedPOP, but need to check for existence anyway
        byte[] pop_sysPubEncryptedSession = req.getExtDataInByteArray("pop_sysPubEncryptedSession");
        byte[] pop_userPubEncryptedSession = req.getExtDataInByteArray("pop_userPubEncryptedSession");
        byte[] iv = req.getExtDataInByteArray("pop_encryptedDataIV");
        if ((pop_encryptedData != null) &&
                (pop_sysPubEncryptedSession != null) &&
                (pop_userPubEncryptedSession != null)) {
            // generate encryptedPOP here
            // algs are hard-coded for now

            try {
                EnvelopedData envData = CryptoUtil.createEnvelopedData(
                        pop_encryptedData,
                        pop_userPubEncryptedSession);
                if (envData == null) {
                    msg = "envData null returned by createEnvelopedData";
                    throw new EBaseException(method + msg);
                }
                ContentInfo ci = new ContentInfo(envData);
                CMS.debug(method + "now we can compose encryptedPOP");

                TaggedRequest.Template tReqTemplate = new TaggedRequest.Template();
                TaggedRequest tReq = (TaggedRequest) tReqTemplate.decode(
                        new ByteArrayInputStream(cmc_msg));
                if (tReq == null) {
                    msg = "tReq null from tReqTemplate.decode";
                    CMS.debug(msg);
                    throw new EBaseException(method + msg);
                }

                OBJECT_IDENTIFIER oid = EncryptionAlgorithm.AES_128_CBC.toOID();
                AlgorithmIdentifier aid = new AlgorithmIdentifier(oid, new OCTET_STRING(iv));

                encPop = new EncryptedPOP(
                        tReq,
                        ci,
                        aid,
                        CryptoUtil.getDefaultHashAlg(),
                        new OCTET_STRING(req.getExtDataInByteArray("pop_witness")));

            } catch (Exception e) {
                CMS.debug(method + " excepton:" + e);
                throw new EBaseException(method + " exception:" + e);
            }

        } else {
            msg = "popChallengeRequired, but one or more of the pop_ data not found in request";
            CMS.debug(method + msg);
            throw new EBaseException(method + msg);
        }

        return encPop;
    }

    private ContentInfo getContentInfo(ResponseBody respBody, SET certs) {
        String method = "CMCOutputTemplate: getContentInfo: ";
        CMS.debug(method + "begins");
        try {
            ICertificateAuthority ca = null;
            // add CA cert chain
            ca = (ICertificateAuthority) CMS.getSubsystem("ca");
            CertificateChain certchains = ca.getCACertChain();
            java.security.cert.X509Certificate[] chains = certchains.getChain();

            for (int i = 0; i < chains.length; i++) {
                Certificate.Template certTemplate = new Certificate.Template();
                Certificate cert = (Certificate) certTemplate.decode(
                        new ByteArrayInputStream(chains[i].getEncoded()));
                certs.addElement(cert);
            }

            EncapsulatedContentInfo enContentInfo = new EncapsulatedContentInfo(
                    OBJECT_IDENTIFIER.id_cct_PKIResponse, respBody);
            org.mozilla.jss.crypto.X509Certificate x509CAcert = null;
            x509CAcert = ca.getCaX509Cert();
            X509CertImpl caimpl = new X509CertImpl(x509CAcert.getEncoded());
            X500Name issuerName = (X500Name) caimpl.getIssuerDN();
            byte[] issuerByte = issuerName.getEncoded();
            ByteArrayInputStream istream = new ByteArrayInputStream(issuerByte);
            Name issuer = (Name) Name.getTemplate().decode(istream);
            IssuerAndSerialNumber ias = new IssuerAndSerialNumber(
                    issuer, new INTEGER(x509CAcert.getSerialNumber().toString()));
            SignerIdentifier si = new SignerIdentifier(
                    SignerIdentifier.ISSUER_AND_SERIALNUMBER, ias, null);
            // use CA instance's default signature and digest algorithm
            SignatureAlgorithm signAlg = ca.getDefaultSignatureAlgorithm();
            org.mozilla.jss.crypto.PrivateKey privKey =
                    CryptoManager.getInstance().findPrivKeyByCert(x509CAcert);
            /*
                        org.mozilla.jss.crypto.PrivateKey.Type keyType = privKey.getType();
                        if( keyType.equals( org.mozilla.jss.crypto.PrivateKey.RSA ) ) {
                            signAlg = SignatureAlgorithm.RSASignatureWithSHA1Digest;
                        } else if( keyType.equals( org.mozilla.jss.crypto.PrivateKey.DSA ) ) {
                            signAlg = SignatureAlgorithm.DSASignatureWithSHA1Digest;
                        } else if( keyType.equals( org.mozilla.jss.crypto.PrivateKey.EC ) ) {
                             signAlg = SignatureAlgorithm.ECSignatureWithSHA1Digest;
                        } else {
                            CMS.debug( "CMCOutputTemplate::getContentInfo() - "
                                     + "signAlg is unsupported!" );
                            return null;
                        }
            */
            DigestAlgorithm digestAlg = signAlg.getDigestAlg();
            MessageDigest msgDigest = null;
            byte[] digest = null;

            msgDigest = MessageDigest.getInstance(digestAlg.toString());

            ByteArrayOutputStream ostream = new ByteArrayOutputStream();

            respBody.encode(ostream);
            digest = msgDigest.digest(ostream.toByteArray());

            SignerInfo signInfo = new
                    SignerInfo(si, null, null,
                            OBJECT_IDENTIFIER.id_cct_PKIResponse,
                            digest, signAlg, privKey);
            SET signInfos = new SET();

            signInfos.addElement(signInfo);

            SET digestAlgs = new SET();

            if (digestAlg != null) {
                AlgorithmIdentifier ai = new
                        AlgorithmIdentifier(digestAlg.toOID(), null);

                digestAlgs.addElement(ai);
            }
            SignedData signedData = new SignedData(digestAlgs,
                    enContentInfo, certs, null, signInfos);

            ContentInfo contentInfo = new ContentInfo(signedData);
            CMS.debug(method + " - done");
            return contentInfo;
        } catch (Exception e) {
            CMS.debug(method + " Failed to create CMCContentInfo. Exception: " + e.toString());
        }
        return null;
    }

    public void createSimpleResponse(HttpServletResponse resp, IRequest[] reqs) {
        SET certs = new SET();
        SessionContext context = SessionContext.getContext();
        try {
            TaggedAttribute attr =
                    (TaggedAttribute) (context.get(OBJECT_IDENTIFIER.id_cmc_getCert));
            processGetCertControl(attr, certs);
        } catch (Exception e) {
            CMS.debug("CMCOutputTemplate: No certificate is found.");
        }

        SET digestAlgorithms = new SET();
        SET signedInfos = new SET();

        // oid for id-data
        OBJECT_IDENTIFIER oid = new OBJECT_IDENTIFIER("1.2.840.113549.1.7.1");
        EncapsulatedContentInfo enContentInfo = new EncapsulatedContentInfo(oid, null);

        try {
            if (reqs != null) {
                for (int i = 0; i < reqs.length; i++) {
                    X509CertImpl impl =
                            (reqs[i].getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT));
                    byte[] bin = impl.getEncoded();
                    Certificate.Template certTemplate = new Certificate.Template();
                    Certificate cert =
                            (Certificate) certTemplate.decode(new ByteArrayInputStream(bin));

                    certs.addElement(cert);
                }

                // Get CA certs
                ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem("ca");
                CertificateChain certchains = ca.getCACertChain();
                java.security.cert.X509Certificate[] chains = certchains.getChain();

                for (int i = 0; i < chains.length; i++) {
                    Certificate.Template certTemplate = new Certificate.Template();
                    Certificate cert = (Certificate) certTemplate.decode(
                            new ByteArrayInputStream(chains[i].getEncoded()));
                    certs.addElement(cert);
                }
            }

            if (certs.size() == 0)
                return;
            SignedData signedData = new SignedData(digestAlgorithms,
                    enContentInfo, certs, null, signedInfos);

            ContentInfo contentInfo = new ContentInfo(signedData);
            ByteArrayOutputStream fos = new ByteArrayOutputStream();
            contentInfo.encode(fos);
            fos.close();
            byte[] contentBytes = fos.toByteArray();

            resp.setContentType("application/pkcs7-mime");
            resp.setContentLength(contentBytes.length);
            OutputStream os = resp.getOutputStream();
            os.write(contentBytes);
            os.flush();
        } catch (java.security.cert.CertificateEncodingException e) {
            CMS.debug("CMCOutputTemplate exception: " + e.toString());
        } catch (InvalidBERException e) {
            CMS.debug("CMCOutputTemplate exception: " + e.toString());
        } catch (IOException e) {
            CMS.debug("CMCOutputTemplate exception: " + e.toString());
        }
    }

    private int processConfirmCertAcceptanceControl(
            TaggedAttribute attr, SEQUENCE controlSeq, int bpid) {
        if (attr != null) {
            INTEGER bodyId = attr.getBodyPartID();
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(bodyId);
            SET values = attr.getValues();
            if (values != null && values.size() > 0) {
                try {
                    CMCCertId cmcCertId =
                            (CMCCertId) (ASN1Util.decode(CMCCertId.getTemplate(),
                                    ASN1Util.encode(values.elementAt(0))));
                    BigInteger serialno = cmcCertId.getSerial();
                    SEQUENCE issuers = cmcCertId.getIssuer();
                    //ANY issuer = (ANY)issuers.elementAt(0);
                    ANY issuer =
                            (ANY) (ASN1Util.decode(ANY.getTemplate(),
                                    ASN1Util.encode(issuers.elementAt(0))));
                    byte[] b = issuer.getEncoded();
                    X500Name n = new X500Name(b);
                    ICertificateAuthority ca = null;
                    ca = (ICertificateAuthority) CMS.getSubsystem("ca");
                    X500Name caName = ca.getX500Name();
                    boolean confirmAccepted = false;
                    if (n.toString().equalsIgnoreCase(caName.toString())) {
                        CMS.debug("CMCOutputTemplate: Issuer names are equal");
                        ICertificateRepository repository = ca.getCertificateRepository();
                        try {
                            repository.getX509Certificate(serialno);
                        } catch (EBaseException ee) {
                            CMS.debug("CMCOutputTemplate: Certificate in the confirm acceptance control was not found");
                        }
                    }
                    CMCStatusInfoV2 cmcStatusInfoV2 = null;
                    if (confirmAccepted) {
                        CMS.debug("CMCOutputTemplate: Confirm Acceptance received. The certificate exists in the certificate repository.");
                        cmcStatusInfoV2 =
                                new CMCStatusInfoV2(CMCStatusInfoV2.SUCCESS, seq,
                                        (String) null, null);
                    } else {
                        CMS.debug("CMCOutputTemplate: Confirm Acceptance received. The certificate does not exist in the certificate repository.");
                        OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                                new INTEGER(OtherInfo.BAD_CERT_ID), null, null);
                        cmcStatusInfoV2 =
                                new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, seq,
                                        (String) null, otherInfo);
                    }
                    TaggedAttribute statustagattr = new TaggedAttribute(
                            new INTEGER(bpid++),
                            OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                    controlSeq.addElement(statustagattr);
                } catch (Exception e) {
                    CMS.debug("CMCOutputTemplate exception: " + e.toString());
                }
            }
        }
        return bpid;
    }

    private void processGetCertControl(TaggedAttribute attr, SET certs)
            throws InvalidBERException, java.security.cert.CertificateEncodingException,
            IOException, EBaseException {
        if (attr != null) {
            SET vals = attr.getValues();

            if (vals.size() == 1) {
                GetCert getCert =
                        (GetCert) (ASN1Util.decode(GetCert.getTemplate(),
                                ASN1Util.encode(vals.elementAt(0))));
                BigInteger serialno = getCert.getSerialNumber();
                ANY issuer = getCert.getIssuer();
                byte b[] = issuer.getEncoded();
                X500Name n = new X500Name(b);
                ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem("ca");
                X500Name caName = ca.getX500Name();
                if (!n.toString().equalsIgnoreCase(caName.toString())) {
                    CMS.debug("CMCOutputTemplate: Issuer names are equal in the GetCert Control");
                    throw new EBaseException("Certificate is not found");
                }
                ICertificateRepository repository =
                        ca.getCertificateRepository();
                X509CertImpl impl = repository.getX509Certificate(serialno);
                byte[] bin = impl.getEncoded();
                Certificate.Template certTemplate = new Certificate.Template();
                Certificate cert =
                        (Certificate) certTemplate.decode(new ByteArrayInputStream(bin));
                certs.addElement(cert);
            }
        }
    }

    private int processQueryPendingControl(TaggedAttribute attr,
            SEQUENCE controlSeq, int bpid) {
        if (attr != null) {
            SET values = attr.getValues();
            if (values != null && values.size() > 0) {
                SEQUENCE pending_bpids = new SEQUENCE();
                SEQUENCE success_bpids = new SEQUENCE();
                SEQUENCE failed_bpids = new SEQUENCE();
                for (int i = 0; i < values.size(); i++) {
                    try {
                        INTEGER reqId = (INTEGER)
                                ASN1Util.decode(INTEGER.getTemplate(),
                                        ASN1Util.encode(values.elementAt(i)));
                        String requestId = new String(reqId.toByteArray());

                        ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem("ca");
                        IRequestQueue queue = ca.getRequestQueue();
                        IRequest r = queue.findRequest(new RequestId(requestId));
                        if (r != null) {
                            RequestStatus status = r.getRequestStatus();
                            if (status.equals(RequestStatus.PENDING)) {
                                pending_bpids.addElement(reqId);
                            } else if (status.equals(RequestStatus.APPROVED)) {
                                success_bpids.addElement(reqId);
                            } else if (status.equals(RequestStatus.REJECTED)) {
                                failed_bpids.addElement(reqId);
                            }
                        }
                    } catch (Exception e) {
                    }
                }

                if (pending_bpids.size() > 0) {
                    CMCStatusInfoV2 cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.PENDING,
                            pending_bpids, (String) null, null);
                    TaggedAttribute tagattr = new TaggedAttribute(
                            new INTEGER(bpid++),
                            OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                    controlSeq.addElement(tagattr);
                }
                if (success_bpids.size() > 0) {
                    CMCStatusInfoV2 cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.SUCCESS,
                            pending_bpids, (String) null, null);
                    TaggedAttribute tagattr = new TaggedAttribute(
                            new INTEGER(bpid++),
                            OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                    controlSeq.addElement(tagattr);
                }

                if (failed_bpids.size() > 0) {
                    CMCStatusInfoV2 cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED,
                            pending_bpids, (String) null, null);
                    TaggedAttribute tagattr = new TaggedAttribute(
                            new INTEGER(bpid++),
                            OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                    controlSeq.addElement(tagattr);
                }

            }
        }
        return bpid;
    }

    private int processTransactionControl(TaggedAttribute attr,
            SEQUENCE controlSeq, int bpid) {
        if (attr != null) {
            SET transIds = attr.getValues();
            if (transIds != null) {
                TaggedAttribute tagattr = new TaggedAttribute(
                        new INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_transactionId,
                        transIds);
                controlSeq.addElement(tagattr);
            }
        }

        return bpid;
    }

    private int processSenderNonceControl(TaggedAttribute attr,
            SEQUENCE controlSeq, int bpid) {
        if (attr != null) {
            SET sNonce = attr.getValues();
            if (sNonce != null) {
                TaggedAttribute tagattr = new TaggedAttribute(
                        new INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_recipientNonce,
                        sNonce);
                controlSeq.addElement(tagattr);
                Date date = new Date();
                String salt = "lala123" + date.toString();
                byte[] dig;
                try {
                    MessageDigest SHA2Digest = MessageDigest.getInstance("SHA256");
                    dig = SHA2Digest.digest(salt.getBytes());
                } catch (NoSuchAlgorithmException ex) {
                    dig = salt.getBytes();
                }

                String b64E = CMS.BtoA(dig);
                tagattr = new TaggedAttribute(
                        new INTEGER(bpid++), OBJECT_IDENTIFIER.id_cmc_senderNonce,
                        new OCTET_STRING(b64E.getBytes()));
                controlSeq.addElement(tagattr);
            }
        }

        return bpid;
    }

    private int processDataReturnControl(TaggedAttribute attr,
            SEQUENCE controlSeq, int bpid) throws InvalidBERException {

        if (attr != null) {
            SET vals = attr.getValues();

            if (vals.size() > 0) {
                OCTET_STRING str =
                        (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                                ASN1Util.encode(vals.elementAt(0))));
                TaggedAttribute tagattr = new TaggedAttribute(
                        new INTEGER(bpid++),
                        OBJECT_IDENTIFIER.id_cmc_dataReturn, str);
                controlSeq.addElement(tagattr);
            }
        }

        return bpid;
    }

    private int processRevokeRequestControl(TaggedAttribute attr,
            SEQUENCE controlSeq, int bpid) throws InvalidBERException, EBaseException,
            IOException {
        String method = "CMCOutputTemplate: processRevokeRequestControl: ";
        String msg = "";
        CMS.debug(method + "begins");
        boolean revoke = false;
        SessionContext context = SessionContext.getContext();
        String authManagerId = (String) context.get(SessionContext.AUTH_MANAGER_ID);
        if (authManagerId == null) {
            CMS.debug(method + "authManagerId null.????");
            //unlikely, but...
            authManagerId = "none";
        } else {
            CMS.debug(method + "authManagerId =" + authManagerId);
        }

        // in case of CMCUserSignedAuth,
        // for matching signer and revoked cert principal
        X500Name signerPrincipal = null;

        // for auditing
        String auditRequesterID = null;
        auditRequesterID = (String) context.get(SessionContext.USER_ID);

        if (auditRequesterID != null) {
            auditRequesterID = auditRequesterID.trim();
        } else {
            auditRequesterID = ILogger.NONROLEUSER;
        }
        signerPrincipal = (X500Name) context.get(SessionContext.CMC_SIGNER_PRINCIPAL);
        String auditSubjectID = null;
        String auditRequestType = "revoke";
        String auditSerialNumber = null;
        String auditReasonNum = null;
        RequestStatus auditApprovalStatus = RequestStatus.REJECTED;

        if (attr != null) {
            INTEGER attrbpid = attr.getBodyPartID();
            CMCStatusInfoV2 cmcStatusInfoV2 = null;
            SET vals = attr.getValues();
            if (vals.size() > 0) {
                RevokeRequest revRequest = (RevokeRequest) (ASN1Util.decode(new RevokeRequest.Template(),
                        ASN1Util.encode(vals.elementAt(0))));
                OCTET_STRING reqSecret = revRequest.getSharedSecret();
                INTEGER pid = attr.getBodyPartID();
                TaggedAttribute tagattr = null;
                INTEGER revokeCertSerial = revRequest.getSerialNumber();
                ENUMERATED n = revRequest.getReason();
                RevocationReason reason = toRevocationReason(n);
                auditReasonNum = reason.toString();
                BigInteger revokeSerial = new BigInteger(revokeCertSerial.toByteArray());
                auditSerialNumber = revokeSerial.toString();

                if (reqSecret == null) {
                    CMS.debug(method + "no shared secret in request; Checking signature;");
                    boolean needVerify = true;
                    try {
                        needVerify = CMS.getConfigStore().getBoolean("cmc.revokeCert.verify", true);
                    } catch (Exception e) {
                    }

                    if (needVerify) {
                        if (authManagerId.equals("CMCUserSignedAuth")) {
                            if (signerPrincipal == null) {
                                CMS.debug(method + "missing CMC signer principal");
                                OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                                        new INTEGER(OtherInfo.BAD_MESSAGE_CHECK),
                                        null, null);
                                SEQUENCE failed_bpids = new SEQUENCE();
                                failed_bpids.addElement(attrbpid);
                                cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, failed_bpids, (String) null,
                                        otherInfo);
                                tagattr = new TaggedAttribute(
                                        new INTEGER(bpid++),
                                        OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                                controlSeq.addElement(tagattr);
                                return bpid;
                            }
                        } else { // !CMCUserSignedAuth

                            // this code is making the assumption that OtherMsg
                            // is used for signer info in signed cmc revocation,
                            // when in fact the signer info is
                            // in the outer layer and should have already been
                            // verified in the auth manager;
                            // Left here for possible legacy client(s)

                            Integer num1 = (Integer) context.get("numOfOtherMsgs");
                            CMS.debug(method + "found numOfOtherMsgs =" + num1.toString());
                            int num = num1.intValue();
                            for (int i = 0; i < num; i++) {
                                OtherMsg data = (OtherMsg) context.get("otherMsg" + i);
                                INTEGER dpid = data.getBodyPartID();
                                if (pid.longValue() == dpid.longValue()) {
                                    CMS.debug(method + "body part id match;");
                                    ANY msgValue = data.getOtherMsgValue();
                                    SignedData msgData = (SignedData) msgValue.decodeWith(SignedData.getTemplate());
                                    if (!verifyRevRequestSignature(msgData)) {
                                        OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL,
                                                new INTEGER(OtherInfo.BAD_MESSAGE_CHECK),
                                                null, null);
                                        SEQUENCE failed_bpids = new SEQUENCE();
                                        failed_bpids.addElement(attrbpid);
                                        cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, failed_bpids,
                                                (String) null,
                                                otherInfo);
                                        tagattr = new TaggedAttribute(
                                                new INTEGER(bpid++),
                                                OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                                        controlSeq.addElement(tagattr);
                                        return bpid;
                                    }
                                } else {
                                    CMS.debug(method + "body part id do not match;");
                                }
                            }
                        }
                    }

                    revoke = true;
                } else { //use shared secret; request unsigned
                    CMS.debug(method + "checking shared secret");
                    // check shared secret
                    //TODO: remember to provide one-time-use when working
                    //      on shared token
                    ISharedToken tokenClass =
                            CMS.getSharedTokenClass("cmc.revokeCert.sharedSecret.class");
                    if (tokenClass == null) {
                        CMS.debug(method + " Failed to retrieve shared secret plugin class");
                        OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL, new INTEGER(OtherInfo.INTERNAL_CA_ERROR),
                                null, null);
                        SEQUENCE failed_bpids = new SEQUENCE();
                        failed_bpids.addElement(attrbpid);
                        cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, failed_bpids, (String) null, otherInfo);
                        tagattr = new TaggedAttribute(
                                new INTEGER(bpid++),
                                OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                        controlSeq.addElement(tagattr);
                        return bpid;
                    }

                    String sharedSecret =
                            sharedSecret = tokenClass.getSharedToken(revokeSerial);

                    if (sharedSecret == null) {
                        CMS.debug("CMCOutputTemplate: shared secret not found.");
                        OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL, new INTEGER(OtherInfo.BAD_IDENTITY),
                                null, null);
                        SEQUENCE failed_bpids = new SEQUENCE();
                        failed_bpids.addElement(attrbpid);
                        cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, failed_bpids, (String) null, otherInfo);
                        tagattr = new TaggedAttribute(
                                new INTEGER(bpid++),
                                OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                        controlSeq.addElement(tagattr);
                        return bpid;
                    }

                    byte[] reqSecretb = reqSecret.toByteArray();
                    String clientSC = new String(reqSecretb);
                    if (clientSC.equals(sharedSecret)) {
                        CMS.debug(method
                                + " Client and server shared secret are the same, can go ahead and revoke certificate.");
                        revoke = true;
                    } else {
                        CMS.debug(method
                                + " Client and server shared secret are not the same, cannot revoke certificate.");
                        OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL, new INTEGER(OtherInfo.BAD_IDENTITY),
                                null, null);
                        SEQUENCE failed_bpids = new SEQUENCE();
                        failed_bpids.addElement(attrbpid);
                        cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, failed_bpids, (String) null, otherInfo);
                        tagattr = new TaggedAttribute(
                                new INTEGER(bpid++),
                                OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                        controlSeq.addElement(tagattr);

                        audit(new CertStatusChangeRequestProcessedEvent(
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditSerialNumber,
                                auditRequestType,
                                auditReasonNum,
                                auditApprovalStatus));

                        return bpid;
                    }
                }

                if (revoke) {
                    ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem("ca");
                    ICertificateRepository repository = ca.getCertificateRepository();
                    ICertRecord record = null;
                    try {
                        record = repository.readCertificateRecord(revokeSerial);
                    } catch (EBaseException ee) {
                        CMS.debug(method + "Exception: " + ee.toString());
                    }

                    if (record == null) {
                        CMS.debug(method + " The certificate is not found");
                        OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL, new INTEGER(OtherInfo.BAD_CERT_ID), null, null);
                        SEQUENCE failed_bpids = new SEQUENCE();
                        failed_bpids.addElement(attrbpid);
                        cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, failed_bpids, (String) null, otherInfo);
                        tagattr = new TaggedAttribute(
                                new INTEGER(bpid++),
                                OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                        controlSeq.addElement(tagattr);
                        return bpid;
                    }

                    if (record.getStatus().equals(ICertRecord.STATUS_REVOKED)) {
                        CMS.debug("CMCOutputTemplate: The certificate is already revoked.");
                        SEQUENCE success_bpids = new SEQUENCE();
                        success_bpids.addElement(attrbpid);
                        cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.SUCCESS,
                                success_bpids, (String) null, null);
                        tagattr = new TaggedAttribute(
                                new INTEGER(bpid++),
                                OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                        controlSeq.addElement(tagattr);
                        return bpid;
                    }

                    X509CertImpl impl = record.getCertificate();

                    X500Name certPrincipal = (X500Name) impl.getSubjectDN();
                    auditSubjectID = certPrincipal.getCommonName();

                    // in case of user-signed request, check if signer
                    // principal matches that of the revoking cert
                    if ((reqSecret == null) && authManagerId.equals("CMCUserSignedAuth")) {
                        if (!certPrincipal.equals(signerPrincipal)) {
                            msg = "certificate principal and signer do not match";
                            CMS.debug(method + msg);
                            OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL, new INTEGER(OtherInfo.BAD_IDENTITY),
                                    null, null);
                            SEQUENCE failed_bpids = new SEQUENCE();
                            failed_bpids.addElement(attrbpid);
                            cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, failed_bpids, msg,
                                    otherInfo);
                            tagattr = new TaggedAttribute(
                                    new INTEGER(bpid++),
                                    OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                            controlSeq.addElement(tagattr);

                            audit(new CertStatusChangeRequestProcessedEvent(
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    auditSerialNumber,
                                    auditRequestType,
                                    auditReasonNum,
                                    auditApprovalStatus));

                            return bpid;
                        } else {
                            CMS.debug(method + "certificate principal and signer match");
                        }
                    }

                    X509CertImpl[] impls = new X509CertImpl[1];
                    impls[0] = impl;
                    CRLReasonExtension crlReasonExtn = new CRLReasonExtension(reason);
                    CRLExtensions entryExtn = new CRLExtensions();
                    GeneralizedTime t = revRequest.getInvalidityDate();
                    InvalidityDateExtension invalidityDateExtn = null;
                    if (t != null) {
                        invalidityDateExtn = new InvalidityDateExtension(t.toDate());
                        entryExtn.set(invalidityDateExtn.getName(), invalidityDateExtn);
                    }
                    if (crlReasonExtn != null) {
                        entryExtn.set(crlReasonExtn.getName(), crlReasonExtn);
                    }

                    RevokedCertImpl revCertImpl = new RevokedCertImpl(impl.getSerialNumber(), CMS.getCurrentDate(),
                            entryExtn);
                    RevokedCertImpl[] revCertImpls = new RevokedCertImpl[1];
                    revCertImpls[0] = revCertImpl;
                    IRequestQueue queue = ca.getRequestQueue();
                    IRequest revReq = queue.newRequest(IRequest.REVOCATION_REQUEST);
                    revReq.setExtData(IRequest.CERT_INFO, revCertImpls);
                    revReq.setExtData(IRequest.REVOKED_REASON,
                            Integer.valueOf(reason.toInt()));
                    UTF8String utfstr = revRequest.getComment();
                    if (utfstr != null)
                        revReq.setExtData(IRequest.REQUESTOR_COMMENTS, utfstr.toString());
                    revReq.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_AGENT);
                    queue.processRequest(revReq);
                    RequestStatus stat = revReq.getRequestStatus();
                    if (stat == RequestStatus.COMPLETE) {
                        Integer result = revReq.getExtDataInInteger(IRequest.RESULT);
                        CMS.debug(method + " revReq result = " + result);
                        if (result.equals(IRequest.RES_ERROR)) {
                            CMS.debug("CMCOutputTemplate: revReq exception: " +
                                    revReq.getExtDataInString(IRequest.ERROR));
                            OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL, new INTEGER(OtherInfo.BAD_REQUEST),
                                    null, null);
                            SEQUENCE failed_bpids = new SEQUENCE();
                            failed_bpids.addElement(attrbpid);
                            cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, failed_bpids, (String) null,
                                    otherInfo);
                            tagattr = new TaggedAttribute(
                                    new INTEGER(bpid++),
                                    OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                            controlSeq.addElement(tagattr);

                            audit(new CertStatusChangeRequestProcessedEvent(
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    auditSerialNumber,
                                    auditRequestType,
                                    auditReasonNum,
                                    auditApprovalStatus));

                            return bpid;
                        }
                    }

                    ILogger logger = CMS.getLogger();
                    String initiative = AuditFormat.FROMUSER;
                    logger.log(ILogger.EV_AUDIT, ILogger.S_OTHER, AuditFormat.LEVEL,
                            AuditFormat.DOREVOKEFORMAT, new Object[] {
                                    revReq.getRequestId(), initiative, "completed",
                                    impl.getSubjectDN(),
                                    impl.getSerialNumber().toString(16),
                                    reason.toString() });
                    CMS.debug(method + " Certificate revoked.");
                    SEQUENCE success_bpids = new SEQUENCE();
                    success_bpids.addElement(attrbpid);
                    cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.SUCCESS,
                            success_bpids, (String) null, null);
                    tagattr = new TaggedAttribute(
                            new INTEGER(bpid++),
                            OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                    controlSeq.addElement(tagattr);

                    auditApprovalStatus = RequestStatus.COMPLETE;
                    audit(new CertStatusChangeRequestProcessedEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditRequesterID,
                            auditSerialNumber,
                            auditRequestType,
                            auditReasonNum,
                            auditApprovalStatus));
                    return bpid;
                } else {
                    OtherInfo otherInfo = new OtherInfo(OtherInfo.FAIL, new INTEGER(OtherInfo.INTERNAL_CA_ERROR), null, null);
                    SEQUENCE failed_bpids = new SEQUENCE();
                    failed_bpids.addElement(attrbpid);
                    cmcStatusInfoV2 = new CMCStatusInfoV2(CMCStatusInfoV2.FAILED, failed_bpids, (String) null, otherInfo);
                    tagattr = new TaggedAttribute(
                            new INTEGER(bpid++),
                            OBJECT_IDENTIFIER.id_cmc_statusInfoV2, cmcStatusInfoV2);
                    controlSeq.addElement(tagattr);

                    audit(new CertStatusChangeRequestProcessedEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditSerialNumber,
                            auditRequestType,
                            auditReasonNum,
                            auditApprovalStatus));

                    return bpid;
                }
            }
        }

        return bpid;
    }

    protected void audit(AuditEvent event) {

        String template = event.getMessage();
        Object[] params = event.getParameters();

        String message = CMS.getLogMessage(template, params);

        audit(message);
    }

    protected void audit(String msg) {
        signedAuditLogger.log(msg);
    }

    private RevocationReason toRevocationReason(ENUMERATED n) {
        long code = n.getValue();
        if (code == RevokeRequest.aACompromise.getValue())
            return RevocationReason.UNSPECIFIED;
        else if (code == RevokeRequest.affiliationChanged.getValue())
            return RevocationReason.AFFILIATION_CHANGED;
        else if (code == RevokeRequest.cACompromise.getValue())
            return RevocationReason.CA_COMPROMISE;
        else if (code == RevokeRequest.certificateHold.getValue())
            return RevocationReason.CERTIFICATE_HOLD;
        else if (code == RevokeRequest.cessationOfOperation.getValue())
            return RevocationReason.CESSATION_OF_OPERATION;
        else if (code == RevokeRequest.keyCompromise.getValue())
            return RevocationReason.KEY_COMPROMISE;
        else if (code == RevokeRequest.privilegeWithdrawn.getValue())
            return RevocationReason.UNSPECIFIED;
        else if (code == RevokeRequest.removeFromCRL.getValue())
            return RevocationReason.REMOVE_FROM_CRL;
        else if (code == RevokeRequest.superseded.getValue())
            return RevocationReason.SUPERSEDED;
        else if (code == RevokeRequest.unspecified.getValue())
            return RevocationReason.UNSPECIFIED;
        return RevocationReason.UNSPECIFIED;
    }

    private boolean verifyRevRequestSignature(SignedData msgData) {
        String method = "CMCOutputTemplate: verifyRevRequestSignature: ";
        CMS.debug(method + "begins");
        try {
            EncapsulatedContentInfo ci = msgData.getContentInfo();
            OCTET_STRING content = ci.getContent();
            ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
            TaggedAttribute tattr = (TaggedAttribute) (new TaggedAttribute.Template()).decode(s);
            SET values = tattr.getValues();
            RevokeRequest revRequest = null;
            if (values != null && values.size() > 0) {
                revRequest = (RevokeRequest) (ASN1Util.decode(new RevokeRequest.Template(),
                        ASN1Util.encode(values.elementAt(0))));
            } else {
                CMS.debug(method + "attribute null");
                return false;
            }

            SET dias = msgData.getDigestAlgorithmIdentifiers();
            int numDig = dias.size();
            Hashtable<String, byte[]> digs = new Hashtable<String, byte[]>();
            for (int i = 0; i < numDig; i++) {
                AlgorithmIdentifier dai = (AlgorithmIdentifier) dias.elementAt(i);
                String name = DigestAlgorithm.fromOID(dai.getOID()).toString();
                MessageDigest md = MessageDigest.getInstance(name);
                byte[] digest = md.digest(content.toByteArray());
                digs.put(name, digest);
            }

            SET sis = msgData.getSignerInfos();
            int numSis = sis.size();
            for (int i = 0; i < numSis; i++) {
                org.mozilla.jss.pkix.cms.SignerInfo si = (org.mozilla.jss.pkix.cms.SignerInfo) sis.elementAt(i);
                String name = si.getDigestAlgorithm().toString();
                byte[] digest = digs.get(name);
                if (digest == null) {
                    MessageDigest md = MessageDigest.getInstance(name);
                    ByteArrayOutputStream ostream = new ByteArrayOutputStream();
                    revRequest.encode(ostream);
                    digest = md.digest(ostream.toByteArray());
                }
                SignerIdentifier sid = si.getSignerIdentifier();
                if (sid.getType().equals(SignerIdentifier.ISSUER_AND_SERIALNUMBER)) {
                    org.mozilla.jss.pkix.cms.IssuerAndSerialNumber issuerAndSerialNumber = sid
                            .getIssuerAndSerialNumber();
                    java.security.cert.X509Certificate cert = null;
                    if (msgData.hasCertificates()) {
                        SET certs = msgData.getCertificates();
                        int numCerts = certs.size();
                        for (int j = 0; j < numCerts; j++) {
                            org.mozilla.jss.pkix.cert.Certificate certJss = (Certificate) certs.elementAt(j);
                            org.mozilla.jss.pkix.cert.CertificateInfo certI = certJss.getInfo();
                            Name issuer = certI.getIssuer();
                            byte[] issuerB = ASN1Util.encode(issuer);
                            INTEGER sn = certI.getSerialNumber();
                            if (new String(issuerB).equalsIgnoreCase(new String(ASN1Util.encode(issuerAndSerialNumber
                                    .getIssuer()))) &&
                                    sn.toString().equals(issuerAndSerialNumber.getSerialNumber().toString())) {
                                ByteArrayOutputStream os = new ByteArrayOutputStream();
                                certJss.encode(os);
                                cert = new X509CertImpl(os.toByteArray());
                                break;
                            }
                        }
                    }

                    if (cert != null) {
                        CMS.debug(method + "found cert");
                        PublicKey pbKey = cert.getPublicKey();
                        PK11PubKey pubK = PK11PubKey.fromSPKI(((X509Key) pbKey).getKey());
                        si.verify(digest, ci.getContentType(), pubK);

                        // now check validity of the cert
                        java.security.cert.X509Certificate[] x509Certs = new java.security.cert.X509Certificate[1];
                        x509Certs[0] = cert;
                        if (CMS.isRevoked(x509Certs)) {
                            CMS.debug(method + "CMC signing cert is a revoked certificate");
                            return false;
                        }
                        try {
                            cert.checkValidity();
                        } catch (CertificateExpiredException e) {
                            CMS.debug(method + "CMC signing cert is an expired certificate");
                            return false;
                        } catch (Exception e) {
                            return false;
                        }

                        return true;
                    } else {
                        CMS.debug(method + "cert not found");
                    }
                } else {
                    CMS.debug(method + "unsupported SignerIdentifier for CMC revocation");
                }
            }

            return false;
        } catch (Exception e) {
            CMS.debug("CMCOutputTemplate: verifyRevRequestSignature. Exception: " + e.toString());
            return false;
        }
    }
}
