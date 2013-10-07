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
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

import netscape.security.pkcs.PKCS10;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.pkcs10.CertificationRequest;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.pkix.cmc.PKIData;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cmc.TaggedCertificationRequest;
import org.mozilla.jss.pkix.cmc.TaggedRequest;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;
import org.mozilla.jss.pkix.cms.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cms.SignedData;
import org.mozilla.jss.pkix.cms.SignerIdentifier;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Process CMC messages according to RFC 2797
 * See http://www.ietf.org/rfc/rfc2797.txt
 *
 * @version $Revision$, $Date$
 */
public class CMCProcessor extends PKIProcessor {

    private boolean enforcePop = false;

    public CMCProcessor() {
        super();
    }

    public CMCProcessor(ICMSRequest cmsReq, CMSServlet servlet, boolean doEnforcePop) {

        super(cmsReq, servlet);
        enforcePop = doEnforcePop;

    }

    public void process(ICMSRequest cmsReq)
            throws EBaseException {
    }

    public void fillCertInfo(
            String protocolString, X509CertInfo certInfo,
            IAuthToken authToken, IArgBlock httpParams)
            throws EBaseException {
    }

    public X509CertInfo[] fillCertInfoArray(
            String protocolString, IAuthToken authToken, IArgBlock httpParams, IRequest req)
            throws EBaseException {

        CMS.debug("CMCProcessor: In CMCProcessor.fillCertInfoArray!");
        String cmc = protocolString;

        try {
            byte[] cmcBlob = CMS.AtoB(cmc);
            ByteArrayInputStream cmcBlobIn =
                    new ByteArrayInputStream(cmcBlob);

            org.mozilla.jss.pkix.cms.ContentInfo cmcReq = (org.mozilla.jss.pkix.cms.ContentInfo)
                    org.mozilla.jss.pkix.cms.ContentInfo.getTemplate().decode(cmcBlobIn);

            if (!cmcReq.getContentType().equals(org.mozilla.jss.pkix.cms.ContentInfo.SIGNED_DATA)
                    || !cmcReq.hasContent())
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_NO_CMC_CONTENT"));

            SignedData cmcFullReq = (SignedData)
                    cmcReq.getInterpretedContent();

            EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();

            OBJECT_IDENTIFIER id = ci.getContentType();

            if (!id.equals(OBJECT_IDENTIFIER.id_cct_PKIData) || !ci.hasContent()) {
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_NO_PKIDATA"));
            }
            OCTET_STRING content = ci.getContent();

            ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
            PKIData pkiData = (PKIData) (new PKIData.Template()).decode(s);

            SEQUENCE reqSequence = pkiData.getReqSequence();

            int numReqs = reqSequence.size();
            X509CertInfo[] certInfoArray = new X509CertInfo[numReqs];
            String[] reqIdArray = new String[numReqs];

            for (int i = 0; i < numReqs; i++) {
                // decode message.
                TaggedRequest taggedRequest = (TaggedRequest) reqSequence.elementAt(i);

                TaggedRequest.Type type = taggedRequest.getType();

                if (type.equals(TaggedRequest.PKCS10)) {
                    TaggedCertificationRequest tcr = taggedRequest.getTcr();
                    int p10Id = tcr.getBodyPartID().intValue();

                    reqIdArray[i] = String.valueOf(p10Id);

                    CertificationRequest p10 =
                            tcr.getCertificationRequest();

                    // transfer to sun class
                    ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                    p10.encode(ostream);

                    PKCS10Processor pkcs10Processor = new PKCS10Processor(mRequest, mServlet);

                    try {
                        PKCS10 pkcs10 = new PKCS10(ostream.toByteArray());
                        //xxx do we need to do anything else?
                        X509CertInfo certInfo = CMS.getDefaultX509CertInfo();

                        pkcs10Processor.fillCertInfo(pkcs10, certInfo, authToken, httpParams);

                        /*    fillPKCS10(pkcs10,certInfo,
                         authToken, httpParams);
                         */

                        certInfoArray[i] = certInfo;
                    } catch (Exception e) {
                        throw new ECMSGWException(
                                CMS.getUserMessage("CMS_GW_PKCS10_ERROR", e.toString()));
                    }
                } else if (type.equals(TaggedRequest.CRMF)) {

                    CRMFProcessor crmfProc = new CRMFProcessor(mRequest, mServlet, enforcePop);

                    CertReqMsg crm = taggedRequest.getCrm();
                    CertRequest certReq = crm.getCertReq();

                    INTEGER certReqId = certReq.getCertReqId();
                    int srcId = certReqId.intValue();

                    reqIdArray[i] = String.valueOf(srcId);

                    certInfoArray[i] = crmfProc.processIndividualRequest(crm, authToken, httpParams);

                } else {
                    throw new ECMSGWException(CMS.getUserMessage("CMS_GW_NO_CMC_CONTENT"));
                }
            }

            // verify the signerInfo
            SET dais = cmcFullReq.getDigestAlgorithmIdentifiers();
            int numDig = dais.size();
            Hashtable<String, byte[]> digs = new Hashtable<String, byte[]>();

            for (int i = 0; i < numDig; i++) {
                AlgorithmIdentifier dai =
                        (AlgorithmIdentifier) dais.elementAt(i);
                String name =
                        DigestAlgorithm.fromOID(dai.getOID()).toString();

                MessageDigest md =
                        MessageDigest.getInstance(name);

                byte[] digest = md.digest(content.toByteArray());

                digs.put(name, digest);
            }

            SET sis = cmcFullReq.getSignerInfos();
            int numSis = sis.size();

            for (int i = 0; i < numSis; i++) {
                org.mozilla.jss.pkix.cms.SignerInfo si =
                        (org.mozilla.jss.pkix.cms.SignerInfo)
                        sis.elementAt(i);

                String name = si.getDigestAlgorithm().toString();
                byte[] digest = digs.get(name);

                if (digest == null) {
                    MessageDigest md = MessageDigest.getInstance(name);
                    ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                    pkiData.encode(ostream);
                    digest = md.digest(ostream.toByteArray());

                }

                SignerIdentifier sid = si.getSignerIdentifier();

                if (sid.getType().equals(SignerIdentifier.ISSUER_AND_SERIALNUMBER)) {
                    IssuerAndSerialNumber issuerAndSerialNumber = sid.getIssuerAndSerialNumber();
                    // find from the certs in the signedData
                    X509Certificate cert = null;

                    if (cmcFullReq.hasCertificates()) {
                        SET certs = cmcFullReq.getCertificates();
                        int numCerts = certs.size();

                        for (int j = 0; j < numCerts; j++) {
                            Certificate certJss =
                                    (Certificate) certs.elementAt(j);
                            CertificateInfo certI =
                                    certJss.getInfo();
                            Name issuer = certI.getIssuer();
                            byte[] issuerB = ASN1Util.encode(issuer);

                            INTEGER sn = certI.getSerialNumber();

                            if (new String(issuerB).equals(new
                                    String(ASN1Util.encode(issuerAndSerialNumber.getIssuer())))
                                    && sn.toString().equals(issuerAndSerialNumber.getSerialNumber().toString())) {
                                ByteArrayOutputStream os = new
                                        ByteArrayOutputStream();

                                certJss.encode(os);
                                cert = new X509CertImpl(os.toByteArray());
                                // xxx validate the cert length

                            }
                        }

                    }
                    // find from internaldb if it's ca. (ra does not have that.)
                    // find from internaldb usrgrp info

                    if (cert == null) {
                        // find from certDB
                        si.verify(digest, id);
                    } else {
                        PublicKey signKey = cert.getPublicKey();
                        PK11PubKey pubK = PK11PubKey.fromSPKI(((X509Key) signKey).getKey());
                        si.verify(digest, id, pubK);
                    }

                } else {
                    OCTET_STRING ski = sid.getSubjectKeyIdentifier();
                    // find the publicKey using ski
                    int j = 0;
                    PublicKey signKey = null;

                    while (signKey == null && j < numReqs) {
                        X509Key subjectKeyInfo =
                                (X509Key) ((CertificateX509Key) certInfoArray[j].get(X509CertInfo.KEY))
                                        .get(CertificateX509Key.KEY);
                        MessageDigest md = MessageDigest.getInstance("SHA-1");

                        md.update(subjectKeyInfo.getEncoded());
                        byte[] skib = md.digest();

                        if (new String(skib).equals(new String(ski.toByteArray()))) {
                            signKey = subjectKeyInfo;
                        }
                        j++;
                    }
                    if (signKey == null) {
                        throw new ECMSGWException(CMS.getUserMessage("CMS_GW_CMC_ERROR",
                                "SubjectKeyIdentifier in SignerInfo does not match any publicKey in the request."));
                    } else {
                        PK11PubKey pubK = PK11PubKey.fromSPKI(((X509Key) signKey).getKey());
                        si.verify(digest, id, pubK);
                    }
                }
            }
            // end verify signerInfo

            // Get control sequence
            // verisign has transactionId, senderNonce, regInfo
            // identification, identityproof
            SEQUENCE controls = pkiData.getControlSequence();
            int numControls = controls.size();

            for (int i = 0; i < numControls; i++) {
                TaggedAttribute control =
                        (TaggedAttribute) controls.elementAt(i);
                OBJECT_IDENTIFIER type = control.getType();
                SET values = control.getValues();
                int numVals = values.size();

                if (type.equals(OBJECT_IDENTIFIER.id_cmc_transactionId)) {
                    String[] vals = null;

                    if (numVals > 0)
                        vals = new String[numVals];
                    for (int j = 0; j < numVals; j++) {
                        ANY val = (ANY)
                                values.elementAt(j);
                        INTEGER transId = (INTEGER) val.decodeWith(
                                INTEGER.getTemplate());

                        if (transId != null) {
                            vals[j] = transId.toString();
                        }
                    }
                    if (vals != null)
                        req.setExtData(IRequest.CMC_TRANSID, vals);
                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_senderNonce)) {
                    String[] vals = null;

                    if (numVals > 0)
                        vals = new String[numVals];
                    for (int j = 0; j < numVals; j++) {
                        ANY val = (ANY)
                                values.elementAt(j);
                        OCTET_STRING nonce = (OCTET_STRING)
                                val.decodeWith(OCTET_STRING.getTemplate());

                        if (nonce != null) {
                            vals[j] = new String(nonce.toByteArray());
                        }
                    }
                    if (vals != null)
                        req.setExtData(IRequest.CMC_SENDERNONCE, vals);

                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_regInfo)) {
                    // what can we do here
                    // for verisign, we just debug.print()
                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_identification)) {
                    // what can we do here
                    // for verisign, we just debug.print()
                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_identityProof)) {
                    // what can we do here
                    // for verisign, we just debug.print()
                }
            }

            req.setExtData(IRequest.CMC_REQIDS, reqIdArray);
            return certInfoArray;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CMC_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CMC_TO_CERTINFO_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CMC_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CMC_TO_CERTINFO_ERROR"));
        } catch (InvalidBERException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CMC_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CMC_TO_CERTINFO_ERROR"));
        } catch (InvalidKeyException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CMC_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CMC_TO_CERTINFO_ERROR"));
        } catch (Exception e) {
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CMC_ERROR", e.toString()));
        }

    }

}
