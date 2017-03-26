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
package com.netscape.cms.profile.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Random;
import java.util.StringTokenizer;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.pkcs10.CertificationRequest;
import org.mozilla.jss.pkcs10.CertificationRequestInfo;
import org.mozilla.jss.pkix.cmc.DecryptedPOP;
import org.mozilla.jss.pkix.cmc.IdentityProofV2;
import org.mozilla.jss.pkix.cmc.LraPopWitness;
import org.mozilla.jss.pkix.cmc.OtherMsg;
import org.mozilla.jss.pkix.cmc.PKIData;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cmc.TaggedCertificationRequest;
import org.mozilla.jss.pkix.cmc.TaggedRequest;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.HMACDigest;

import netscape.security.pkcs.PKCS10;
import netscape.security.pkcs.PKCS10Attribute;
import netscape.security.pkcs.PKCS10Attributes;
import netscape.security.pkcs.PKCS9Attribute;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateIssuerName;
import netscape.security.x509.CertificateSerialNumber;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.Extension;
import netscape.security.x509.Extensions;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

/**
 * This class implements a generic enrollment profile.
 *
 * @version $Revision$, $Date$
 */
public abstract class EnrollProfile extends BasicProfile
        implements IEnrollProfile {

    private final static String LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST =
            "LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST_5";
    private final static String LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION =
            "LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION_2";

    private PKIData mCMCData;

    public EnrollProfile() {
        super();
    }

    public abstract IAuthority getAuthority();

    public IRequestQueue getRequestQueue() {
        IAuthority authority = getAuthority();

        return authority.getRequestQueue();
    }

    public IProfileContext createContext() {
        return new ProfileContext();
    }

    /**
     * Creates request.
     */
    public IRequest[] createRequests(IProfileContext ctx, Locale locale)
            throws EProfileException {
        // determine how many requests should be created
        String cert_request_type = ctx.get(CTX_CERT_REQUEST_TYPE);
        String cert_request = ctx.get(CTX_CERT_REQUEST);
        String is_renewal = ctx.get(CTX_RENEWAL);
        Integer renewal_seq_num = 0;

        /* cert_request_type can be null for the case of CMC */
        if (cert_request_type == null) {
            CMS.debug("EnrollProfile: request type is null");
        }

        int num_requests = 1; // default to 1 request

        if (cert_request_type != null && cert_request_type.startsWith("pkcs10")) {
            // catch for invalid request
            parsePKCS10(locale, cert_request);
        }
        if (cert_request_type != null && cert_request_type.startsWith("crmf")) {
            CertReqMsg msgs[] = parseCRMF(locale, cert_request);

            num_requests = msgs.length;
        }
        TaggedRequest[] cmc_msgs = null;
        if (cert_request_type != null && cert_request_type.startsWith("cmc")) {
            /*
             * TODO: cfu: Phase 2: check if CMCAuth pre-signed request passed.
             *     if not, identityProofV2 and/or identification controls
             *     are required;
             */
            // catch for invalid request
            cmc_msgs = parseCMC(locale, cert_request);
            if (cmc_msgs == null)
                return null;
            else
                num_requests = cmc_msgs.length;
        }

        // only 1 request for renewal
        if ((is_renewal != null) && (is_renewal.equals("true"))) {
            num_requests = 1;
            String renewal_seq_num_str = ctx.get(CTX_RENEWAL_SEQ_NUM);
            if (renewal_seq_num_str != null) {
                renewal_seq_num = Integer.parseInt(renewal_seq_num_str);
            } else {
                renewal_seq_num = 0;
            }
        }

        // populate requests with appropriate content
        IRequest result[] = new IRequest[num_requests];

        for (int i = 0; i < num_requests; i++) {
            result[i] = createEnrollmentRequest();
            if ((is_renewal != null) && (is_renewal.equals("true"))) {
                result[i].setExtData(REQUEST_SEQ_NUM, renewal_seq_num);
            } else {
                result[i].setExtData(REQUEST_SEQ_NUM, Integer.valueOf(i));
                if ((cmc_msgs != null) && (cmc_msgs[i] != null)) {
                    CMS.debug("EnrollProfile: createRequests: setting cmc TaggedRequest in request");
                    result[i].setExtData(
                            CTX_CERT_REQUEST,
                            ASN1Util.encode(cmc_msgs[i]));
                }
            }
            if (locale != null) {
                result[i].setExtData(REQUEST_LOCALE, locale.getLanguage());
            }

            // set requested CA
            result[i].setExtData(IRequest.AUTHORITY_ID, ctx.get(REQUEST_AUTHORITY_ID));
        }
        return result;
    }

    public abstract X500Name getIssuerName();

    public void setDefaultCertInfo(IRequest req) throws EProfileException {
        // create an empty certificate template so that
        // default plugins that store stuff
        X509CertInfo info = new X509CertInfo();

        // retrieve issuer name
        X500Name issuerName = getIssuerName();

        byte[] dummykey = new byte[] {
                48, 92, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5,
                0, 3, 75, 0, 48, 72, 2, 65, 0, -65, 121, -119, -59, 105, 66,
                -122, -78, -30, -64, 63, -47, 44, -48, -104, 103, -47, -108,
                42, -38, 46, -8, 32, 49, -29, -26, -112, -29, -86, 71, 24,
                -104, 78, -31, -75, -128, 90, -92, -34, -51, -125, -13, 80, 101,
                -78, 39, -119, -38, 117, 28, 67, -19, -71, -124, -85, 105, -53,
                -103, -59, -67, -38, -83, 118, 65, 2, 3, 1, 0, 1 };
        // default values into x509 certinfo. This thing is
        // not serializable by default
        try {
            info.set(X509CertInfo.VERSION,
                    new CertificateVersion(CertificateVersion.V3));
            info.set(X509CertInfo.SERIAL_NUMBER,
                    new CertificateSerialNumber(new BigInteger("0")));
            ICertificateAuthority authority =
                    (ICertificateAuthority) getAuthority();
            if (authority.getIssuerObj() != null) {
                // this ensures the isserDN has the same encoding as the
                // subjectDN of the CA signing cert
                CMS.debug("EnrollProfile: setDefaultCertInfo: setting issuerDN using exact CA signing cert subjectDN encoding");
                info.set(X509CertInfo.ISSUER,
                        authority.getIssuerObj());
            } else {
                CMS.debug("EnrollProfile: setDefaultCertInfo: authority.getIssuerObj() is null, creating new CertificateIssuerName");
                info.set(X509CertInfo.ISSUER,
                        new CertificateIssuerName(issuerName));
            }
            info.set(X509CertInfo.KEY,
                    new CertificateX509Key(X509Key.parse(new DerValue(dummykey))));
            info.set(X509CertInfo.SUBJECT,
                    new CertificateSubjectName(new X500Name("CN=Dummy Subject Name")));
            info.set(X509CertInfo.VALIDITY,
                    new CertificateValidity(new Date(), new Date()));
            info.set(X509CertInfo.ALGORITHM_ID,
                    new CertificateAlgorithmId(AlgorithmId.get("MD5withRSA")));

            // add default extension container
            info.set(X509CertInfo.EXTENSIONS,
                    new CertificateExtensions());
        } catch (Exception e) {
            // throw exception - add key to template
            CMS.debug("EnrollProfile: Unable to create X509CertInfo: " + e);
            CMS.debug(e);
            throw new EProfileException(e);
        }
        req.setExtData(REQUEST_CERTINFO, info);
    }

    public IRequest createEnrollmentRequest()
            throws EProfileException {
        IRequest req = null;

        try {
            req = getRequestQueue().newRequest("enrollment");

            setDefaultCertInfo(req);

            // put the certificate info into request
            req.setExtData(REQUEST_EXTENSIONS,
                    new CertificateExtensions());

            CMS.debug("EnrollProfile: createRequest " +
                    req.getRequestId());
        } catch (EBaseException e) {
            // raise exception?
            CMS.debug("EnrollProfile: Unable to create enrollment request: " + e);
            CMS.debug(e);
        }

        return req;
    }

    public abstract void execute(IRequest request)
            throws EProfileException;

    /**
     * Perform simple policy set assignment.
     */
    public String getPolicySetId(IRequest req) {
        Integer seq = req.getExtDataInInteger(REQUEST_SEQ_NUM);
        int seq_no = seq.intValue(); // start from 0

        int count = 0;
        Enumeration<String> setIds = getProfilePolicySetIds();

        while (setIds.hasMoreElements()) {
            String setId = setIds.nextElement();

            if (count == seq_no) {
                return setId;
            }
            count++;
        }
        return null;
    }

    public String getRequestorDN(IRequest request) {
        X509CertInfo info = request.getExtDataInCertInfo(REQUEST_CERTINFO);

        try {
            CertificateSubjectName sn = (CertificateSubjectName)
                    info.get(X509CertInfo.SUBJECT);

            return sn.toString();
        } catch (Exception e) {
            CMS.debug("EnrollProfile: Unable to get requestor DN: " + e);
            CMS.debug(e);
        }
        return null;
    }

    /**
     * setPOPchallenge generates a POP challenge and sets necessary info in request
     * for composing encryptedPOP later
     *
     * @param IRequest the request
     * @author cfu
     */
    public void setPOPchallenge(IRequest req) throws EBaseException {
        String method = "EnrollProfile: setPOPchallenge: ";
        String msg = "";

        CMS.debug(method + " getting user public key in request");
        if (req == null) {
            CMS.debug(method + "method parameters cannot be null");
            throw new EBaseException(method + msg);
        }
        byte[] req_key_data = req.getExtDataInByteArray(IEnrollProfile.REQUEST_KEY);
        netscape.security.x509.CertificateX509Key pubKey = null;
        if (req_key_data != null) {
            CMS.debug(method + "found user public key in request");

            // generate a challenge of 64 bytes;
            Random random = new Random();
            byte[] challenge = new byte[64];
            random.nextBytes(challenge);

            ICertificateAuthority authority = (ICertificateAuthority) getAuthority();
            PublicKey issuanceProtPubKey = authority.getIssuanceProtPubKey();
            if (issuanceProtPubKey != null)
                CMS.debug(method + "issuanceProtPubKey not null");
            else {
                msg = method + "issuanceProtPubKey null";
                CMS.debug(msg);
                throw new EBaseException(method + msg);
            }

            try {
                CryptoToken token = null;
                String tokenName = CMS.getConfigStore().getString("cmc.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                token = CryptoUtil.getCryptoToken(tokenName);

                PublicKey userPubKey = X509Key.parsePublicKey(new DerValue(req_key_data));
                if (userPubKey == null) {
                    msg = method + "userPubKey null after X509Key.parsePublicKey";
                    CMS.debug(msg);
                    throw new EBaseException(msg);
                }

                SymmetricKey symKey = CryptoUtil.generateKey(token);
                byte[] pop_encreyptedData = CryptoUtil.encryptUsingSymmetricKey(
                        token, symKey, challenge);
                if (pop_encreyptedData == null) {
                    msg = method + "pop_encreyptedData null";
                    CMS.debug(msg);
                    throw new EBaseException(msg);
                }

                byte[] pop_sysPubEncreyptedSession = CryptoUtil.wrapUsingPublicKey(
                        token, issuanceProtPubKey, symKey);
                if (pop_sysPubEncreyptedSession == null) {
                    msg = method + "pop_sysPubEncreyptedSession null";
                    CMS.debug(msg);
                    throw new EBaseException(msg);
                }

                byte[] pop_userPubEncreyptedSession = CryptoUtil.wrapUsingPublicKey(
                        token, userPubKey, symKey);
                if (pop_userPubEncreyptedSession == null) {
                    msg = method + "pop_userPubEncreyptedSession null";
                    CMS.debug(msg);
                    throw new EBaseException(msg);
                }
                CMS.debug(method + "POP challenge fields generated successfully...setting request extData");

                req.setExtData("pop_encreyptedData", pop_encreyptedData);

                req.setExtData("pop_sysPubEncreyptedSession", pop_sysPubEncreyptedSession);

                req.setExtData("pop_userPubEncreyptedSession", pop_userPubEncreyptedSession);

                // now compute and set witness
                CMS.debug(method + "now compute and set witness");
                String hashName = CryptoUtil.getDefaultHashAlgName();
                CMS.debug(method + "hashName is " + hashName);
                MessageDigest hash = MessageDigest.getInstance(hashName);
                byte[] witness = hash.digest(challenge);
                req.setExtData("pop_witness", witness);

            } catch (Exception e) {
                CMS.debug(method + e);
                throw new EBaseException(e.toString());
            }

        } else {
            CMS.debug(method + " public key not found in request");
            throw new EBaseException(method + " public key not found in request");
        }
    }

    /**
     * This method is called after the user submits the
     * request from the end-entity page.
     */
    public void submit(IAuthToken token, IRequest request)
            throws EDeferException, EProfileException {
        // Request Submission Logic:
        //
        // if (Authentication Failed) {
        //   return Error
        // } else {
        //   if (No Auth Token) {
        //     queue request
        //   } else {
        //     process request
        //   }
        // }
        String method = "EnrollProfile: submit: ";

        IRequestQueue queue = getRequestQueue();
        String msg = "";

        boolean popChallengeRequired =
                request.getExtDataInBoolean("cmc_POPchallengeRequired", false);
        CMS.debug(method + "popChallengeRequired =" + popChallengeRequired);

        // this profile queues request that is authenticated
        // by NoAuth
        try {
            queue.updateRequest(request);
        } catch (EBaseException e) {
            // save request to disk
            CMS.debug(method + " Unable to update request: " + e);
            CMS.debug(e);
        }

        if (token == null){
            CMS.debug(method + " auth token is null");
            CMS.debug(method + " validating request");
            validate(request);
            try {
                queue.updateRequest(request);
            } catch (EBaseException e) {
                msg = method + " Unable to update request after validation: " + e;
                CMS.debug(msg);
                throw new EProfileException(msg);
            }
            throw new EDeferException("defer request");
        } else if (popChallengeRequired) {
            // this is encryptedPOP case; defer to require decryptedPOP
            CMS.debug(method + " popChallengeRequired, defer to enforce decryptedPOP");
            validate(request);
            CMS.debug(method + " about to call setPOPchallenge");
            try {
                setPOPchallenge(request);
                queue.updateRequest(request);
            } catch (EBaseException e) {
                msg = method + e;
                CMS.debug(msg);
                throw new EProfileException(msg);
            }

            throw new EDeferException("EnrollProfile: submit: encryptedPOP defer request");

        } else {
            // this profile executes request that is authenticated
            // by non NoAuth
            CMS.debug(method + " auth token is not null");
            validate(request);
            execute(request);
        }
    }

    public TaggedRequest[] parseCMC(Locale locale, String certreq)
            throws EProfileException {

        String method = "EnrollProfile: parseCMC: ";
        String msg = ""; // for capturing debug and throw info

        /* cert request must not be null */
        if (certreq == null) {
            msg = method + "certreq null";
            CMS.debug(msg);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                            msg);
        }
        //CMS.debug(method + " Start parseCMC(): " + certreq);
        CMS.debug(method + "starts");

        TaggedRequest msgs[] = null;

        String creq = normalizeCertReq(certreq);
        try {
            byte data[] = CMS.AtoB(creq);
            ByteArrayInputStream cmcBlobIn =
                    new ByteArrayInputStream(data);

            org.mozilla.jss.pkix.cms.ContentInfo cmcReq = (org.mozilla.jss.pkix.cms.ContentInfo)
                    org.mozilla.jss.pkix.cms.ContentInfo.getTemplate().decode(cmcBlobIn);
            org.mozilla.jss.pkix.cms.SignedData cmcFullReq =
                (org.mozilla.jss.pkix.cms.SignedData) cmcReq.getInterpretedContent();
            org.mozilla.jss.pkix.cms.EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();
            OCTET_STRING content = ci.getContent();

            ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
            PKIData pkiData = (PKIData) (new PKIData.Template()).decode(s);

            mCMCData = pkiData;
            //PKIData pkiData = (PKIData)
            //    (new PKIData.Template()).decode(cmcBlobIn);
            SEQUENCE controlSeq = pkiData.getControlSequence();
            int numcontrols = controlSeq.size();
            SEQUENCE reqSeq = pkiData.getReqSequence();
            byte randomSeed[] = null;
            SessionContext context = SessionContext.getContext();
            if (!context.containsKey("numOfControls")) {
                if (numcontrols > 0) {
                    context.put("numOfControls", Integer.valueOf(numcontrols));
                    TaggedAttribute[] attributes = new TaggedAttribute[numcontrols];
                    boolean id_cmc_decryptedPOP = false;
                    SET decPopVals = null;

                    boolean id_cmc_identification = false;
                    SET ident = null;

                    boolean id_cmc_identityProofV2 = false;
                    boolean id_cmc_identityProof = false;
                    TaggedAttribute attr = null;

                    boolean id_cmc_idPOPLinkRandom = false;
                    SET vals = null;

                    for (int i = 0; i < numcontrols; i++) {
                        attributes[i] = (TaggedAttribute) controlSeq.elementAt(i);
                        OBJECT_IDENTIFIER oid = attributes[i].getType();
                        if (oid.equals(OBJECT_IDENTIFIER.id_cmc_decryptedPOP)) {
                            CMS.debug(method + " decryptedPOP found");
                            id_cmc_decryptedPOP = true;
                            decPopVals = attributes[i].getValues();
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_identification)) {
                            id_cmc_identification = true;
                            ident = attributes[i].getValues();
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_identityProofV2)) {
                            id_cmc_identityProofV2 = true;
                            attr = attributes[i];
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_identityProof)) {
                            id_cmc_identityProof = true;
                            attr = attributes[i];
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_idPOPLinkRandom)) {
                            id_cmc_idPOPLinkRandom = true;
                            vals = attributes[i].getValues();
                        } else {
                            context.put(attributes[i].getType(), attributes[i]);
                        }
                    } //for

                    /**
                     * now do the actual control processing
                     * (the postponed processing is so that we can capture
                     * the identification, if included)
                     */

                    if (id_cmc_decryptedPOP) {
                        if (decPopVals != null) {

                            DecryptedPOP decPop = (DecryptedPOP) (ASN1Util.decode(DecryptedPOP.getTemplate(),
                                    ASN1Util.encode(decPopVals.elementAt(0))));
                            CMS.debug(method + "DecryptedPOP encoded");

                            Integer reqId = verifyDecryptedPOP(locale, decPop);
                            if (reqId != null) {
                                context.put("decryptedPopReqId", reqId);
                            }
                        } else { //decPopVals == null
                            msg = "id_cmc_decryptedPOP contains invalid DecryptedPOP";
                            CMS.debug(method + msg);
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("decryptedPOP", bpids);
                        }
                        return null;
                    }

                    UTF8String ident_s = null;
                    if (id_cmc_identification) {
                        if (ident == null) {
                            msg = "id_cmc_identification contains null attribute value";
                            CMS.debug(method + msg);
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identification", bpids);
                            return null;
                        }
                        ident_s = (UTF8String) (ASN1Util.decode(UTF8String.getTemplate(),
                                ASN1Util.encode(ident.elementAt(0))));
                        if (ident_s == null) {
                            msg = "id_cmc_identification contains invalid content";
                            CMS.debug(method + msg);
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identification", bpids);
                            return null;
                        }
                    }

                    // either V2 or not V2; can't be both
                    if (id_cmc_identityProofV2 && (attr != null)) {
                        if (!id_cmc_identification) {
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identification", bpids);
                            msg = "id_cmc_identityProofV2 must be accompanied by id_cmc_identification in this server";
                            CMS.debug(method + msg);
                            throw new EProfileException(
                                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                                            msg);
                        }

                        boolean valid = verifyIdentityProofV2(attr, ident_s,
                                reqSeq);
                        if (!valid) {
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identityProofV2", bpids);
                            return null;
                        }
                    } else if (id_cmc_identityProof && (attr != null)) {
                        boolean valid = verifyIdentityProof(attr,
                                reqSeq);
                        if (!valid) {
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identityProof", bpids);
                            return null;
                        }
                    }

                    if (id_cmc_idPOPLinkRandom && vals != null) {
                        OCTET_STRING ostr = (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                                ASN1Util.encode(vals.elementAt(0))));
                        randomSeed = ostr.toByteArray();
                    }
                } // numcontrols > 0
            }

            SEQUENCE otherMsgSeq = pkiData.getOtherMsgSequence();
            int numOtherMsgs = otherMsgSeq.size();
            if (!context.containsKey("numOfOtherMsgs")) {
                context.put("numOfOtherMsgs", Integer.valueOf(numOtherMsgs));
                for (int i = 0; i < numOtherMsgs; i++) {
                    OtherMsg omsg = (OtherMsg) (ASN1Util.decode(OtherMsg.getTemplate(),
                            ASN1Util.encode(otherMsgSeq.elementAt(i))));
                    context.put("otherMsg" + i, omsg);
                }
            }

            int nummsgs = reqSeq.size();
            if (nummsgs > 0) {
                msgs = new TaggedRequest[reqSeq.size()];
                SEQUENCE bpids = new SEQUENCE();
                boolean valid = true;
                for (int i = 0; i < nummsgs; i++) {
                    msgs[i] = (TaggedRequest) reqSeq.elementAt(i);
                    if (!context.containsKey("POPLinkWitness")) {
                        if (randomSeed != null) {
                            valid = verifyPOPLinkWitness(randomSeed, msgs[i], bpids);
                            if (!valid || bpids.size() > 0) {
                                context.put("POPLinkWitness", bpids);
                                return null;
                            }
                        }
                    }
                }
            } else
                return null;

            CMS.debug(method + "ends");
            return msgs;
        } catch (Exception e) {
            CMS.debug(method + "Unable to parse CMC request: " + e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
    }

    /**
     * verifyDecryptedPOP verifies the POP challenge provided in
     * DecryptedPOP and returns the matching requestID
     *
     * @author cfu
     */
    private Integer verifyDecryptedPOP(Locale locale, DecryptedPOP decPop)
            throws EProfileException {
        String method = "EnrollProfile: verifyDecryptedPOP: ";
        CMS.debug(method + "begins");
        String msg = "";

        if (decPop == null) {
            CMS.debug(method + "method parameters cannot be null");
            return null;
        }

        // iBody contains the request id
        INTEGER iBody = decPop.getBodyPartID();
        if (iBody == null) {
            msg = method + "iBody null after decPop.getBodyPartID";
            CMS.debug(msg);
            return null;
        }
        CMS.debug(method + "request id from decryptedPOP =" +
                iBody.toString());
        Integer reqId = new Integer(iBody.toString());

        OCTET_STRING witness_os = decPop.getWitness();

        IRequestQueue reqQueue = getRequestQueue();
        IRequest req = null;
        try {
            req = reqQueue.findRequest(new RequestId(reqId));
        } catch (Exception e) {
            msg = method + "after findRequest: " + e;
            CMS.debug(msg);
            return null;
        }

        // now verify the POP witness
        byte[] pop_encreyptedData = req.getExtDataInByteArray("pop_encreyptedData");
        if (pop_encreyptedData == null) {
            msg = method +
                    "pop_encreyptedData not found in request:" +
                    reqId.toString();
            CMS.debug(msg);
            return null;
        }

        byte[] pop_sysPubEncreyptedSession = req.getExtDataInByteArray("pop_sysPubEncreyptedSession");
        if (pop_sysPubEncreyptedSession == null) {
            msg = method +
                    "pop_sysPubEncreyptedSession not found in request:" +
                    reqId.toString();
            CMS.debug(msg);
            return null;
        }

        byte[] cmc_msg = req.getExtDataInByteArray(IEnrollProfile.CTX_CERT_REQUEST);
        if (pop_sysPubEncreyptedSession == null) {
            msg = method +
                    "pop_sysPubEncreyptedSession not found in request:" +
                    reqId.toString();
            CMS.debug(msg);
            return null;
        }

        ICertificateAuthority authority = (ICertificateAuthority) getAuthority();
        PrivateKey issuanceProtPrivKey = authority.getIssuanceProtPrivKey();
        if (issuanceProtPrivKey != null)
            CMS.debug(method + "issuanceProtPrivKey not null");
        else {
            msg = method + "issuanceProtPrivKey null";
            CMS.debug(msg);
            return null;
        }

        try {
            CryptoToken token = null;
            String tokenName = CMS.getConfigStore().getString("cmc.token", CryptoUtil.INTERNAL_TOKEN_NAME);
            token = CryptoUtil.getKeyStorageToken(tokenName);

            SymmetricKey symKey = CryptoUtil.unwrap(
                    token,
                    SymmetricKey.Usage.DECRYPT,
                    issuanceProtPrivKey,
                    pop_sysPubEncreyptedSession);
            if (symKey == null) {
                msg = "symKey null after CryptoUtil.unwrap returned";
                CMS.debug(msg);
                return null;
            }

            byte[] challenge_b = CryptoUtil.decryptUsingSymmetricKey(
                    token, pop_encreyptedData, symKey);
            if (challenge_b == null) {
                msg = method + "challenge_b null after decryptUsingSymmetricKey returned";
                CMS.debug(msg);
                return null;
            }

            MessageDigest digest = MessageDigest.getInstance(CryptoUtil.getDefaultHashAlgName());
            if (digest == null) {
                msg = method + "digest null after decryptUsingSymmetricKey returned";
                CMS.debug(msg);
                return null;
            }
            HMACDigest hmacDigest = new HMACDigest(digest, challenge_b);
            hmacDigest.update(cmc_msg);
            byte[] proofValue = hmacDigest.digest();
            if (proofValue == null) {
                msg = method + "proofValue null after hmacDigest.digest returned";
                CMS.debug(msg);
                return null;
            }
            boolean witnessChecked = Arrays.equals(proofValue, witness_os.toByteArray());
            if (!witnessChecked) {
                msg = method + "POP challenge witness verification failure";
                CMS.debug(msg);
                return null;
            }
        } catch (Exception e) {
            msg = method + e;
            CMS.debug(msg);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                            e);
        }

        CMS.debug(method + "POP challenge verified!");
        req.setExtData("cmc_POPchallengeRequired", "false");

        CMS.debug(method + "cmc_POPchallengeRequired set back to false");
        CMS.debug(method + "ends");

        return reqId;
    }

    private boolean verifyPOPLinkWitness(byte[] randomSeed, TaggedRequest req,
            SEQUENCE bpids) {
        ISharedToken tokenClass = null;
        boolean sharedSecretFound = true;
        String name = null;
        try {
            name = CMS.getConfigStore().getString("cmc.sharedSecret.class");
        } catch (EPropertyNotFound e) {
            CMS.debug("EnrollProfile: Failed to find the token class in the configuration file.");
            sharedSecretFound = false;
        } catch (EBaseException e) {
            CMS.debug("EnrollProfile: Failed to find the token class in the configuration file.");
            sharedSecretFound = false;
        }

        try {
            tokenClass = (ISharedToken) Class.forName(name).newInstance();
        } catch (ClassNotFoundException e) {
            CMS.debug("EnrollProfile: Failed to find class name: " + name);
            sharedSecretFound = false;
        } catch (InstantiationException e) {
            CMS.debug("EnrollProfile: Failed to instantiate class: " + name);
            sharedSecretFound = false;
        } catch (IllegalAccessException e) {
            CMS.debug("EnrollProfile: Illegal access: " + name);
            sharedSecretFound = false;
        }

        INTEGER reqId = null;
        byte[] bv = null;
        String sharedSecret = null;
        if (tokenClass != null)
            sharedSecret = tokenClass.getSharedToken(mCMCData);
        if (req.getType().equals(TaggedRequest.PKCS10)) {
            TaggedCertificationRequest tcr = req.getTcr();
            if (!sharedSecretFound) {
                bpids.addElement(tcr.getBodyPartID());
                return false;
            } else {
                CertificationRequest creq = tcr.getCertificationRequest();
                CertificationRequestInfo cinfo = creq.getInfo();
                SET attrs = cinfo.getAttributes();
                for (int j = 0; j < attrs.size(); j++) {
                    Attribute pkcs10Attr = (Attribute) attrs.elementAt(j);
                    if (pkcs10Attr.getType().equals(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness)) {
                        SET witnessVal = pkcs10Attr.getValues();
                        if (witnessVal.size() > 0) {
                            try {
                                OCTET_STRING str =
                                        (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                                                ASN1Util.encode(witnessVal.elementAt(0))));
                                bv = str.toByteArray();
                                return verifyDigest(sharedSecret.getBytes(),
                                        randomSeed, bv);
                            } catch (InvalidBERException ex) {
                                return false;
                            }
                        }
                    }
                }

                return false;
            }
        } else if (req.getType().equals(TaggedRequest.CRMF)) {
            CertReqMsg crm = req.getCrm();
            CertRequest certReq = crm.getCertReq();
            reqId = certReq.getCertReqId();
            if (!sharedSecretFound) {
                bpids.addElement(reqId);
                return false;
            } else {
                for (int i = 0; i < certReq.numControls(); i++) {
                    AVA ava = certReq.controlAt(i);

                    if (ava.getOID().equals(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness)) {
                        ASN1Value value = ava.getValue();
                        ByteArrayInputStream bis = new ByteArrayInputStream(
                                ASN1Util.encode(value));
                        OCTET_STRING ostr = null;
                        try {
                            ostr = (OCTET_STRING)
                                    (new OCTET_STRING.Template()).decode(bis);
                            bv = ostr.toByteArray();
                        } catch (Exception e) {
                            bpids.addElement(reqId);
                            return false;
                        }

                        boolean valid = verifyDigest(sharedSecret.getBytes(),
                                randomSeed, bv);
                        if (!valid) {
                            bpids.addElement(reqId);
                            return valid;
                        }
                    }
                }
            }
        }

        return true;
    }

    private boolean verifyDigest(byte[] sharedSecret, byte[] text, byte[] bv) {
        MessageDigest hashAlg;
        try {
            hashAlg = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException ex) {
            CMS.debug("EnrollProfile:verifyDigest: " + ex.toString());
            return false;
        }

        return verifyDigest(sharedSecret, text, bv, hashAlg, hashAlg);
    }

    /**
     * verifyDigest verifies digest using the
     * specified hashAlg and macAlg
     *
     * @param sharedSecret shared secret in bytes
     * @param text data to be verified in bytes
     * @param bv witness in bytes
     * @param hashAlg hashing algorithm
     * @param macAlg message authentication algorithm
     * cfu
     */
    private boolean verifyDigest(byte[] sharedSecret, byte[] text, byte[] bv,
            MessageDigest hashAlg, MessageDigest macAlg) {
        String method = "EnrollProfile:verifyDigest: ";
        byte[] key = null;
        CMS.debug(method + "in verifyDigest: hashAlg=" + hashAlg.toString() +
                "; macAlg=" + macAlg.toString());

        if ((sharedSecret == null) ||
            (text == null) ||
            (bv == null) ||
            (hashAlg == null) ||
            (macAlg == null)) {
            CMS.debug(method + "method parameters cannot be null");
            return false;
        }
        key = hashAlg.digest(sharedSecret);

        byte[] finalDigest = null;
        HMACDigest hmacDigest = new HMACDigest(macAlg, key);
        hmacDigest.update(text);
        if (hmacDigest == null) {
            CMS.debug(method + " hmacDigest null after hmacDigest.update");
            return false;
        }
        finalDigest = hmacDigest.digest();

        if (finalDigest.length != bv.length) {
            CMS.debug(method + " The length of two HMAC digest are not the same.");
            return false;
        }

        for (int j = 0; j < bv.length; j++) {
            if (bv[j] != finalDigest[j]) {
                CMS.debug(method + " The content of two HMAC digest are not the same.");
                return false;
            }
        }

        CMS.debug(method + " The content of two HMAC digest are the same.");
        return true;
    }

    private SEQUENCE getRequestBpids(SEQUENCE reqSeq) {
        SEQUENCE bpids = new SEQUENCE();
        for (int i = 0; i < reqSeq.size(); i++) {
            TaggedRequest req = (TaggedRequest) reqSeq.elementAt(i);
            if (req.getType().equals(TaggedRequest.PKCS10)) {
                TaggedCertificationRequest tcr = req.getTcr();
                bpids.addElement(tcr.getBodyPartID());
            } else if (req.getType().equals(TaggedRequest.CRMF)) {
                CertReqMsg crm = req.getCrm();
                CertRequest request = crm.getCertReq();
                bpids.addElement(request.getCertReqId());
            }
        }

        return bpids;
    }

    /**
     * verifyIdentityProofV2 handles IdentityProofV2 as defined by RFC5272
     *
     * @param attr controlSequence of the PKI request PKIData
     * @param ident value of the id_cmc_identification control
     * @param reqSeq requestSequence of the PKI request PKIData
     * @return boolean true if the witness values correctly verified
     * @author cfu
     */
    private boolean verifyIdentityProofV2(
            TaggedAttribute attr,
            UTF8String ident,
            SEQUENCE reqSeq) {
        String method = "EnrollProfile:verifyIdentityProofV2: ";
        CMS.debug(method + " begins");
        if ((attr == null) ||
                (ident == null) ||
                (reqSeq == null)) {
            CMS.debug(method + "method parameters cannot be null");
            return false;
        }

        String ident_string = ident.toString();

        SET vals = attr.getValues(); // getting the IdentityProofV2 structure
        if (vals.size() < 1) {
            return false;
        }

        String name = null;
        try {
            String configName = "cmc.sharedSecret.class";
            CMS.debug(method + "getting :" + configName);
            name = CMS.getConfigStore().getString(configName);
            CMS.debug(method + "Shared Secret plugin class name retrieved:" +
                    name);
        } catch (Exception e) {
            CMS.debug(method + " Failed to retrieve shared secret plugin class name");
            return false;
        }

        ISharedToken tokenClass = null;
        try {
            tokenClass = (ISharedToken) Class.forName(name).newInstance();
            CMS.debug(method + "Shared Secret plugin class retrieved");
        } catch (ClassNotFoundException e) {
            CMS.debug(method + " Failed to find class name: " + name);
            return false;
        } catch (InstantiationException e) {
            CMS.debug("EnrollProfile: Failed to instantiate class: " + name);
            return false;
        } catch (IllegalAccessException e) {
            CMS.debug(method + " Illegal access: " + name);
            return false;
        }
        if (tokenClass == null) {
            CMS.debug(method + " Failed to retrieve shared secret plugin class");
            return false;
        }

        String token = null;
        if (ident_string != null)
            token = tokenClass.getSharedToken(ident_string);
        else
            token = tokenClass.getSharedToken(mCMCData);

        if (token == null) {
            CMS.debug(method + " Failed to retrieve shared secret");
            return false;
        }

        // CMS.debug(method + "Shared Secret returned by tokenClass:" + token);
        try {
            IdentityProofV2 idV2val = (IdentityProofV2) (ASN1Util.decode(IdentityProofV2.getTemplate(),
                    ASN1Util.encode(vals.elementAt(0))));
            /**
             * TODO: cfu:
             * phase2: getting configurable allowable hashing and mac algorithms
             */

            DigestAlgorithm hashAlgID = DigestAlgorithm.fromOID(idV2val.getHashAlgID().getOID());
            MessageDigest hashAlg = MessageDigest.getInstance(hashAlgID.toString());
            // TODO: check against CA allowed algs later

            HMACAlgorithm macAlgId = HMACAlgorithm.fromOID(idV2val.getMacAlgId().getOID());
            MessageDigest macAlg = MessageDigest
                    .getInstance(CryptoUtil.getHMACtoMessageDigestName(macAlgId.toString()));
            // TODO: check against CA allowed algs later

            OCTET_STRING witness = idV2val.getWitness();
            if (witness == null) {
                CMS.debug(method + " witness reurned by idV2val.getWitness is null");
                return false;
            }

            byte[] witness_bytes = witness.toByteArray();
            byte[] request_bytes = ASN1Util.encode(reqSeq); // PKIData reqSequence field
            return verifyDigest(
                    (ident_string != null) ? (token + ident_string).getBytes() : token.getBytes(),
                    request_bytes,
                    witness_bytes,
                    hashAlg, macAlg);
        } catch (Exception e) {
            CMS.debug(method + " Failed with Exception: " + e.toString());
            return false;
        }

    } // verifyIdentityProofV2

    private boolean verifyIdentityProof(TaggedAttribute attr, SEQUENCE reqSeq) {
        SET vals = attr.getValues();
        if (vals.size() < 1)
            return false;
        String name = null;
        try {
            name = CMS.getConfigStore().getString("cmc.sharedSecret.class");
        } catch (EPropertyNotFound e) {
        } catch (EBaseException e) {
        }

        if (name == null)
            return false;
        else {
            ISharedToken tokenClass = null;
            try {
                tokenClass = (ISharedToken) Class.forName(name).newInstance();
            } catch (ClassNotFoundException e) {
                CMS.debug("EnrollProfile: Failed to find class name: " + name);
                return false;
            } catch (InstantiationException e) {
                CMS.debug("EnrollProfile: Failed to instantiate class: " + name);
                return false;
            } catch (IllegalAccessException e) {
                CMS.debug("EnrollProfile: Illegal access: " + name);
                return false;
            }

            String token = tokenClass.getSharedToken(mCMCData);
            OCTET_STRING ostr = null;
            try {
                ostr = (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                        ASN1Util.encode(vals.elementAt(0))));
            } catch (InvalidBERException e) {
                CMS.debug("EnrollProfile: Failed to decode the byte value.");
                return false;
            }
            byte[] b = ostr.toByteArray();
            byte[] text = ASN1Util.encode(reqSeq);

            return verifyDigest(token.getBytes(), text, b);
        }
    }

    public void fillTaggedRequest(Locale locale, TaggedRequest tagreq, X509CertInfo info,
            IRequest req)
            throws EProfileException {
        String method = "EnrollProfile: fillTaggedRequest: ";
        TaggedRequest.Type type = tagreq.getType();
        if (type == null) {
            CMS.debug(method + "TaggedRequest type == null");
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST")+
                    "TaggedRequest type null");
        }

        if (type.equals(TaggedRequest.PKCS10)) {
            CMS.debug(method + " TaggedRequest type == pkcs10");
            boolean sigver = true;
            boolean tokenSwitched = false;
            CryptoManager cm = null;
            CryptoToken signToken = null;
            CryptoToken savedToken = null;
            try {
                sigver = CMS.getConfigStore().getBoolean("ca.requestVerify.enabled", true);
                cm = CryptoManager.getInstance();
                if (sigver == true) {
                    String tokenName =
                        CMS.getConfigStore().getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                    savedToken = cm.getThreadToken();
                    signToken = CryptoUtil.getCryptoToken(tokenName);
                    if (!savedToken.getName().equals(signToken.getName())) {
                        cm.setThreadToken(signToken);
                        tokenSwitched = true;
                    }
                }

                TaggedCertificationRequest tcr = tagreq.getTcr();
                CertificationRequest p10 = tcr.getCertificationRequest();
                ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                p10.encode(ostream);
                PKCS10 pkcs10 = new PKCS10(ostream.toByteArray(), sigver);

                req.setExtData("bodyPartId", tcr.getBodyPartID());
                fillPKCS10(locale, pkcs10, info, req);
            } catch (Exception e) {
                CMS.debug(method + e);
            }  finally {
                if ((sigver == true) && (tokenSwitched == true)){
                    cm.setThreadToken(savedToken);
                }
            }
        } else if (type.equals(TaggedRequest.CRMF)) {
            CMS.debug(method + " TaggedRequest type == crmf");
            CertReqMsg crm = tagreq.getCrm();
            SessionContext context = SessionContext.getContext();
            Integer nums = (Integer) (context.get("numOfControls"));

            boolean verifyAllow = false; //disable RA by default
            try {
                String configName = "cmc.lraPopWitness.verify.allow";
                CMS.debug(method + "getting :" + configName);
                verifyAllow = CMS.getConfigStore().getBoolean(configName, false);
                CMS.debug(method + "cmc.lraPopWitness.verify.allow is " + verifyAllow);
            } catch (Exception e) {
                // unlikely to get here
                String msg = method + " Failed to retrieve cmc.lraPopWitness.verify.allow";
                CMS.debug(msg);
                throw new EProfileException(method + msg);
            }
            if (verifyAllow) {
                // check if the LRA POP Witness Control attribute exists
                if (nums != null && nums.intValue() > 0) {
                    TaggedAttribute attr = (TaggedAttribute) (context.get(OBJECT_IDENTIFIER.id_cmc_lraPOPWitness));
                    if (attr != null) {
                        parseLRAPopWitness(locale, crm, attr);
                    } else {
                        CMS.debug(
                                method + " verify POP in CMC because LRA POP Witness control attribute doesnt exist in the CMC request.");
                        if (crm.hasPop()) {
                            CMS.debug(method + " hasPop true");
                            verifyPOP(locale, crm);
                        } else { // no signing POP, then do it the hard way
                            CMS.debug(method + "hasPop false, need to challenge");
                            req.setExtData("cmc_POPchallengeRequired", "true");
                        }
                    }
                } else {
                    CMS.debug(
                            method + " verify POP in CMC because LRA POP Witness control attribute doesnt exist in the CMC request.");
                    if (crm.hasPop()) {
                        CMS.debug(method + " hasPop true");
                        verifyPOP(locale, crm);
                    } else { // no signing POP, then do it the hard way
                        CMS.debug(method + "hasPop false, need to challenge");
                        req.setExtData("cmc_POPchallengeRequired", "true");
                    }
                }

            } else { //!verifyAllow

                if (crm.hasPop()) {
                    CMS.debug(method + " hasPop true");
                    verifyPOP(locale, crm);
                } else { // no signing POP, then do it the hard way
                    CMS.debug(method + "hasPop false, need to challenge");
                    req.setExtData("cmc_POPchallengeRequired", "true");
                }
            }

            fillCertReqMsg(locale, crm, info, req);
        } else {
            CMS.debug(method + " unsupported type (not CRMF or PKCS10)");
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"));
        }
    }

    private void parseLRAPopWitness(Locale locale, CertReqMsg crm,
            TaggedAttribute attr) throws EProfileException {
        SET vals = attr.getValues();
        boolean donePOP = false;
        INTEGER reqId = null;
        if (vals.size() > 0) {
            LraPopWitness lraPop = null;
            try {
                lraPop = (LraPopWitness) (ASN1Util.decode(LraPopWitness.getTemplate(),
                        ASN1Util.encode(vals.elementAt(0))));
            } catch (InvalidBERException e) {
                CMS.debug("EnrollProfile: Unable to parse LRA POP Witness: " + e);
                CMS.debug(e);
                throw new EProfileException(
                        CMS.getUserMessage(locale, "CMS_PROFILE_ENCODING_ERROR"), e);
            }

            SEQUENCE bodyIds = lraPop.getBodyIds();
            reqId = crm.getCertReq().getCertReqId();

            for (int i = 0; i < bodyIds.size(); i++) {
                INTEGER num = (INTEGER) (bodyIds.elementAt(i));
                if (num.toString().equals(reqId.toString())) {
                    donePOP = true;
                    CMS.debug("EnrollProfile: skip POP for request: "
                            + reqId + " because LRA POP Witness control is found.");
                    break;
                }
            }
        }

        if (!donePOP) {
            CMS.debug("EnrollProfile: not skip POP for request: "
                    + reqId
                    + " because this request id is not part of the body list in LRA Pop witness control.");
            verifyPOP(locale, crm);
        }
    }

    public CertReqMsg[] parseCRMF(Locale locale, String certreq)
            throws EProfileException {

        /* cert request must not be null */
        if (certreq == null) {
            CMS.debug("EnrollProfile: parseCRMF() certreq null");
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"));
        }
        CMS.debug("EnrollProfile: Start parseCRMF(): "/* + certreq*/);

        CertReqMsg msgs[] = null;
        String creq = normalizeCertReq(certreq);
        try {
            byte data[] = CMS.AtoB(creq);
            ByteArrayInputStream crmfBlobIn =
                    new ByteArrayInputStream(data);
            SEQUENCE crmfMsgs = (SEQUENCE)
                    new SEQUENCE.OF_Template(new
                            CertReqMsg.Template()).decode(crmfBlobIn);
            int nummsgs = crmfMsgs.size();

            if (nummsgs <= 0)
                return null;
            msgs = new CertReqMsg[crmfMsgs.size()];
            for (int i = 0; i < nummsgs; i++) {
                msgs[i] = (CertReqMsg) crmfMsgs.elementAt(i);
            }
            return msgs;
        } catch (Exception e) {
            CMS.debug("EnrollProfile: Unable to parse CRMF request: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
    }

    private static final OBJECT_IDENTIFIER PKIARCHIVEOPTIONS_OID =
            new OBJECT_IDENTIFIER(new long[] { 1, 3, 6, 1, 5, 5, 7, 5, 1, 4 }
            );

    protected PKIArchiveOptions getPKIArchiveOptions(AVA ava) {
        ASN1Value archVal = ava.getValue();
        ByteArrayInputStream bis = new ByteArrayInputStream(
                ASN1Util.encode(archVal));
        PKIArchiveOptions archOpts = null;

        try {
            archOpts = (PKIArchiveOptions)
                    (new PKIArchiveOptions.Template()).decode(bis);
        } catch (Exception e) {
            CMS.debug("EnrollProfile: getPKIArchiveOptions " + e);
        }
        return archOpts;
    }

    public PKIArchiveOptions toPKIArchiveOptions(byte options[]) {
        ByteArrayInputStream bis = new ByteArrayInputStream(options);
        PKIArchiveOptions archOpts = null;

        try {
            archOpts = (PKIArchiveOptions)
                    (new PKIArchiveOptions.Template()).decode(bis);
        } catch (Exception e) {
            CMS.debug("EnrollProfile: toPKIArchiveOptions " + e);
        }
        return archOpts;
    }

    public byte[] toByteArray(PKIArchiveOptions options) {
        return ASN1Util.encode(options);
    }

    public void fillCertReqMsg(Locale locale, CertReqMsg certReqMsg, X509CertInfo info,
            IRequest req)
            throws EProfileException {
        try {
            CMS.debug("Start parseCertReqMsg ");
            CertRequest certReq = certReqMsg.getCertReq();
            req.setExtData("bodyPartId", certReq.getCertReqId());
            // handle PKIArchiveOption (key archival)
            for (int i = 0; i < certReq.numControls(); i++) {
                AVA ava = certReq.controlAt(i);

                if (ava.getOID().equals(PKIARCHIVEOPTIONS_OID)) {
                    PKIArchiveOptions opt = getPKIArchiveOptions(ava);

                    //req.set(REQUEST_ARCHIVE_OPTIONS, opt);
                    req.setExtData(REQUEST_ARCHIVE_OPTIONS,
                            toByteArray(opt));
                    try {
                        String transportCert = CMS.getConfigStore().getString("ca.connector.KRA.transportCert", "");
                        req.setExtData(IEnrollProfile.REQUEST_TRANSPORT_CERT, transportCert);
                    } catch (EBaseException ee) {
                        CMS.debug("EnrollProfile: fillCertReqMsg - Exception reading transportCert: "+ ee);
                    }
                }
            }

            CertTemplate certTemplate = certReq.getCertTemplate();

            // parse key
            SubjectPublicKeyInfo spki = certTemplate.getPublicKey();
            ByteArrayOutputStream keyout = new ByteArrayOutputStream();

            spki.encode(keyout);
            byte[] keybytes = keyout.toByteArray();
            X509Key key = new X509Key();

            key.decode(keybytes);

            // XXX - kmccarth - this may simply undo the decoding above
            //                  but for now it's unclear whether X509Key
            //                  changest the format when decoding.
            CertificateX509Key certKey = new CertificateX509Key(key);
            ByteArrayOutputStream certKeyOut = new ByteArrayOutputStream();
            certKey.encode(certKeyOut);
            req.setExtData(REQUEST_KEY, certKeyOut.toByteArray());

            // parse validity
            if (certTemplate.getNotBefore() != null ||
                    certTemplate.getNotAfter() != null) {
                CMS.debug("EnrollProfile:  requested notBefore: " + certTemplate.getNotBefore());
                CMS.debug("EnrollProfile:  requested notAfter:  " + certTemplate.getNotAfter());
                CMS.debug("EnrollProfile:  current CA time:     " + new Date());
                CertificateValidity certValidity = new CertificateValidity(
                        certTemplate.getNotBefore(), certTemplate.getNotAfter());
                ByteArrayOutputStream certValidityOut =
                        new ByteArrayOutputStream();
                certValidity.encode(certValidityOut);
                req.setExtData(REQUEST_VALIDITY, certValidityOut.toByteArray());
            } else {
                CMS.debug("EnrollProfile:  validity not supplied");
            }

            // parse subject
            if (certTemplate.hasSubject()) {
                Name subjectdn = certTemplate.getSubject();
                ByteArrayOutputStream subjectEncStream =
                        new ByteArrayOutputStream();

                subjectdn.encode(subjectEncStream);
                byte[] subjectEnc = subjectEncStream.toByteArray();
                X500Name subject = new X500Name(subjectEnc);

                //info.set(X509CertInfo.SUBJECT,
                //  new CertificateSubjectName(subject));

                req.setExtData(REQUEST_SUBJECT_NAME,
                        new CertificateSubjectName(subject));
                try {
                    String subjectCN = subject.getCommonName();
                    if (subjectCN == null)
                        subjectCN = "";
                    req.setExtData(REQUEST_SUBJECT_NAME + ".cn", subjectCN);
                } catch (Exception ee) {
                    req.setExtData(REQUEST_SUBJECT_NAME + ".cn", "");
                }
                try {
                    String subjectUID = subject.getUserID();
                    if (subjectUID == null)
                        subjectUID = "";
                    req.setExtData(REQUEST_SUBJECT_NAME + ".uid", subjectUID);
                } catch (Exception ee) {
                    req.setExtData(REQUEST_SUBJECT_NAME + ".uid", "");
                }
            }

            // parse extensions
            CertificateExtensions extensions = null;

            // try {
            extensions = req.getExtDataInCertExts(REQUEST_EXTENSIONS);
            //  } catch (CertificateException e) {
            //     extensions = null;
            // } catch (IOException e) {
            //    extensions = null;
            //  }
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
                //                info.set(X509CertInfo.EXTENSIONS, extensions);
                req.setExtData(REQUEST_EXTENSIONS, extensions);

            }
        } catch (IOException e) {
            CMS.debug("EnrollProfile: Unable to fill certificate request message: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        } catch (InvalidKeyException e) {
            CMS.debug("EnrollProfile: Unable to fill certificate request message: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        // } catch (CertificateException e) {
        //     CMS.debug(e);
        //     throw new EProfileException(e);
        }
    }

    public PKCS10 parsePKCS10(Locale locale, String certreq)
            throws EProfileException {
        /* cert request must not be null */
        if (certreq == null) {
            CMS.debug("EnrollProfile: parsePKCS10() certreq null");
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"));
        }
        CMS.debug("Start parsePKCS10(): " + certreq);

        // trim header and footer
        String creq = normalizeCertReq(certreq);

        // parse certificate into object
        byte data[] = CMS.AtoB(creq);
        PKCS10 pkcs10 = null;
        CryptoManager cm = null;
        CryptoToken savedToken = null;
        boolean sigver = true;

        try {
            cm = CryptoManager.getInstance();
            sigver = CMS.getConfigStore().getBoolean("ca.requestVerify.enabled", true);
            if (sigver) {
                CMS.debug("EnrollProfile: parsePKCS10: signature verification enabled");
                String tokenName = CMS.getConfigStore().getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                savedToken = cm.getThreadToken();
                CryptoToken signToken = CryptoUtil.getCryptoToken(tokenName);
                CMS.debug("EnrollProfile: parsePKCS10 setting thread token");
                cm.setThreadToken(signToken);
                pkcs10 = new PKCS10(data);
            } else {
                CMS.debug("EnrollProfile: parsePKCS10: signature verification disabled");
                pkcs10 = new PKCS10(data, sigver);
            }
        } catch (Exception e) {
            CMS.debug("EnrollProfile: Unable to parse PKCS #10 request: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        } finally {
            if (sigver) {
                CMS.debug("EnrollProfile: parsePKCS10 restoring thread token");
                cm.setThreadToken(savedToken);
            }
        }

        return pkcs10;
    }

    public void fillPKCS10(Locale locale, PKCS10 pkcs10, X509CertInfo info, IRequest req)
            throws EProfileException {
        X509Key key = pkcs10.getSubjectPublicKeyInfo();

        try {
            CertificateX509Key certKey = new CertificateX509Key(key);
            ByteArrayOutputStream certKeyOut = new ByteArrayOutputStream();
            certKey.encode(certKeyOut);
            req.setExtData(IEnrollProfile.REQUEST_KEY, certKeyOut.toByteArray());

            req.setExtData(EnrollProfile.REQUEST_SUBJECT_NAME,
                    new CertificateSubjectName(pkcs10.getSubjectName()));
            try {
                String subjectCN = pkcs10.getSubjectName().getCommonName();
                if (subjectCN == null)
                    subjectCN = "";
                req.setExtData(REQUEST_SUBJECT_NAME + ".cn", subjectCN);
            } catch (Exception ee) {
                req.setExtData(REQUEST_SUBJECT_NAME + ".cn", "");
            }
            try {
                String subjectUID = pkcs10.getSubjectName().getUserID();
                if (subjectUID == null)
                    subjectUID = "";
                req.setExtData(REQUEST_SUBJECT_NAME + ".uid", subjectUID);
            } catch (Exception ee) {
                req.setExtData(REQUEST_SUBJECT_NAME + ".uid", "");
            }

            info.set(X509CertInfo.KEY, certKey);

            PKCS10Attributes p10Attrs = pkcs10.getAttributes();
            if (p10Attrs != null) {
                PKCS10Attribute p10Attr = p10Attrs.getAttribute(CertificateExtensions.NAME);
                if (p10Attr != null && p10Attr.getAttributeId().equals(
                        PKCS9Attribute.EXTENSION_REQUEST_OID)) {
                    CMS.debug("Found PKCS10 extension");
                    Extensions exts0 = (Extensions)
                            (p10Attr.getAttributeValue());
                    DerOutputStream extOut = new DerOutputStream();

                    exts0.encode(extOut);
                    byte[] extB = extOut.toByteArray();
                    DerInputStream extIn = new DerInputStream(extB);
                    CertificateExtensions exts = new CertificateExtensions(extIn);
                    if (exts != null) {
                        CMS.debug("Set extensions " + exts);
                        // info.set(X509CertInfo.EXTENSIONS, exts);
                        req.setExtData(REQUEST_EXTENSIONS, exts);
                    }
                } else {
                    CMS.debug("PKCS10 extension Not Found");
                }
            }

            CMS.debug("Finish parsePKCS10 - " + pkcs10.getSubjectName());
        } catch (IOException e) {
            CMS.debug("EnrollProfile: Unable to fill PKCS #10: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        } catch (CertificateException e) {
            CMS.debug("EnrollProfile: Unable to fill PKCS #10: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
    }

    // for netkey
    public void fillNSNKEY(Locale locale, String sn, String skey, X509CertInfo info, IRequest req)
            throws EProfileException {

        try {
            //cfu - is the algorithm going to be replaced by the policy?
            X509Key key = new X509Key();
            key.decode(CMS.AtoB(skey));

            info.set(X509CertInfo.KEY, new CertificateX509Key(key));
            //                      req.set(EnrollProfile.REQUEST_SUBJECT_NAME,
            //                              new CertificateSubjectName(new
            //                              X500Name("CN="+sn)));
            req.setExtData("screenname", sn);
            // keeping "aoluid" to be backward compatible
            req.setExtData("aoluid", sn);
            req.setExtData("uid", sn);
            CMS.debug("EnrollProfile: fillNSNKEY(): uid=" + sn);

        } catch (Exception e) {
            CMS.debug("EnrollProfile: Unable to fill NSNKEY: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
    }

    // for house key
    public void fillNSHKEY(Locale locale, String tcuid, String skey, X509CertInfo info, IRequest req)
            throws EProfileException {

        try {
            //cfu - is the algorithm going to be replaced by the policy?
            X509Key key = new X509Key();
            key.decode(CMS.AtoB(skey));

            info.set(X509CertInfo.KEY, new CertificateX509Key(key));
            //                      req.set(EnrollProfile.REQUEST_SUBJECT_NAME,
            //                              new CertificateSubjectName(new
            //                              X500Name("CN="+sn)));
            req.setExtData("tokencuid", tcuid);

            CMS.debug("EnrollProfile: fillNSNKEY(): tokencuid=" + tcuid);

        } catch (Exception e) {
            CMS.debug("EnrollProfile: Unable to fill NSHKEY: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
    }

    public DerInputStream parseKeyGen(Locale locale, String certreq)
            throws EProfileException {
        byte data[] = CMS.AtoB(certreq);

        DerInputStream derIn = new DerInputStream(data);

        return derIn;
    }

    public void fillKeyGen(Locale locale, DerInputStream derIn, X509CertInfo info, IRequest req
            )
                    throws EProfileException {
        try {

            /* get SPKAC Algorithm & Signature */
            DerValue derSPKACContent[] = derIn.getSequence(3);
            @SuppressWarnings("unused")
            AlgorithmId mAlgId = AlgorithmId.parse(derSPKACContent[1]);
            @SuppressWarnings("unused")
            byte mSignature[] = derSPKACContent[2].getBitString();

            /* get PKAC SPKI & Challenge */
            byte mPKAC[] = derSPKACContent[0].toByteArray();

            derIn = new DerInputStream(mPKAC);
            DerValue derPKACContent[] = derIn.getSequence(2);

            @SuppressWarnings("unused")
            DerValue mDerSPKI = derPKACContent[0];
            X509Key mSPKI = X509Key.parse(derPKACContent[0]);

            @SuppressWarnings("unused")
            String mChallenge;
            DerValue mDerChallenge = derPKACContent[1];

            if (mDerChallenge.length() != 0)
                mChallenge = derPKACContent[1].getIA5String();

            CertificateX509Key certKey = new CertificateX509Key(mSPKI);
            ByteArrayOutputStream certKeyOut = new ByteArrayOutputStream();
            certKey.encode(certKeyOut);
            req.setExtData(IEnrollProfile.REQUEST_KEY, certKeyOut.toByteArray());
            info.set(X509CertInfo.KEY, certKey);
        } catch (IOException e) {
            CMS.debug("EnrollProfile: Unable to fill key gen: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        } catch (CertificateException e) {
            CMS.debug("EnrollProfile: Unable to fill key gen: " + e);
            CMS.debug(e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
    }

    public String normalizeCertReq(String s) {
        if (s == null) {
            return s;
        }
        s = s.replaceAll("-----BEGIN CERTIFICATE REQUEST-----", "");
        s = s.replaceAll("-----BEGIN NEW CERTIFICATE REQUEST-----", "");
        s = s.replaceAll("-----END CERTIFICATE REQUEST-----", "");
        s = s.replaceAll("-----END NEW CERTIFICATE REQUEST-----", "");

        StringBuffer sb = new StringBuffer();
        StringTokenizer st = new StringTokenizer(s, "\r\n ");

        while (st.hasMoreTokens()) {
            String nextLine = st.nextToken();

            nextLine = nextLine.trim();
            if (nextLine.equals("-----BEGIN CERTIFICATE REQUEST-----"))
                continue;
            if (nextLine.equals("-----BEGIN NEW CERTIFICATE REQUEST-----"))
                continue;
            if (nextLine.equals("-----END CERTIFICATE REQUEST-----"))
                continue;
            if (nextLine.equals("-----END NEW CERTIFICATE REQUEST-----"))
                continue;
            sb.append(nextLine);
        }
        return sb.toString();
    }

    public Locale getLocale(IRequest request) {
        Locale locale = null;
        String language = request.getExtDataInString(
                EnrollProfile.REQUEST_LOCALE);
        if (language != null) {
            locale = new Locale(language);
        }
        return locale;
    }

    /**
     * Populate input
     * <P>
     *
     * (either all "agent" profile cert requests NOT made through a connector, or all "EE" profile cert requests NOT
     * made through a connector)
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST used when a profile cert request is made (before
     * approval process)
     * </ul>
     *
     * @param ctx profile context
     * @param request the certificate request
     * @exception EProfileException an error related to this profile has
     *                occurred
     */
    public void populateInput(IProfileContext ctx, IRequest request)
            throws EProfileException {
        super.populateInput(ctx, request);
    }

    public void populate(IRequest request)
            throws EProfileException {
        super.populate(request);

    }

    /**
     * Passes the request to the set of constraint policies
     * that validate the request against the profile.
     */
    public void validate(IRequest request)
            throws ERejectException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(request);
        String auditProfileID = auditProfileID();
        String auditCertificateSubjectName = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        String subject = null;

        CMS.debug("EnrollProfile.validate: start");

        // try {
        X509CertInfo info = request.getExtDataInCertInfo(REQUEST_CERTINFO);

        try {
            CertificateSubjectName sn = (CertificateSubjectName)
                    info.get(X509CertInfo.SUBJECT);

            // if the cert subject name is NOT MISSING, retrieve the
            // actual "auditCertificateSubjectName" and "normalize" it
            if (sn != null) {
                subject = sn.toString();
                if (subject != null) {
                    // NOTE:  This is ok even if the cert subject name
                    //        is "" (empty)!
                    auditCertificateSubjectName = subject.trim();
                    CMS.debug("EnrollProfile.validate: cert subject name:" +
                            auditCertificateSubjectName);
                }
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditRequesterID,
                        auditProfileID,
                        auditCertificateSubjectName);

            audit(auditMessage);
        } catch (CertificateException e) {
            CMS.debug("EnrollProfile: populate " + e);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        auditProfileID,
                        auditCertificateSubjectName);

            audit(auditMessage);
        } catch (IOException e) {
            CMS.debug("EnrollProfile: populate " + e);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        auditProfileID,
                        auditCertificateSubjectName);

            audit(auditMessage);
        }

        super.validate(request);
        Object key = null;

        try {
            key = info.get(X509CertInfo.KEY);
        } catch (CertificateException e) {
        } catch (IOException e) {
        }

        if (key == null) {
            Locale locale = getLocale(request);

            throw new ERejectException(CMS.getUserMessage(
                        locale, "CMS_PROFILE_EMPTY_KEY"));
        }
        /*
        try {
            CMS.debug("EnrollProfile.validate: certInfo : \n" + info);
        } catch (NullPointerException e) {
            // do nothing
        }
        */
        CMS.debug("EnrollProfile.validate: end");
    }

    /**
     * Signed Audit Log Requester ID
     *
     * This method is inherited by all extended "EnrollProfile"s,
     * and is called to obtain the "RequesterID" for
     * a signed audit log message.
     * <P>
     *
     * @param request the actual request
     * @return id string containing the signed audit log message RequesterID
     */
    protected String auditRequesterID(IRequest request) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String requesterID = ILogger.UNIDENTIFIED;

        if (request != null) {
            // overwrite "requesterID" if and only if "id" != null
            String id = request.getRequestId().toString();

            if (id != null) {
                requesterID = id.trim();
            }
        }

        return requesterID;
    }

    /**
     * Signed Audit Log Profile ID
     *
     * This method is inherited by all extended "EnrollProfile"s,
     * and is called to obtain the "ProfileID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message ProfileID
     */
    protected String auditProfileID() {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String profileID = getId();

        if (profileID != null) {
            profileID = profileID.trim();
        } else {
            profileID = ILogger.UNIDENTIFIED;
        }

        return profileID;
    }

    /*
     * verifyPOP - CRMF POP verification for signing keys
     */
    public void verifyPOP(Locale locale, CertReqMsg certReqMsg)
            throws EProfileException {
        String method = "EnrollProfile: verifyPOP: ";
        CMS.debug(method + "for signing keys");

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        if (!certReqMsg.hasPop()) {
            CMS.debug(method + "missing pop.");
            popFailed(locale, auditSubjectID, auditMessage);
        }
        ProofOfPossession pop = certReqMsg.getPop();
        ProofOfPossession.Type popType = pop.getType();

        if (popType != ProofOfPossession.SIGNATURE) {
            CMS.debug(method + "pop type is not ProofOfPossession.SIGNATURE.");
            popFailed(locale, auditSubjectID, auditMessage);
        }

        try {
            CryptoToken verifyToken = null;
            String tokenName = CMS.getConfigStore().getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
            if (CryptoUtil.isInternalToken(tokenName)) {
                CMS.debug("POP verification using internal token");
                certReqMsg.verify();
            } else {
                CMS.debug("POP verification using token:" + tokenName);
                verifyToken = CryptoUtil.getCryptoToken(tokenName);
                certReqMsg.verify(verifyToken);
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION,
                    auditSubjectID,
                    ILogger.SUCCESS);
            audit(auditMessage);
        } catch (Exception e) {
            CMS.debug(method + "Unable to verify POP: " + e);
            popFailed(locale, auditSubjectID, auditMessage, e);
        }
        CMS.debug(method + "ends.");
    }

    private void popFailed(Locale locale, String auditSubjectID, String auditMessage)
            throws EProfileException {
        popFailed(locale, auditSubjectID, auditMessage, null);
    }
    private void popFailed(Locale locale, String auditSubjectID, String auditMessage, Exception e)
            throws EProfileException {

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION,
                    auditSubjectID,
                    ILogger.FAILURE);

            audit(auditMessage);

            if (e != null) {
                throw new EProfileException(CMS.getUserMessage(locale,
                        "CMS_POP_VERIFICATION_ERROR"), e);
            } else {
                throw new EProfileException(CMS.getUserMessage(locale,
                        "CMS_POP_VERIFICATION_ERROR"));
            }
    }
}
