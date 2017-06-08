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
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.pkcs10.CertificationRequest;
import org.mozilla.jss.pkcs10.CertificationRequestInfo;
import org.mozilla.jss.pkix.cmc.DecryptedPOP;
import org.mozilla.jss.pkix.cmc.IdentityProofV2;
import org.mozilla.jss.pkix.cmc.LraPopWitness;
import org.mozilla.jss.pkix.cmc.OtherMsg;
import org.mozilla.jss.pkix.cmc.PKIData;
import org.mozilla.jss.pkix.cmc.PopLinkWitnessV2;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cmc.TaggedCertificationRequest;
import org.mozilla.jss.pkix.cmc.TaggedRequest;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.logging.AuditEvent;
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
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

/**
 * This class implements a generic enrollment profile.
 *
 * @version $Revision$, $Date$
 */
public abstract class EnrollProfile extends BasicProfile
        implements IEnrollProfile {

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

        String method = "EnrollProfile: createRequests: ";
        CMS.debug(method + "begins");

        // determine how many requests should be created
        String cert_request_type = ctx.get(CTX_CERT_REQUEST_TYPE);
        String cert_request = ctx.get(CTX_CERT_REQUEST);
        String is_renewal = ctx.get(CTX_RENEWAL);
        Integer renewal_seq_num = 0;

        /* cert_request_type can be null for the case of CMC */
        if (cert_request_type == null) {
            CMS.debug(method + " request type is null");
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

            // donePOI true means Proof-Of-Identity is already done.
            // if the auth manager is the CMCUserSignedAuth, then
            // the new cert will eventually have the same subject as the
            // user signing cert
            // if the auth manager is the CMCAuth (agent pre-approved),
            // then no changes
            boolean donePOI = false;
            String signingUserSerial = ctx.get(IAuthManager.CRED_CMC_SIGNING_CERT);
            if (signingUserSerial != null) {
                donePOI = true;
            }
            // catch for invalid request
            cmc_msgs = parseCMC(locale, cert_request, donePOI);
            if (cmc_msgs == null) {
                CMS.debug(method + "parseCMC returns cmc_msgs null");
                return null;
            } else {
                num_requests = cmc_msgs.length;
                CMS.debug(method + "parseCMC returns cmc_msgs num_requests=" +
                        num_requests);
            }
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
                    CMS.debug(method + "setting cmc TaggedRequest in request");
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

            CMS.debug("EnrollProfile: createEnrollmentRequest " +
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

                byte[] iv = CryptoUtil.getNonceData(EncryptionAlgorithm.AES_128_CBC.getIVLength());
                IVParameterSpec ivps = new IVParameterSpec(iv);

                PublicKey userPubKey = X509Key.parsePublicKey(new DerValue(req_key_data));
                if (userPubKey == null) {
                    msg = method + "userPubKey null after X509Key.parsePublicKey";
                    CMS.debug(msg);
                    throw new EBaseException(msg);
                }

                SymmetricKey symKey = CryptoUtil.generateKey(
                        token,
                        KeyGenAlgorithm.AES,
                        128,
                        null,
                        true);

                byte[] pop_encryptedData = CryptoUtil.encryptUsingSymmetricKey(
                        token,
                        symKey,
                        challenge,
                        EncryptionAlgorithm.AES_128_CBC,
                        ivps);

                if (pop_encryptedData == null) {
                    msg = method + "pop_encryptedData null";
                    CMS.debug(msg);
                    throw new EBaseException(msg);
                }

                byte[] pop_sysPubEncryptedSession =  CryptoUtil.wrapUsingPublicKey(
                        token,
                        issuanceProtPubKey,
                        symKey,
                        KeyWrapAlgorithm.RSA);

                if (pop_sysPubEncryptedSession == null) {
                    msg = method + "pop_sysPubEncryptedSession null";
                    CMS.debug(msg);
                    throw new EBaseException(msg);
                }


                byte[] pop_userPubEncryptedSession = CryptoUtil.wrapUsingPublicKey(
                        token,
                        userPubKey,
                        symKey,
                        KeyWrapAlgorithm.RSA);

                if (pop_userPubEncryptedSession == null) {
                    msg = method + "pop_userPubEncryptedSession null";
                    CMS.debug(msg);
                    throw new EBaseException(msg);
                }
                CMS.debug(method + "POP challenge fields generated successfully...setting request extData");

                req.setExtData("pop_encryptedData", pop_encryptedData);

                req.setExtData("pop_sysPubEncryptedSession", pop_sysPubEncryptedSession);

                req.setExtData("pop_userPubEncryptedSession", pop_userPubEncryptedSession);

                req.setExtData("pop_encryptedDataIV", iv);

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
        CMS.debug(method + "begins");

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
            CMS.debug(method + " auth token is null; agent manual approval required;");
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

    /**
     * getPKIDataFromCMCblob
     *
     * @param certReqBlob cmc b64 encoded blob
     * @return PKIData
     */
    public PKIData getPKIDataFromCMCblob(Locale locale, String certReqBlob)
            throws EProfileException {

        String method = "EnrollProfile: getPKIDataFromCMCblob: ";
        String msg = ""; // for capturing debug and throw info

        /* cert request must not be null */
        if (certReqBlob == null) {
            msg = method + "certReqBlob null";
            CMS.debug(msg);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                            msg);
        }
        //CMS.debug(method + " Start: " + certReqBlob);
        CMS.debug(method + "starts");

        String creq = normalizeCertReq(certReqBlob);
        try {
            byte data[] = CMS.AtoB(creq);
            ByteArrayInputStream cmcBlobIn = new ByteArrayInputStream(data);

            org.mozilla.jss.pkix.cms.ContentInfo cmcReq = (org.mozilla.jss.pkix.cms.ContentInfo) org.mozilla.jss.pkix.cms.ContentInfo
                    .getTemplate().decode(cmcBlobIn);
            org.mozilla.jss.pkix.cms.SignedData cmcFullReq = (org.mozilla.jss.pkix.cms.SignedData) cmcReq
                    .getInterpretedContent();
            org.mozilla.jss.pkix.cms.EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();
            OCTET_STRING content = ci.getContent();

            ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
            PKIData pkiData = (PKIData) (new PKIData.Template()).decode(s);

            mCMCData = pkiData;
            //PKIData pkiData = (PKIData)
            //    (new PKIData.Template()).decode(cmcBlobIn);

            return pkiData;
        } catch (Exception e) {
            CMS.debug(method + e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
    }

    public static CertificateSubjectName getCMCSigningCertSNfromCertSerial(
            String certSerial) throws Exception {
        X509CertImpl userCert = getCMCSigningCertFromCertSerial(certSerial);

        if (userCert != null) {
            return userCert.getSubjectObj();
        } else {
            return null;
        }
    }

    /**
     * getCMCSigningCertFromCertSerial is to be used when authentication
     * was done with CMCUserSignedAuth where the resulting
     * authToken contains
     * IAuthManager.CRED_CMC_SIGNING_CERT, serial number
     * This method takes the serial number
     * and finds the cert from the CA's certdb
     */
    public static X509CertImpl getCMCSigningCertFromCertSerial(
            String certSerial) throws Exception {
        String method = "EnrollProfile: getCMCSigningCertFromCertSerial: ";
        String msg = "";

        X509CertImpl userCert = null;

        if (certSerial == null || certSerial.equals("")) {
            msg = method + "certSerial empty";
            CMS.debug(msg);
            throw new Exception(msg);
        }

        // for CMCUserSignedAuth, the signing user is the subject of
        // the new cert
        ICertificateAuthority authority = (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
        try {
            BigInteger serialNo = new BigInteger(certSerial);
            userCert = authority.getCertificateRepository().getX509Certificate(serialNo);
        } catch (NumberFormatException e) {
            msg = method + e;
            CMS.debug(msg);
            throw new Exception(msg);
        } catch (EBaseException e) {
            msg = method + e + "; signing user cert not found: serial=" + certSerial;
            CMS.debug(msg);
            throw new Exception(msg);
        }

        if (userCert != null) {
            msg = method + "signing user cert found; serial=" + certSerial;
            CMS.debug(msg);
        } else {
            msg = method + "signing user cert not found: serial=" + certSerial;
            CMS.debug(msg);
            throw new Exception(msg);
        }

        return userCert;
    }

    /*
     * parseCMC
     * @throws EProfileException in case of error
     *   note: returing "null" doesn't mean failure
     */
    public TaggedRequest[] parseCMC(Locale locale, String certreq)
            throws EProfileException {
        return parseCMC(locale, certreq, false);
    }
    public TaggedRequest[] parseCMC(Locale locale, String certreq, boolean donePOI)
            throws EProfileException {

        String method = "EnrollProfile: parseCMC: ";
        String msg = ""; // for capturing debug and throw info
        //CMS.debug(method + " Start parseCMC(): " + certreq);
        CMS.debug(method + "starts");
        String auditMessage = "";
        String auditSubjectID = auditSubjectID();

        /* cert request must not be null */
        if (certreq == null) {
            msg = method + "certreq null";
            CMS.debug(msg);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                            msg);
        }

        TaggedRequest msgs[] = null;
        try {
            PKIData pkiData = getPKIDataFromCMCblob(locale, certreq);
            SEQUENCE controlSeq = pkiData.getControlSequence();
            int numcontrols = controlSeq.size();
            SEQUENCE reqSeq = pkiData.getReqSequence();
            byte randomSeed[] = null;
            UTF8String ident_s = null;
            SessionContext context = SessionContext.getContext();
            if (!context.containsKey("numOfControls")) {
                CMS.debug(method + "numcontrols="+ numcontrols);
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

                    /**
                     * pre-process all controls --
                     * the postponed processing is so that we can capture
                     * the identification, if included
                     */
                    CMS.debug(method + "about to pre-process controls");
                    for (int i = 0; i < numcontrols; i++) {
                        attributes[i] = (TaggedAttribute) controlSeq.elementAt(i);
                        OBJECT_IDENTIFIER oid = attributes[i].getType();
                        if (oid.equals(OBJECT_IDENTIFIER.id_cmc_decryptedPOP)) {
                            CMS.debug(method + " id_cmc_decryptedPOP found");
                            id_cmc_decryptedPOP = true;
                            decPopVals = attributes[i].getValues();
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_identification)) {
                            CMS.debug(method + " id_cmc_identification found");
                            id_cmc_identification = true;
                            ident = attributes[i].getValues();
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_identityProofV2)) {
                            CMS.debug(method + " id_cmc_identityProofV2 found");
                            id_cmc_identityProofV2 = true;
                            attr = attributes[i];
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_identityProof)) {
                            CMS.debug(method + " id_cmc_identityProof found");
                            id_cmc_identityProof = true;
                            attr = attributes[i];
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_idPOPLinkRandom)) {
                            CMS.debug(method + "id_cmc_idPOPLinkRandom found");
                            id_cmc_idPOPLinkRandom = true;
                            vals = attributes[i].getValues();
                        } else {
                            CMS.debug(method + "unknown control found");
                            context.put(attributes[i].getType(), attributes[i]);
                        }
                    } //for

                    /**
                     * now do the actual control processing
                     */
                    CMS.debug(method + "processing controls...");

                    if (id_cmc_identification) {
                        if (ident == null) {
                            msg = "id_cmc_identification contains null attribute value";
                            CMS.debug(method + msg);
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identification", bpids);

                            msg = " id_cmc_identification attribute value not found in";
                            CMS.debug(method + msg);
/*
                            throw new EProfileException(
                                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                                            msg);
*/
                        } else {
                            ident_s = (UTF8String) (ASN1Util.decode(UTF8String.getTemplate(),
                                    ASN1Util.encode(ident.elementAt(0))));
                        }
                        if (ident == null && ident_s == null) {
                            msg = " id_cmc_identification contains invalid content";
                            CMS.debug(method + msg);
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identification", bpids);

                            CMS.debug(method + msg);
/*
                            throw new EProfileException(
                                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                                            msg);
*/
                        }
                    }

                    // checking Proof Of Identity, if not pre-signed

                    if (donePOI) {
                        // for logging purposes
                        if (id_cmc_identityProofV2) {
                            CMS.debug(method
                                    + "pre-signed CMC request, but id_cmc_identityProofV2 found...ignore; no further proof of identification check");
                        } else if (id_cmc_identityProof) {
                            CMS.debug(method
                                    + "pre-signed CMC request, but id_cmc_identityProof found...ignore; no further proof of identification check");
                        } else {
                            CMS.debug(method + "pre-signed CMC request; no further proof of identification check");
                        }
                    } else if (id_cmc_identityProofV2 && (attr != null)) {
                        // either V2 or not V2; can't be both
                        CMS.debug(method +
                                "not pre-signed CMC request; calling verifyIdentityProofV2;");
                        if (!id_cmc_identification || ident_s == null) {
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identification", bpids);
                            context.put("identityProofV2", bpids);
                            msg = "id_cmc_identityProofV2 missing id_cmc_identification";
                            CMS.debug(method + msg);
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    method + msg);
                            audit(auditMessage);

                            throw new EProfileException(
                                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                                            msg);
                        }

                        boolean valid = verifyIdentityProofV2(context, attr, ident_s,
                                reqSeq);
                        if (!valid) {
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identityProofV2", bpids);

                            msg = " after verifyIdentityProofV2";
                            CMS.debug(method + msg);
                            throw new EProfileException(CMS.getUserMessage(locale,
                                    "CMS_POI_VERIFICATION_ERROR") + msg);
                        } else {
                            CMS.debug(method + "passed verifyIdentityProofV2; Proof of Identity successful;");
                        }
                    } else if (id_cmc_identityProof && (attr != null)) {
                        CMS.debug(method + "not pre-signed CMC request; calling verifyIdentityProof;");
                        boolean valid = verifyIdentityProof(attr,
                                reqSeq);
                        if (!valid) {
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identityProof", bpids);

                            msg = " after verifyIdentityProof";
                            CMS.debug(method + msg);
                            throw new EProfileException(CMS.getUserMessage(locale,
                                    "CMS_POI_VERIFICATION_ERROR") + msg);
                        } else {
                            CMS.debug(method + "passed verifyIdentityProof; Proof of Identity successful;");
                            // in case it was set
                            auditSubjectID = auditSubjectID();
                        }
                    } else {
                        msg = "not pre-signed CMC request; missing Proof of Identification control";
                        CMS.debug(method + msg);
                        auditMessage = CMS.getLogMessage(
                                AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                                auditSubjectID,
                                ILogger.FAILURE,
                                method + msg);
                        audit(auditMessage);
                        throw new EProfileException(CMS.getUserMessage(locale,
                                "CMS_POI_VERIFICATION_ERROR") + ":" + method + msg);
                    }

                    if (id_cmc_decryptedPOP) {
                        if (decPopVals != null) {

                            DecryptedPOP decPop = (DecryptedPOP) (ASN1Util.decode(DecryptedPOP.getTemplate(),
                                    ASN1Util.encode(decPopVals.elementAt(0))));
                            CMS.debug(method + "DecryptedPOP encoded");

                            Integer reqId = verifyDecryptedPOP(locale, decPop);
                            if (reqId != null) {
                                context.put("cmcDecryptedPopReqId", reqId);
                            }
                        } else { //decPopVals == null
                            msg = "id_cmc_decryptedPOP contains invalid DecryptedPOP";
                            CMS.debug(method + msg);
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.PROOF_OF_POSSESSION,
                                    auditSubjectID,
                                    ILogger.SUCCESS,
                                    method + msg);
                            audit(auditMessage);

                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("decryptedPOP", bpids);
                        }

                        // decryptedPOP is expected to return null;
                        // POPLinkWitnessV2 would have to be checked in
                        // round one, if required
                        return null;
                    }

                    if (id_cmc_idPOPLinkRandom && vals != null) {
                        OCTET_STRING ostr =
                                (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                                ASN1Util.encode(vals.elementAt(0))));
                        randomSeed = ostr.toByteArray();
                        CMS.debug(method + "got randomSeed");
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

            /**
             * in CS.cfg, cmc.popLinkWitnessRequired=true
             * will enforce popLinkWitness (or V2);
             */
            boolean popLinkWitnessRequired = false;
            try {
                String configName = "cmc.popLinkWitnessRequired";
                CMS.debug(method + "getting :" + configName);
                popLinkWitnessRequired = CMS.getConfigStore().getBoolean(configName, false);
                if (popLinkWitnessRequired) {
                    CMS.debug(method + "popLinkWitness(V2) required");
                } else {
                    CMS.debug(method + "popLinkWitness(V2) not required");
                }
            } catch (Exception e) {
                // unlikely to get here
                msg = method + " Failed to retrieve cmc.popLinkWitnessRequired";
                CMS.debug(msg);
                throw new EProfileException(method + msg);
            }

            int nummsgs = reqSeq.size();
            if (nummsgs > 0) {
                CMS.debug(method + "nummsgs =" + nummsgs);
                msgs = new TaggedRequest[reqSeq.size()];
                SEQUENCE bpids = new SEQUENCE();

                boolean valid = true;
                for (int i = 0; i < nummsgs; i++) {
                    msgs[i] = (TaggedRequest) reqSeq.elementAt(i);
                    if (popLinkWitnessRequired &&
                            !context.containsKey("POPLinkWitnessV2") &&
                            !context.containsKey("POPLinkWitness")) {
                        CMS.debug(method + "popLinkWitness(V2) required");
                        if (randomSeed == null || ident_s == null) {
                            msg = "no randomSeed or identification found needed for popLinkWitness(V2)";
                            CMS.debug(method + msg);
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.CMC_ID_POP_LINK_WITNESS,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    method + msg);
                            audit(auditMessage);

                            context.put("POPLinkWitnessV2", bpids);
                            return null;
                        }

                        // verifyPOPLinkWitness() will determine if this is
                        // POPLinkWitnessV2 or POPLinkWitness
                        // If failure, context is set in verifyPOPLinkWitness
                        valid = verifyPOPLinkWitness(ident_s, randomSeed, msgs[i], bpids, context);
                        if (valid == false) {
                            if (context.containsKey("POPLinkWitnessV2"))
                                msg = " in POPLinkWitnessV2";
                            else if (context.containsKey("POPLinkWitness"))
                                msg = " in POPLinkWitness";
                            else
                                msg = " failure from verifyPOPLinkWitness";

                            msg = msg + ": ident_s=" + ident_s;
                            CMS.debug(method + msg);
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.CMC_ID_POP_LINK_WITNESS,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    method + msg);
                            audit(auditMessage);
                            throw new EProfileException(CMS.getUserMessage(locale,
                                    "CMS_POP_LINK_WITNESS_VERIFICATION_ERROR") + msg);
                        } else {
                            msg = ": ident_s=" + ident_s;
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.CMC_ID_POP_LINK_WITNESS,
                                    auditSubjectID,
                                    ILogger.SUCCESS,
                                    method + msg);
                            audit(auditMessage);
                        }
                    }
                } //for
            } else {
                CMS.debug(method + "nummsgs 0; returning...");
                return null;
            }

            CMS.debug(method + "ends");
            return msgs;
        } catch (EProfileException e) {
            throw new EProfileException(e);
        } catch (Exception e) {
            CMS.debug(method + e);
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
        byte[] pop_encryptedData = req.getExtDataInByteArray("pop_encryptedData");
        if (pop_encryptedData == null) {
            msg = method +
                    "pop_encryptedData not found in request:" +
                    reqId.toString();
            CMS.debug(msg);
            return null;
        }

        byte[] pop_sysPubEncryptedSession = req.getExtDataInByteArray("pop_sysPubEncryptedSession");
        if (pop_sysPubEncryptedSession == null) {
            msg = method +
                    "pop_sysPubEncryptedSession not found in request:" +
                    reqId.toString();
            CMS.debug(msg);
            return null;
        }

        byte[] cmc_msg = req.getExtDataInByteArray(IEnrollProfile.CTX_CERT_REQUEST);
        if (cmc_msg == null) {
            msg = method +
                    "cmc_msg not found in request:" +
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
                    SymmetricKey.AES,
                    128,
                    SymmetricKey.Usage.DECRYPT,
                    issuanceProtPrivKey,
                    pop_sysPubEncryptedSession,
                    KeyWrapAlgorithm.RSA);

            if (symKey == null) {
                msg = "symKey null after CryptoUtil.unwrap returned";
                CMS.debug(msg);
                return null;
            }

            // TODO(alee) The code below should be replaced by code that gets the IV from the Pop request
            // This IV is supposed to be random
            byte[] iv = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            IVParameterSpec default_iv = new IVParameterSpec(iv);

            byte[] challenge_b = CryptoUtil.decryptUsingSymmetricKey(
                    token,
                    default_iv,
                    pop_encryptedData,
                    symKey,
                    EncryptionAlgorithm.AES_128_CBC);

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

    /**
     * getPopLinkWitnessV2control
     *
     * @author cfu
     */
    protected PopLinkWitnessV2 getPopLinkWitnessV2control(ASN1Value value) {
        String method = "EnrollProfile: getPopLinkWitnessV2control: ";

        ByteArrayInputStream bis = new ByteArrayInputStream(
                ASN1Util.encode(value));
        PopLinkWitnessV2 popLinkWitnessV2 = null;

        try {
            popLinkWitnessV2 = (PopLinkWitnessV2) (new PopLinkWitnessV2.Template()).decode(bis);
        } catch (Exception e) {
            CMS.debug(method + e);
        }
        return popLinkWitnessV2;
    }

    /**
     * verifyPopLinkWitnessV2
     *
     * @author cfu
     */
    protected boolean verifyPopLinkWitnessV2(
            PopLinkWitnessV2 popLinkWitnessV2,
            byte[] randomSeed,
            String sharedSecret,
            String ident_string) {
        String method = "EnrollProfile: verifyPopLinkWitnessV2: ";

        if ((popLinkWitnessV2 == null) ||
                (randomSeed == null) ||
                (sharedSecret == null)) {
            CMS.debug(method + " method parameters cannot be null");
            return false;
        }
        AlgorithmIdentifier keyGenAlg = popLinkWitnessV2.getKeyGenAlgorithm();
        AlgorithmIdentifier macAlg = popLinkWitnessV2.getMacAlgorithm();
        OCTET_STRING witness = popLinkWitnessV2.getWitness();
        if (keyGenAlg == null) {
            CMS.debug(method + " keyGenAlg reurned by popLinkWitnessV2.getWitness is null");
            return false;
        }
        if (macAlg == null) {
            CMS.debug(method + " macAlg reurned by popLinkWitnessV2.getWitness is null");
            return false;
        }
        if (witness == null) {
            CMS.debug(method + " witness reurned by popLinkWitnessV2.getWitness is null");
            return false;
        }

        try {
            DigestAlgorithm keyGenAlgID = DigestAlgorithm.fromOID(keyGenAlg.getOID());
            MessageDigest keyGenMDAlg = MessageDigest.getInstance(keyGenAlgID.toString());

            HMACAlgorithm macAlgID = HMACAlgorithm.fromOID(macAlg.getOID());
            MessageDigest macMDAlg = MessageDigest
                    .getInstance(CryptoUtil.getHMACtoMessageDigestName(macAlgID.toString()));

            byte[] witness_bytes = witness.toByteArray();
            return verifyDigest(
                    (ident_string != null) ? (sharedSecret + ident_string).getBytes() : sharedSecret.getBytes(),
                    randomSeed,
                    witness_bytes,
                    keyGenMDAlg, macMDAlg);
        } catch (NoSuchAlgorithmException e) {
            CMS.debug(method + e);
            return false;
        } catch (Exception e) {
            CMS.debug(method + e);
            return false;
        }
    }

    /*
     * verifyPOPLinkWitness now handles POPLinkWitnessV2;
     */
    private boolean verifyPOPLinkWitness(
            UTF8String ident, byte[] randomSeed, TaggedRequest req,
            SEQUENCE bpids, SessionContext context) {
        String method = "EnrollProfile: verifyPOPLinkWitness: ";
        CMS.debug(method + "begins.");

        String ident_string = null;
        if (ident != null) {
            ident_string = ident.toString();
        }

        boolean sharedSecretFound = true;
        String configName = "cmc.sharedSecret.class";
        String sharedSecret = null;
        ISharedToken tokenClass = getSharedTokenClass(configName);
        if (tokenClass == null) {
            CMS.debug(method + " Failed to retrieve shared secret plugin class");
            sharedSecretFound = false;
        } else {
            if (ident_string != null) {
                sharedSecret = tokenClass.getSharedToken(ident_string);
            } else {
                sharedSecret = tokenClass.getSharedToken(mCMCData);
            }
            if (sharedSecret == null)
                sharedSecretFound = false;
        }

        INTEGER reqId = null;
        byte[] bv = null;

        if (req.getType().equals(TaggedRequest.PKCS10)) {
            String methodPos = method + "PKCS10: ";
            CMS.debug(methodPos + "begins");

            TaggedCertificationRequest tcr = req.getTcr();
            if (!sharedSecretFound) {
                bpids.addElement(tcr.getBodyPartID());
                context.put("POPLinkWitness", bpids);
                return false;
            } else {
                CertificationRequest creq = tcr.getCertificationRequest();
                CertificationRequestInfo cinfo = creq.getInfo();
                SET attrs = cinfo.getAttributes();
                for (int j = 0; j < attrs.size(); j++) {
                    Attribute pkcs10Attr = (Attribute) attrs.elementAt(j);
                    if (pkcs10Attr.getType().equals(OBJECT_IDENTIFIER.id_cmc_popLinkWitnessV2)) {
                        CMS.debug(methodPos + "found id_cmc_popLinkWitnessV2");
                        if (ident_string == null) {
                            bpids.addElement(reqId);
                            context.put("identification", bpids);
                            context.put("POPLinkWitnessV2", bpids);
                            String msg = "id_cmc_popLinkWitnessV2 must be accompanied by id_cmc_identification in this server";
                            CMS.debug(methodPos + msg);
                            return false;
                        }

                        SET witnessVal = pkcs10Attr.getValues();
                        if (witnessVal.size() > 0) {
                            try {
                                PopLinkWitnessV2 popLinkWitnessV2 = getPopLinkWitnessV2control(witnessVal.elementAt(0));
                                boolean valid = verifyPopLinkWitnessV2(popLinkWitnessV2,
                                        randomSeed,
                                        sharedSecret,
                                        ident_string);
                                if (!valid) {
                                    bpids.addElement(reqId);
                                    context.put("POPLinkWitnessV2", bpids);
                                    return valid;
                                }
                                return true;
                            } catch (Exception ex) {
                                CMS.debug(methodPos + ex);
                                return false;
                            }
                        }
                    } else if (pkcs10Attr.getType().equals(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness)) {
                        SET witnessVal = pkcs10Attr.getValues();
                        if (witnessVal.size() > 0) {
                            try {
                                OCTET_STRING str = (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
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
            String methodPos = method + "CRMF: ";
            CMS.debug(methodPos + "begins");

            CertReqMsg crm = req.getCrm();
            CertRequest certReq = crm.getCertReq();
            reqId = certReq.getCertReqId();
            if (!sharedSecretFound) {
                bpids.addElement(reqId);
                context.put("POPLinkWitness", bpids);
                return false;
            } else {
                for (int i = 0; i < certReq.numControls(); i++) {
                    AVA ava = certReq.controlAt(i);

                    if (ava.getOID().equals(OBJECT_IDENTIFIER.id_cmc_popLinkWitnessV2)) {
                        CMS.debug(methodPos + "found id_cmc_popLinkWitnessV2");
                        if (ident_string == null) {
                            bpids.addElement(reqId);
                            context.put("identification", bpids);
                            context.put("POPLinkWitnessV2", bpids);
                            String msg = "id_cmc_popLinkWitnessV2 must be accompanied by id_cmc_identification in this server";
                            CMS.debug(methodPos + msg);
                            return false;
                        }

                        ASN1Value value = ava.getValue();
                        PopLinkWitnessV2 popLinkWitnessV2 = getPopLinkWitnessV2control(value);

                        boolean valid = verifyPopLinkWitnessV2(popLinkWitnessV2,
                                randomSeed,
                                sharedSecret,
                                ident_string);
                        if (!valid) {
                            bpids.addElement(reqId);
                            context.put("POPLinkWitnessV2", bpids);
                            return valid;
                        }
                    } else if (ava.getOID().equals(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness)) {
                        CMS.debug(methodPos + "found id_cmc_idPOPLinkWitness");
                        ASN1Value value = ava.getValue();
                        ByteArrayInputStream bis = new ByteArrayInputStream(
                                ASN1Util.encode(value));
                        OCTET_STRING ostr = null;
                        try {
                            ostr = (OCTET_STRING) (new OCTET_STRING.Template()).decode(bis);
                            bv = ostr.toByteArray();
                        } catch (Exception e) {
                            bpids.addElement(reqId);
                            context.put("POPLinkWitness", bpids);
                            return false;
                        }

                        boolean valid = verifyDigest(sharedSecret.getBytes(),
                                randomSeed, bv);
                        if (!valid) {
                            bpids.addElement(reqId);
                            context.put("POPLinkWitness", bpids);
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


    ISharedToken getSharedTokenClass(String configName) {
        String method = "EnrollProfile: getSharedTokenClass: ";
        ISharedToken tokenClass = null;

        String name = null;
        try {
            CMS.debug(method + "getting :" + configName);
            name = CMS.getConfigStore().getString(configName);
            CMS.debug(method + "Shared Secret plugin class name retrieved:" +
                    name);
        } catch (Exception e) {
            CMS.debug(method + " Failed to retrieve shared secret plugin class name");
            return null;
        }

        try {
            tokenClass = (ISharedToken) Class.forName(name).newInstance();
            CMS.debug(method + "Shared Secret plugin class retrieved");
        } catch (ClassNotFoundException e) {
            CMS.debug(method + " Failed to find class name: " + name);
            return null;
        } catch (InstantiationException e) {
            CMS.debug("EnrollProfile: Failed to instantiate class: " + name);
            return null;
        } catch (IllegalAccessException e) {
            CMS.debug(method + " Illegal access: " + name);
            return null;
        }

        return tokenClass;
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
            SessionContext sessionContext,
            TaggedAttribute attr,
            UTF8String ident,
            SEQUENCE reqSeq) {
        String method = "EnrollProfile:verifyIdentityProofV2: ";
        String msg = "";
        CMS.debug(method + " begins");
        boolean verified = false;
        String auditMessage = method;

        if ((attr == null) ||
                (ident == null) ||
                (reqSeq == null)) {
            CMS.debug(method + "method parameters cannot be null");
            // this is internal error
            return false;
        }

        String ident_string = ident.toString();
        String auditAttemptedCred = null;

        SET vals = attr.getValues(); // getting the IdentityProofV2 structure
        if (vals.size() < 1) {
            msg = " invalid TaggedAttribute in request";
            CMS.debug(method + msg);
            auditMessage = CMS.getLogMessage(
                    AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                    auditAttemptedCred,
                    ILogger.FAILURE,
                    method + msg);
            audit(auditMessage);
            return false;
        }

        String configName = "cmc.sharedSecret.class";
        ISharedToken tokenClass = getSharedTokenClass(configName);

        if (tokenClass == null) {
            msg = " Failed to retrieve shared secret plugin class";
            CMS.debug(method + msg);
            auditMessage = CMS.getLogMessage(
                    AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                    auditAttemptedCred,
                    ILogger.FAILURE,
                    method + msg);
            audit(auditMessage);
            return false;
        }

        String token = null;
        if (ident_string != null) {
            auditAttemptedCred = ident_string;
            token = tokenClass.getSharedToken(ident_string);
        } else
            token = tokenClass.getSharedToken(mCMCData);

        if (token == null) {
            msg = " Failed to retrieve shared secret";
            CMS.debug(method + msg);
            auditMessage = CMS.getLogMessage(
                    AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                    auditAttemptedCred,
                    ILogger.FAILURE,
                    method + msg);
            audit(auditMessage);
            return false;
        }

        // CMS.debug(method + "Shared Secret returned by tokenClass:" + token);
        try {
            IdentityProofV2 idV2val = (IdentityProofV2) (ASN1Util.decode(IdentityProofV2.getTemplate(),
                    ASN1Util.encode(vals.elementAt(0))));

            DigestAlgorithm hashAlgID = DigestAlgorithm.fromOID(idV2val.getHashAlgID().getOID());
            MessageDigest hashAlg = MessageDigest.getInstance(hashAlgID.toString());

            HMACAlgorithm macAlgId = HMACAlgorithm.fromOID(idV2val.getMacAlgId().getOID());
            MessageDigest macAlg = MessageDigest
                    .getInstance(CryptoUtil.getHMACtoMessageDigestName(macAlgId.toString()));

            OCTET_STRING witness = idV2val.getWitness();
            if (witness == null) {
                msg = " witness reurned by idV2val.getWitness is null";
                CMS.debug(method + msg);
                throw new EBaseException(msg);
            }

            byte[] witness_bytes = witness.toByteArray();
            byte[] request_bytes = ASN1Util.encode(reqSeq); // PKIData reqSequence field
            verified = verifyDigest(
                    (ident_string != null) ? (token + ident_string).getBytes() : token.getBytes(),
                    request_bytes,
                    witness_bytes,
                    hashAlg, macAlg);

            String auditSubjectID = null;

            if (verified) {
                auditSubjectID = (String)
                        sessionContext.get(SessionContext.USER_ID);
                CMS.debug(method + "current auditSubjectID was:"+ auditSubjectID);
                CMS.debug(method + "identity verified. Updating auditSubjectID");
                CMS.debug(method + "updated auditSubjectID is:"+ ident_string);
                auditSubjectID = ident_string;
                sessionContext.put(SessionContext.USER_ID, auditSubjectID);

                auditMessage = CMS.getLogMessage(
                        AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        "method=" + method);
                audit(auditMessage);
            } else {
                throw new EBaseException("failed to verify");
            }
            return verified;
        } catch (Exception e) {
            CMS.debug(method + " Failed with Exception: " + e.toString());
            auditMessage = CMS.getLogMessage(
                    AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                    auditAttemptedCred,
                    ILogger.FAILURE,
                    method + e.toString());
            audit(auditMessage);
            return false;
        }

    } // verifyIdentityProofV2

    private boolean verifyIdentityProof(
            TaggedAttribute attr, SEQUENCE reqSeq) {
        String method = "verifyIdentityProof: ";
        boolean verified = false;

        SET vals = attr.getValues();
        if (vals.size() < 1)
            return false;

        String configName = "cmc.sharedSecret.class";
            ISharedToken tokenClass = getSharedTokenClass(configName);
        if (tokenClass == null) {
            CMS.debug(method + " Failed to retrieve shared secret plugin class");
            return false;
        }

            String token = tokenClass.getSharedToken(mCMCData);
            OCTET_STRING ostr = null;
            try {
                ostr = (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                        ASN1Util.encode(vals.elementAt(0))));
            } catch (InvalidBERException e) {
                CMS.debug(method + "Failed to decode the byte value.");
                return false;
            }
            byte[] b = ostr.toByteArray();
            byte[] text = ASN1Util.encode(reqSeq);

            verified = verifyDigest(token.getBytes(), text, b);
            if (verified) {// update auditSubjectID
                //placeholder. Should probably just disable this v1 method
            }
            return verified;
    }

    public void fillTaggedRequest(Locale locale, TaggedRequest tagreq, X509CertInfo info,
            IRequest req)
            throws EProfileException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        String method = "EnrollProfile: fillTaggedRequest: ";
        CMS.debug(method + "begins");
        TaggedRequest.Type type = tagreq.getType();
        if (type == null) {
            CMS.debug(method + "TaggedRequest type == null");
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST")+
                    "TaggedRequest type null");
        }

        if (type.equals(TaggedRequest.PKCS10)) {
            String methodPos = method + "PKCS10: ";
            CMS.debug(methodPos + " TaggedRequest type == pkcs10");
            boolean sigver = true;
            boolean tokenSwitched = false;
            CryptoManager cm = null;
            CryptoToken signToken = null;
            CryptoToken savedToken = null;
            try {
                // for PKCS10, "sigver" would provide the POP
                sigver = CMS.getConfigStore().getBoolean("ca.requestVerify.enabled", true);
                cm = CryptoManager.getInstance();
                if (sigver == true) {
                    CMS.debug(methodPos + "sigver true, POP is to be verified");
                    String tokenName =
                        CMS.getConfigStore().getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                    savedToken = cm.getThreadToken();
                    signToken = CryptoUtil.getCryptoToken(tokenName);
                    if (!savedToken.getName().equals(signToken.getName())) {
                        cm.setThreadToken(signToken);
                        tokenSwitched = true;
                    }
                } else {
                    // normally, you would not get here, as you almost always
                    // would want to verify the PKCS10 signature when it's
                    // already there instead of taking a 2nd trip
                    CMS.debug(methodPos + "sigver false, POP is not to be verified now, but instead will be challenged");
                    req.setExtData("cmc_POPchallengeRequired", "true");
                }

                TaggedCertificationRequest tcr = tagreq.getTcr();
                CertificationRequest p10 = tcr.getCertificationRequest();
                ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                p10.encode(ostream);
                PKCS10 pkcs10 = new PKCS10(ostream.toByteArray(), sigver);
                if (sigver) {
                    auditMessage = CMS.getLogMessage(
                            AuditEvent.PROOF_OF_POSSESSION,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            "method="+method);
                    audit(auditMessage);
                }

                req.setExtData("bodyPartId", tcr.getBodyPartID());
                fillPKCS10(locale, pkcs10, info, req);
            } catch (Exception e) {
                CMS.debug(method + e);
                // this will throw
                if (sigver)
                    popFailed(locale, auditSubjectID, auditMessage, e);
            }  finally {
                if ((sigver == true) && (tokenSwitched == true)){
                    cm.setThreadToken(savedToken);
                }
            }
            CMS.debug(methodPos + "done");
        } else if (type.equals(TaggedRequest.CRMF)) {
            String methodPos = method + "CRMF: ";
            CMS.debug(methodPos + " TaggedRequest type == crmf");
            CertReqMsg crm = tagreq.getCrm();
            SessionContext context = SessionContext.getContext();
            Integer nums = (Integer) (context.get("numOfControls"));

            boolean verifyAllow = false; //disable RA by default
            try {
                String configName = "cmc.lraPopWitness.verify.allow";
                CMS.debug(methodPos + "getting :" + configName);
                verifyAllow = CMS.getConfigStore().getBoolean(configName, false);
                CMS.debug(methodPos + "cmc.lraPopWitness.verify.allow is " + verifyAllow);
            } catch (Exception e) {
                // unlikely to get here
                String msg = methodPos + " Failed to retrieve cmc.lraPopWitness.verify.allow";
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
                                methodPos + " verify POP in CMC because LRA POP Witness control attribute doesnt exist in the CMC request.");
                        if (crm.hasPop()) {
                            CMS.debug(methodPos + " hasPop true");
                            verifyPOP(locale, crm);
                        } else { // no signing POP, then do it the hard way
                            CMS.debug(methodPos + "hasPop false, need to challenge");
                            req.setExtData("cmc_POPchallengeRequired", "true");
                        }
                    }
                } else {
                    CMS.debug(
                            methodPos + " verify POP in CMC because LRA POP Witness control attribute doesnt exist in the CMC request.");
                    if (crm.hasPop()) {
                        CMS.debug(methodPos + " hasPop true");
                        verifyPOP(locale, crm);
                    } else { // no signing POP, then do it the hard way
                        CMS.debug(methodPos + "hasPop false, need to challenge");
                        req.setExtData("cmc_POPchallengeRequired", "true");
                    }
                }

            } else { //!verifyAllow

                if (crm.hasPop()) {
                    CMS.debug(methodPos + " hasPop true");
                    verifyPOP(locale, crm);
                } else { // no signing POP, then do it the hard way
                    CMS.debug(methodPos + "hasPop false, need to challenge");
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
        String method = "EnrollProfile: fillCertReqMsg: ";
        try {
            CMS.debug(method + "Start parseCertReqMsg ");
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

                /*
                 * there seems to be an issue with constructor in Extension
                 * when feeding SubjectKeyIdentifierExtension;
                 * Special-case it
                 */
                OBJECT_IDENTIFIER SKIoid =
                        new OBJECT_IDENTIFIER(PKIXExtensions.SubjectKey_Id.toString());
                for (int j = 0; j < numexts; j++) {
                    org.mozilla.jss.pkix.cert.Extension jssext =
                            certTemplate.extensionAt(j);
                    boolean isCritical = jssext.getCritical();
                    org.mozilla.jss.asn1.OBJECT_IDENTIFIER jssoid =
                            jssext.getExtnId();
                    CMS.debug(method + "found extension:" + jssoid.toString());
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

                    Extension ext = null;
                    if (jssoid.equals(SKIoid)) {
                        CMS.debug(method + "found SUBJECT_KEY_IDENTIFIER extension");
                        ext = new SubjectKeyIdentifierExtension(false,
                                jssext.getExtnValue().toByteArray());
                    } else {
                        new Extension(oid, isCritical, extValue);
                    }

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
        String method = "EnrollProfile: fillPKCS10: ";
        CMS.debug(method + "begins");
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
                    CMS.debug(method + "Found PKCS10 extension");
                    Extensions exts0 = (Extensions)
                            (p10Attr.getAttributeValue());
                    DerOutputStream extOut = new DerOutputStream();

                    exts0.encode(extOut);
                    byte[] extB = extOut.toByteArray();
                    DerInputStream extIn = new DerInputStream(extB);
                    CertificateExtensions exts = new CertificateExtensions(extIn);
                    if (exts != null) {
                        CMS.debug(method + "PKCS10 found extensions " + exts);
                        // info.set(X509CertInfo.EXTENSIONS, exts);
                        req.setExtData(REQUEST_EXTENSIONS, exts);
                    }
                } else {
                    CMS.debug(method + "PKCS10 no extension found");
                }
            }

            CMS.debug(method + "Finish parsePKCS10 - " + pkcs10.getSubjectName());
        } catch (IOException e) {
            CMS.debug(method + "Unable to fill PKCS #10: " + e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        } catch (CertificateException e) {
            CMS.debug(method + "Unable to fill PKCS #10: " + e);
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

        String method = "EnrollProfile: populate: ";
        CMS.debug(method + "begins");

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
                        AuditEvent.PROFILE_CERT_REQUEST,
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
                        AuditEvent.PROFILE_CERT_REQUEST,
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
                        AuditEvent.PROFILE_CERT_REQUEST,
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
        CMS.debug(method + "for signing keys begins.");

        String auditMessage = method;
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
                CMS.debug(method + "POP verification using internal token");
                certReqMsg.verify();
            } else {
                CMS.debug(method + "POP verification using token:" + tokenName);
                verifyToken = CryptoUtil.getCryptoToken(tokenName);
                certReqMsg.verify(verifyToken);
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    AuditEvent.PROOF_OF_POSSESSION,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    "method="+method);
            audit(auditMessage);
        } catch (Exception e) {
            CMS.debug(method + "Unable to verify POP: " + e);
            popFailed(locale, auditSubjectID, auditMessage, e);
        }
        CMS.debug(method + "done.");
    }

    private void popFailed(Locale locale, String auditSubjectID, String msg)
            throws EProfileException {
        popFailed(locale, auditSubjectID, msg, null);
    }
    private void popFailed(Locale locale, String auditSubjectID, String msg, Exception e)
            throws EProfileException {

            if (e != null)
                msg = msg + e.toString();
            // store a message in the signed audit log file
            String auditMessage = CMS.getLogMessage(
                    AuditEvent.PROOF_OF_POSSESSION,
                    auditSubjectID,
                    ILogger.FAILURE,
                    msg);
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
