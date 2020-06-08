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
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

import javax.crypto.Mac;

import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.server.authentication.IAuthManager;
import org.dogtagpki.server.authentication.IAuthSubsystem;
import org.dogtagpki.server.ca.ICertificateAuthority;
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
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.pkcs.PKCS9Attribute;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertAttrSet;
import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSerialNumber;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.CertificateVersion;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
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

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.ECMCBadIdentityException;
import com.netscape.certsrv.profile.ECMCBadMessageCheckException;
import com.netscape.certsrv.profile.ECMCBadRequestException;
import com.netscape.certsrv.profile.ECMCPopFailedException;
import com.netscape.certsrv.profile.ECMCPopRequiredException;
import com.netscape.certsrv.profile.ECMCUnsupportedExtException;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This class implements a generic enrollment profile.
 *
 * <p>
 * An enrollment profile contains a list of enrollment specific input plugins, default policies, constriant policies and
 * output plugins.
 * <p>
 * This interface also defines a set of enrollment specific attribute names that can be used to retrieve values from an
 * enrollment request.
 * <p>
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public abstract class EnrollProfile extends Profile {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(EnrollProfile.class);

    /**
     * Name of request attribute that stores the User
     * Supplied Certificate Request Type.
     */
    public static final String CTX_CERT_REQUEST_TYPE = "cert_request_type";

    /**
     * Possible values for CTX_CERT_REQUEST_TYPE attribute.
     */
    public static final String REQ_TYPE_PKCS10 = "pkcs10";
    public static final String REQ_TYPE_CRMF = "crmf";
    public static final String REQ_TYPE_CMC = "cmc";
    public static final String REQ_TYPE_KEYGEN = "keygen";

    /**
     * Name of request attribute that stores the End-User Locale.
     * <p>
     * The value is of type java.util.Locale.
     */
    public static final String REQUEST_LOCALE = "req_locale";

    /**
     * Name of request attribute that stores the sequence number. Consider
     * a CRMF request that may contain multiple certificate request.
     * The first sub certificate certificate request has a sequence
     * number of 0, the next one has a sequence of 1, and so on.
     * <p>
     * The value is of type java.lang.Integer.
     */
    public static final String REQUEST_SEQ_NUM = "req_seq_num";

    /**
     * Name of the request attribute that stores the sequence number for a
     * renewal request. Only one request at a time is permitted for a renewal.
     * This value corresponds to the sequence number (and hence the appropriate
     * certificate) of the original request
     */
    public static final String CTX_RENEWAL_SEQ_NUM = "renewal_seq_num";

    /**
     * Name of request attribute to indicate if this is a renewal
     */
    public static final String CTX_RENEWAL = "renewal";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Validity.
     * <p>
     * The value is of type org.mozilla.jss.netscape.security.x509.CertificateValidity
     */
    public static final String REQUEST_VALIDITY = "req_validity";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Signing Algorithm.
     * <p>
     * The value is of type org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId
     */
    public static final String REQUEST_SIGNING_ALGORITHM = "req_signing_alg";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Extensions.
     * <p>
     * The value is of type org.mozilla.jss.netscape.security.x509.CertificateExtensions
     */
    public static final String REQUEST_EXTENSIONS = "req_extensions";

    /**
     * Name of request attribute that stores the certificate template
     * that will be signed and then become a certificate.
     * <p>
     * The value is of type org.mozilla.jss.netscape.security.x509.X509CertInfo
     */
    public static final String REQUEST_CERTINFO = "req_x509info";

    /**
     * Name of request attribute that stores the issued certificate.
     * <p>
     * The value is of type org.mozilla.jss.netscape.security.x509.X509CertImpl
     */
    public static final String REQUEST_ISSUED_CERT = "req_issued_cert";

    /**
     * Name of request attribute that stores the issued P12 from server-side keygen.
     * <p>
     */
    public static final String REQUEST_ISSUED_P12 = "req_issued_p12";

    /**
     * ID of requested certificate authority (absense implies host authority)
     */
    public static final String REQUEST_AUTHORITY_ID = "req_authority_id";

    /**
     * Arbitrary user-supplied data.
     */
    public static final String REQUEST_USER_DATA = "req_user_data";

    public EnrollProfile() {
        super();
    }

    public abstract IAuthority getAuthority();

    public IRequestQueue getRequestQueue() {
        IAuthority authority = getAuthority();

        return authority.getRequestQueue();
    }

    /**
     * Creates request.
     */
    public IRequest[] createRequests(Map<String, String> ctx, Locale locale) throws Exception {

        String method = "EnrollProfile: createRequests: ";
        logger.debug(method + "begins");

        // determine how many requests should be created
        String cert_request_type = ctx.get(CTX_CERT_REQUEST_TYPE);
        String cert_request = ctx.get(IRequest.CTX_CERT_REQUEST);
        String is_renewal = ctx.get(CTX_RENEWAL);
        Integer renewal_seq_num = 0;

        /* cert_request_type can be null for the case of CMC */
        if (cert_request_type == null) {
            logger.debug(method + " request type is null");
        }

        int num_requests = 1; // default to 1 request

        if (cert_request_type != null && cert_request_type.startsWith("pkcs10")) {

            logger.info("EnrollProfile: Parsing PKCS #10 request:");

            PKCS10 pkcs10 = CertUtils.parsePKCS10(locale, cert_request);

            PKCS10Attributes attributes = pkcs10.getAttributes();
            for (PKCS10Attribute attribute : attributes) {

                ObjectIdentifier attrID = attribute.getAttributeId();
                CertAttrSet attrValues = attribute.getAttributeValue();
                String attrName = attrValues.getName();
                logger.info("- " + attrID + ": " + attrName);
            }
        }

        if (cert_request_type != null && cert_request_type.startsWith("crmf")) {
            CertReqMsg[] msgs = CertUtils.parseCRMF(locale, cert_request);
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
            SessionContext sessionContext = SessionContext.getContext();
            String authenticatedSubject =
                    (String) sessionContext.get(IAuthToken.TOKEN_SHARED_TOKEN_AUTHENTICATED_CERT_SUBJECT);

            if (authenticatedSubject != null) {
                ctx.put(IAuthToken.TOKEN_SHARED_TOKEN_AUTHENTICATED_CERT_SUBJECT, authenticatedSubject);
            }

            if (cmc_msgs == null) {
                logger.debug(method + "parseCMC returns cmc_msgs null");
                return null;
            } else {
                num_requests = cmc_msgs.length;
                logger.debug(method + "parseCMC returns cmc_msgs num_requests=" +
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
                    logger.debug(method + "setting cmc TaggedRequest in request");
                    result[i].setExtData(
                            IRequest.CTX_CERT_REQUEST,
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

    /**
     * Set Default X509CertInfo in the request.
     *
     * @param request profile-based certificate request.
     * @exception EProfileException failed to set the X509CertInfo.
     */
    public void setDefaultCertInfo(IRequest request) throws EProfileException {
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
                logger.debug("EnrollProfile: setDefaultCertInfo: setting issuerDN using exact CA signing cert subjectDN encoding");
                info.set(X509CertInfo.ISSUER,
                        authority.getIssuerObj());
            } else {
                logger.debug("EnrollProfile: setDefaultCertInfo: authority.getIssuerObj() is null, creating new CertificateIssuerName");
                info.set(X509CertInfo.ISSUER,
                        new CertificateIssuerName(issuerName));
            }
            info.set(X509CertInfo.KEY,
                    new CertificateX509Key(X509Key.parse(new DerValue(dummykey))));

            info.set(X509CertInfo.SUBJECT,
                    new CertificateSubjectName(new X500Name("")));

            info.set(X509CertInfo.VALIDITY,
                    new CertificateValidity(new Date(), new Date()));
            info.set(X509CertInfo.ALGORITHM_ID,
                    new CertificateAlgorithmId(AlgorithmId.get("SHA256withRSA")));

            // add default extension container
            info.set(X509CertInfo.EXTENSIONS,
                    new CertificateExtensions());
        } catch (Exception e) {
            // throw exception - add key to template
            logger.error("Unable to create X509CertInfo: " + e.getMessage(), e);
            throw new EProfileException(e);
        }
        request.setExtData(REQUEST_CERTINFO, info);
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

            logger.info("EnrollProfile: createEnrollmentRequest " + req.getRequestId());
        } catch (EBaseException e) {
            logger.warn("Unable to create enrollment request: " + e.getMessage(), e);
            // raise exception?
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
            logger.warn("Unable to get requestor DN: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * setPOPchallenge generates a POP challenge and sets necessary info in request
     * for composing encryptedPOP later
     *
     * @param req the request
     */
    public void setPOPchallenge(IRequest req) throws EBaseException {
        String method = "EnrollProfile: setPOPchallenge: ";
        String msg = "";

        logger.debug(method + " getting user public key in request");
        if (req == null) {
            logger.error(method + "method parameters cannot be null");
            throw new EBaseException(method + msg);
        }

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        byte[] req_key_data = req.getExtDataInByteArray(IRequest.REQUEST_KEY);
        if (req_key_data != null) {
            logger.debug(method + "found user public key in request");

            // generate a challenge of 64 bytes;
            SecureRandom random = jssSubsystem.getRandomNumberGenerator();
            byte[] challenge = new byte[64];
            random.nextBytes(challenge);

            ICertificateAuthority authority = (ICertificateAuthority) getAuthority();
            PublicKey issuanceProtPubKey = authority.getIssuanceProtPubKey();
            if (issuanceProtPubKey != null)
                logger.debug(method + "issuanceProtPubKey not null");
            else {
                msg = method + "issuanceProtPubKey null";
                logger.error(msg);
                throw new EBaseException(method + msg);
            }

            try {
                CryptoToken token = null;
                String tokenName = cs.getString("cmc.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                token = CryptoUtil.getCryptoToken(tokenName);

                byte[] iv = CryptoUtil.getNonceData(EncryptionAlgorithm.AES_128_CBC.getIVLength());
                IVParameterSpec ivps = new IVParameterSpec(iv);

                PublicKey userPubKey = X509Key.parsePublicKey(new DerValue(req_key_data));
                if (userPubKey == null) {
                    msg = method + "userPubKey null after X509Key.parsePublicKey";
                    logger.error(msg);
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
                    logger.error(msg);
                    throw new EBaseException(msg);
                }

                byte[] pop_sysPubEncryptedSession =  CryptoUtil.wrapUsingPublicKey(
                        token,
                        issuanceProtPubKey,
                        symKey,
                        KeyWrapAlgorithm.RSA);

                if (pop_sysPubEncryptedSession == null) {
                    msg = method + "pop_sysPubEncryptedSession null";
                    logger.error(msg);
                    throw new EBaseException(msg);
                }


                byte[] pop_userPubEncryptedSession = CryptoUtil.wrapUsingPublicKey(
                        token,
                        userPubKey,
                        symKey,
                        KeyWrapAlgorithm.RSA);

                if (pop_userPubEncryptedSession == null) {
                    msg = method + "pop_userPubEncryptedSession null";
                    logger.error(msg);
                    throw new EBaseException(msg);
                }
                logger.debug(method + "POP challenge fields generated successfully...setting request extData");

                req.setExtData("pop_encryptedData", pop_encryptedData);

                req.setExtData("pop_sysPubEncryptedSession", pop_sysPubEncryptedSession);

                req.setExtData("pop_userPubEncryptedSession", pop_userPubEncryptedSession);

                req.setExtData("pop_encryptedDataIV", iv);

                // now compute and set witness
                logger.debug(method + "now compute and set witness");
                String hashName = CryptoUtil.getDefaultHashAlgName();
                logger.debug(method + "hashName is " + hashName);
                MessageDigest hash = MessageDigest.getInstance(hashName);
                byte[] witness = hash.digest(challenge);
                req.setExtData("pop_witness", witness);

            } catch (Exception e) {
                String message = "Unable to generate POP challenge: " + e.getMessage();
                logger.error(message, e);
                throw new EBaseException(message, e);
            }

        } else {
            logger.error(method + " public key not found in request");
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
        logger.debug(method + "begins");

        boolean popChallengeRequired =
                request.getExtDataInBoolean("cmc_POPchallengeRequired", false);
        logger.debug(method + "popChallengeRequired =" + popChallengeRequired);

        // this profile queues request that is authenticated
        // by NoAuth
        try {
            queue.updateRequest(request);
        } catch (EBaseException e) {
            // save request to disk
            logger.warn("Unable to update request: " + e.getMessage(), e);
        }

        if (token == null){
            logger.debug(method + " auth token is null; agent manual approval required;");
            logger.debug(method + " validating request");
            validate(request);
            try {
                queue.updateRequest(request);
            } catch (EBaseException e) {
                msg = method + " Unable to update request after validation: " + e.getMessage();
                logger.error(msg, e);
                throw new EProfileException(msg, e);
            }
            throw new EDeferException("defer request");
        } else if (popChallengeRequired) {
            // this is encryptedPOP case; defer to require decryptedPOP
            logger.debug(method + " popChallengeRequired, defer to enforce decryptedPOP");
            validate(request);

            logger.debug(method + " about to call setPOPchallenge");
            try {
                setPOPchallenge(request);
                queue.updateRequest(request);
            } catch (EBaseException e) {
                msg = method + e.getMessage();
                logger.error(msg, e);
                throw new EProfileException(msg, e);
            }

            throw new ECMCPopRequiredException(" Return  with DecryptedPOP to complete");

        } else {
            // this profile executes request that is authenticated
            // by non NoAuth
            logger.debug(method + " auth token is not null");
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
            logger.error(msg);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                            msg);
        }
        //logger.debug(method + " Start: " + certReqBlob);
        logger.debug(method + "starts");

        byte[] data = CertUtil.parseCSR(certReqBlob);
        try {
            ByteArrayInputStream cmcBlobIn = new ByteArrayInputStream(data);
            PKIData pkiData = null;

            org.mozilla.jss.pkix.cms.ContentInfo cmcReq = (org.mozilla.jss.pkix.cms.ContentInfo) org.mozilla.jss.pkix.cms.ContentInfo
                    .getTemplate().decode(cmcBlobIn);
            OCTET_STRING content = null;
            if (cmcReq.getContentType().equals(
                    org.mozilla.jss.pkix.cms.ContentInfo.SIGNED_DATA)) {
                logger.debug(method + "cmc request content is signed data");
                org.mozilla.jss.pkix.cms.SignedData cmcFullReq = (org.mozilla.jss.pkix.cms.SignedData) cmcReq
                        .getInterpretedContent();
                org.mozilla.jss.pkix.cms.EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();
                content = ci.getContent();

            } else { // for unsigned revocation requests (using shared secret)
                logger.debug(method + "cmc request content is unsigned data");
                content = (OCTET_STRING) cmcReq.getInterpretedContent();
            }
            ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
            pkiData = (PKIData) (new PKIData.Template()).decode(s);

            //PKIData pkiData = (PKIData)
            //    (new PKIData.Template()).decode(cmcBlobIn);

            return pkiData;

        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
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
            logger.error(msg);
            throw new Exception(msg);
        }

        CMSEngine engine = CMS.getCMSEngine();

        // for CMCUserSignedAuth, the signing user is the subject of
        // the new cert
        ICertificateAuthority authority = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        try {
            BigInteger serialNo = new BigInteger(certSerial);
            userCert = authority.getCertificateRepository().getX509Certificate(serialNo);
        } catch (NumberFormatException e) {
            msg = method + e.getMessage();
            logger.error(msg, e);
            throw new Exception(msg, e);
        } catch (EBaseException e) {
            msg = method + e.getMessage() + "; signing user cert not found: serial=" + certSerial;
            logger.error(msg, e);
            throw new Exception(msg, e);
        }

        if (userCert != null) {
            msg = method + "signing user cert found; serial=" + certSerial;
            logger.info(msg);
        } else {
            msg = method + "signing user cert not found: serial=" + certSerial;
            logger.error(msg);
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
        //logger.debug(method + " Start parseCMC(): " + certreq);
        logger.debug(method + "starts");

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        String auditMessage = "";
        String auditSubjectID = auditSubjectID();

        /* cert request must not be null */
        if (certreq == null) {
            msg = method + "certreq null";
            logger.error(msg);
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
            String authManagerId = (String) context.get(SessionContext.AUTH_MANAGER_ID);
            if (authManagerId == null) {
                logger.debug(method + "authManagerId null.????");
                //unlikely, but...
                authManagerId = "none";
            } else {
                logger.debug(method + "authManagerId =" + authManagerId);
            }
            if(authManagerId.equals("CMCAuth")) {
                donePOI = true;
            }

            boolean id_cmc_revokeRequest = false;
            if (!context.containsKey("numOfControls")) {
                logger.debug(method + "numcontrols="+ numcontrols);
                if (numcontrols > 0) {
                    context.put("numOfControls", Integer.valueOf(numcontrols));
                    TaggedAttribute[] attributes = new TaggedAttribute[numcontrols];
                    boolean id_cmc_decryptedPOP = false;
                    SET decPopVals = null;
                    boolean id_cmc_regInfo = false;
                    SET reqIdVals = null;

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
                    logger.debug(method + "about to pre-process controls");
                    for (int i = 0; i < numcontrols; i++) {
                        attributes[i] = (TaggedAttribute) controlSeq.elementAt(i);
                        OBJECT_IDENTIFIER oid = attributes[i].getType();
                        if (oid.equals(OBJECT_IDENTIFIER.id_cmc_revokeRequest)) {
                            id_cmc_revokeRequest = true;
                            // put in context for processing in
                            // CMCOutputTemplate.java later
                            context.put(OBJECT_IDENTIFIER.id_cmc_revokeRequest,
                                    attributes[i]);
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_decryptedPOP)) {
                            logger.debug(method + " id_cmc_decryptedPOP found");
                            id_cmc_decryptedPOP = true;
                            decPopVals = attributes[i].getValues();
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_regInfo)) {
                            logger.debug(method + "id_cmc_regInfo found");
                            id_cmc_regInfo = true;
                            reqIdVals = attributes[i].getValues();
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_identification)) {
                            logger.debug(method + " id_cmc_identification found");
                            id_cmc_identification = true;
                            ident = attributes[i].getValues();
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_identityProofV2)) {
                            logger.debug(method + " id_cmc_identityProofV2 found");
                            id_cmc_identityProofV2 = true;
                            attr = attributes[i];
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_identityProof)) {
                            logger.debug(method + " id_cmc_identityProof found");
                            id_cmc_identityProof = true;
                            attr = attributes[i];
                        } else if (oid.equals(OBJECT_IDENTIFIER.id_cmc_idPOPLinkRandom)) {
                            logger.debug(method + "id_cmc_idPOPLinkRandom found");
                            id_cmc_idPOPLinkRandom = true;
                            vals = attributes[i].getValues();
                        } else {
                            logger.debug(method + "unknown control found");
                            context.put(attributes[i].getType(), attributes[i]);
                        }
                    } //for

                    /**
                     * now do the actual control processing
                     */
                    logger.debug(method + "processing controls...");

                    if (id_cmc_revokeRequest) {
                        logger.debug(method + "revocation control");
                    }

                    if (id_cmc_identification) {
                        if (ident == null) {
                            msg = "id_cmc_identification contains null attribute value";
                            logger.debug(method + msg);
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identification", bpids);

                            msg = " id_cmc_identification attribute value not found in";
                            logger.error(method + msg);

                            throw new ECMCBadRequestException(
                                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") + ":" +
                                            msg);
                        } else {
                            ident_s = (UTF8String) (ASN1Util.decode(UTF8String.getTemplate(),
                                    ASN1Util.encode(ident.elementAt(0))));
                        }
                        if (ident_s == null) {
                            msg = " id_cmc_identification contains invalid content";
                            logger.error(method + msg);
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identification", bpids);

                            throw new ECMCBadRequestException(
                                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") + ":" +
                                            msg);

                        }
                    }

                    // checking Proof Of Identity, if not pre-signed

                    if (donePOI || id_cmc_revokeRequest) {
                        // for logging purposes
                        if (id_cmc_identityProofV2) {
                            logger.debug(method
                                    + "pre-signed CMC request, but id_cmc_identityProofV2 found...ignore; no further proof of identification check");
                        } else if (id_cmc_identityProof) {
                            logger.debug(method
                                    + "pre-signed CMC request, but id_cmc_identityProof found...ignore; no further proof of identification check");
                        } else {
                            logger.debug(method + "pre-signed CMC request; no further proof of identification check");
                        }
                    } else if (id_cmc_identityProofV2 && (attr != null)) {
                        // either V2 or not V2; can't be both
                        logger.debug(method +
                                "not pre-signed CMC request; calling verifyIdentityProofV2;");
                        if (!id_cmc_identification || ident_s == null) {
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identification", bpids);
                            context.put("identityProofV2", bpids);
                            msg = "id_cmc_identityProofV2 missing id_cmc_identification";
                            logger.error(method + msg);
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    method + msg);
                            signedAuditLogger.log(auditMessage);

                            throw new ECMCBadIdentityException(
                                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") + ":" +
                                            msg);
                        }

                        boolean valid = verifyIdentityProofV2(context, attr, ident_s, reqSeq, pkiData);
                        if (!valid) {
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identityProofV2", bpids);

                            msg = " after verifyIdentityProofV2";
                            logger.error(method + msg);
                            throw new ECMCBadIdentityException(CMS.getUserMessage(locale,
                                    "CMS_POI_VERIFICATION_ERROR") + msg);
                        } else {
                            logger.debug(method + "passed verifyIdentityProofV2; Proof of Identity successful;");
                        }
                    } else if (id_cmc_identityProof && (attr != null)) {
                        logger.debug(method + "not pre-signed CMC request; calling verifyIdentityProof;");
                        boolean valid = verifyIdentityProof(attr, reqSeq, pkiData);
                        if (!valid) {
                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("identityProof", bpids);

                            msg = " after verifyIdentityProof";
                            logger.error(method + msg);
                            throw new ECMCBadIdentityException(CMS.getUserMessage(locale,
                                    "CMS_POI_VERIFICATION_ERROR") + msg);
                        } else {
                            logger.debug(method + "passed verifyIdentityProof; Proof of Identity successful;");
                            // in case it was set
                            auditSubjectID = auditSubjectID();
                        }
                    } else {
                        msg = "not pre-signed CMC request; missing Proof of Identification control";
                        logger.error(method + msg);
                        auditMessage = CMS.getLogMessage(
                                AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                                auditSubjectID,
                                ILogger.FAILURE,
                                method + msg);
                        signedAuditLogger.log(auditMessage);
                        throw new ECMCBadRequestException(CMS.getUserMessage(locale,
                                "CMS_POI_VERIFICATION_ERROR") + ":" + msg);
                    }

                    if (id_cmc_decryptedPOP) {
                        if (decPopVals != null) {
                            if (!id_cmc_regInfo) {
                                msg = "id_cmc_decryptedPOP must be accompanied by id_cmc_regInfo for request id per server/client agreement";
                                logger.error(method + msg);
                                auditMessage = CMS.getLogMessage(
                                        AuditEvent.PROOF_OF_POSSESSION,
                                        auditSubjectID,
                                        ILogger.FAILURE,
                                        method + msg);
                                signedAuditLogger.log(auditMessage);

                                SEQUENCE bpids = getRequestBpids(reqSeq);
                                context.put("decryptedPOP", bpids);
                                throw new ECMCPopFailedException(CMS.getUserMessage(locale,
                                        "CMS_POP_VERIFICATION_ERROR") + ":" + msg);
                            }

                            OCTET_STRING reqIdOS =
                                    (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                                    ASN1Util.encode(reqIdVals.elementAt(0))));

                            DecryptedPOP decPop = (DecryptedPOP) (ASN1Util.decode(DecryptedPOP.getTemplate(),
                                    ASN1Util.encode(decPopVals.elementAt(0))));
                            logger.error(method + "DecryptedPOP encoded");

                            BigInteger reqId = verifyDecryptedPOP(locale, decPop, reqIdOS);
                            if (reqId != null) {
                                context.put("cmcDecryptedPopReqId", reqId);
                            } else {
                                msg = "DecryptedPOP failed to verify";
                                logger.error(method + msg);
                                auditMessage = CMS.getLogMessage(
                                        AuditEvent.PROOF_OF_POSSESSION,
                                        auditSubjectID,
                                        ILogger.FAILURE,
                                        method + msg);
                                signedAuditLogger.log(auditMessage);

                                SEQUENCE bpids = getRequestBpids(reqSeq);
                                context.put("decryptedPOP", bpids);
                                throw new ECMCPopFailedException(CMS.getUserMessage(locale,
                                        "CMS_POP_VERIFICATION_ERROR") + ":" + msg);
                            }
                        } else { //decPopVals == null
                            msg = "id_cmc_decryptedPOP contains invalid DecryptedPOP";
                            logger.error(method + msg);
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.PROOF_OF_POSSESSION,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    method + msg);
                            signedAuditLogger.log(auditMessage);

                            SEQUENCE bpids = getRequestBpids(reqSeq);
                            context.put("decryptedPOP", bpids);
                            throw new ECMCPopFailedException(CMS.getUserMessage(locale,
                                    "CMS_POP_VERIFICATION_ERROR") + ":" + msg);
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
                        logger.debug(method + "got randomSeed");
                    }
                } // numcontrols > 0
            }

            SEQUENCE otherMsgSeq = pkiData.getOtherMsgSequence();
            int numOtherMsgs = otherMsgSeq.size();
            if (!context.containsKey("numOfOtherMsgs")) {
                logger.debug(method + "found numOfOtherMsgs: " + numOtherMsgs);
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
                logger.debug(method + "getting :" + configName);
                popLinkWitnessRequired = cs.getBoolean(configName, false);
                if (popLinkWitnessRequired) {
                    logger.debug(method + "popLinkWitness(V2) required");
                } else {
                    logger.debug(method + "popLinkWitness(V2) not required");
                }
            } catch (Exception e) {
                // unlikely to get here
                msg = " Failed to retrieve cmc.popLinkWitnessRequired: " + e.getMessage();
                logger.error(method + msg, e);
                throw new EProfileException(msg, e);
            }

            int nummsgs = reqSeq.size();
            if (nummsgs > 0) {
                logger.debug(method + "nummsgs =" + nummsgs);
                msgs = new TaggedRequest[reqSeq.size()];
                SEQUENCE bpids = new SEQUENCE();

                boolean valid = true;
                for (int i = 0; i < nummsgs; i++) {
                    msgs[i] = (TaggedRequest) reqSeq.elementAt(i);
                    if (id_cmc_revokeRequest)
                        continue;

                    boolean hasPop = true;
                    if (msgs[i].getType().equals(TaggedRequest.CRMF)) {
                        CertReqMsg crm = msgs[i].getCrm();
                        if (!crm.hasPop())
                            hasPop = false;
                    }
                    if (popLinkWitnessRequired &&
                            hasPop && // popLinkWitness needs POP
                            !context.containsKey("POPLinkWitnessV2") &&
                            !context.containsKey("POPLinkWitness")) {
                        logger.debug(method + "popLinkWitness(V2) required");
                        if (randomSeed == null || ident_s == null) {
                            msg = "missing needed randomSeed or identification for popLinkWitness(V2)";
                            logger.error(method + msg);
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.CMC_ID_POP_LINK_WITNESS,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    method + msg);
                            signedAuditLogger.log(auditMessage);

                            context.put("POPLinkWitnessV2", bpids);
                            throw new ECMCBadRequestException(CMS.getUserMessage(locale,
                                    "CMS_POP_LINK_WITNESS_VERIFICATION_ERROR") + ":" + msg);
                        }

                        // verifyPOPLinkWitness() will determine if this is
                        // POPLinkWitnessV2 or POPLinkWitness
                        // If failure, context is set in verifyPOPLinkWitness
                        valid = verifyPOPLinkWitness(ident_s, randomSeed, msgs[i], bpids, context, pkiData);
                        if (valid == false) {
                            if (context.containsKey("POPLinkWitnessV2"))
                                msg = " in POPLinkWitnessV2";
                            else if (context.containsKey("POPLinkWitness"))
                                msg = " in POPLinkWitness";
                            else
                                msg = " failure from verifyPOPLinkWitness";

                            msg = msg + ": ident_s=" + ident_s;
                            logger.error(method + msg);
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.CMC_ID_POP_LINK_WITNESS,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    method + msg);
                            signedAuditLogger.log(auditMessage);
                            throw new ECMCBadRequestException(CMS.getUserMessage(locale,
                                    "CMS_POP_LINK_WITNESS_VERIFICATION_ERROR") + ":" + msg);
                        } else {
                            msg = ": ident_s=" + ident_s;
                            auditMessage = CMS.getLogMessage(
                                    AuditEvent.CMC_ID_POP_LINK_WITNESS,
                                    auditSubjectID,
                                    ILogger.SUCCESS,
                                    method + msg);
                            signedAuditLogger.log(auditMessage);
                        }
                    }
                } //for
            } else {
                logger.debug(method + "nummsgs 0; returning...");
                return null;
            }

            logger.debug(method + "ends");
            return msgs;
        } catch (ECMCBadMessageCheckException e) {
            throw new ECMCBadMessageCheckException(e);
        } catch (ECMCBadIdentityException e) {
            throw new ECMCBadIdentityException(e);
        } catch (ECMCPopFailedException e) {
            throw new ECMCPopFailedException(e);
        } catch (ECMCBadRequestException e) {
            throw new ECMCBadRequestException(e);
        } catch (EProfileException e) {
            throw new EProfileException(e);
        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
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
    private BigInteger verifyDecryptedPOP(Locale locale,
            DecryptedPOP decPop,
            OCTET_STRING reqIdOS)
            throws EProfileException, ECMCPopFailedException {
        String method = "EnrollProfile: verifyDecryptedPOP: ";
        logger.debug(method + "begins");
        String msg = "";

        if (decPop == null || reqIdOS == null) {
            logger.warn(method + "method parameters cannot be null");
            return null;
        }

        byte[] reqIdBA = reqIdOS.toByteArray();
        BigInteger reqIdBI = new BigInteger(reqIdBA);

        OCTET_STRING witness_os = decPop.getWitness();

        IRequestQueue reqQueue = getRequestQueue();
        IRequest req = null;
        try {
            req = reqQueue.findRequest(new RequestId(reqIdBI));
        } catch (Exception e) {
            msg = method + "after findRequest: " + e.getMessage();
            logger.warn(msg, e);
            return null;
        }

        // now verify the POP witness
        byte[] pop_encryptedData = req.getExtDataInByteArray("pop_encryptedData");
        if (pop_encryptedData == null) {
            msg = method +
                    "pop_encryptedData not found in request:" +
                    reqIdBI.toString();
            logger.warn(msg);
            return null;
        }

        byte[] pop_sysPubEncryptedSession = req.getExtDataInByteArray("pop_sysPubEncryptedSession");
        if (pop_sysPubEncryptedSession == null) {
            msg = method +
                    "pop_sysPubEncryptedSession not found in request:" +
                    reqIdBI.toString();
            logger.warn(msg);
            return null;
        }

        byte[] cmc_msg = req.getExtDataInByteArray(IRequest.CTX_CERT_REQUEST);
        if (cmc_msg == null) {
            msg = method +
                    "cmc_msg not found in request:" +
                    reqIdBI.toString();
            logger.warn(msg);
            return null;
        }

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        ICertificateAuthority authority = (ICertificateAuthority) getAuthority();
        PrivateKey issuanceProtPrivKey = authority.getIssuanceProtPrivKey();
        if (issuanceProtPrivKey != null)
            logger.debug(method + "issuanceProtPrivKey not null");
        else {
            msg = method + "issuanceProtPrivKey null";
            logger.warn(msg);
            return null;
        }

        try {
            CryptoToken token = null;
            String tokenName = cs.getString("cmc.token", CryptoUtil.INTERNAL_TOKEN_NAME);
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
                logger.warn(msg);
                return null;
            }

            byte[] iv = req.getExtDataInByteArray("pop_encryptedDataIV");
            IVParameterSpec ivps = new IVParameterSpec(iv);

            byte[] challenge_b = CryptoUtil.decryptUsingSymmetricKey(
                    token,
                    ivps,
                    pop_encryptedData,
                    symKey,
                    EncryptionAlgorithm.AES_128_CBC);

            if (challenge_b == null) {
                msg = method + "challenge_b null after decryptUsingSymmetricKey returned";
                logger.warn(msg);
                return null;
            }

            MessageDigest digest = MessageDigest.getInstance(CryptoUtil.getDefaultHashAlgName());
            if (digest == null) {
                msg = method + "digest null after decryptUsingSymmetricKey returned";
                logger.warn(msg);
                return null;
            }

            Mac hmac;
            String hmacAlgName = CryptoUtil.getHMACAlgName(CryptoUtil.getDefaultHashAlgName() + "-HMAC");
            hmac = Mac.getInstance(hmacAlgName,"Mozilla-JSS");
            Key secKey = CryptoUtil.importHmacSha1Key(challenge_b);
            hmac.init(secKey);
            hmac.update(cmc_msg);
            byte[] proofValue = hmac.doFinal();

            if (proofValue == null) {
                msg = method + "proofValue null after hmacDigest.digest returned";
                logger.warn(msg);
                return null;
            }
            boolean witnessChecked = Arrays.equals(proofValue, witness_os.toByteArray());
            if (!witnessChecked) {
                msg = method + "POP challenge witness verification failure";
                logger.warn(msg);
                return null;
            }
        } catch (Exception e) {
            msg = e.getMessage();
            logger.error(method + msg, e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST") +
                            e);
        }

        logger.debug(method + "POP challenge verified!");
        req.setExtData("cmc_POPchallengeRequired", "false");

        logger.debug(method + "cmc_POPchallengeRequired set back to false");
        logger.debug(method + "ends");

        return reqIdBI;
    }

    /**
     * getPopLinkWitnessV2control
     */
    protected PopLinkWitnessV2 getPopLinkWitnessV2control(ASN1Value value) {
        String method = "EnrollProfile: getPopLinkWitnessV2control: ";

        ByteArrayInputStream bis = new ByteArrayInputStream(
                ASN1Util.encode(value));
        PopLinkWitnessV2 popLinkWitnessV2 = null;

        try {
            popLinkWitnessV2 = (PopLinkWitnessV2) (new PopLinkWitnessV2.Template()).decode(bis);
        } catch (Exception e) {
            logger.warn(method + e.getMessage(), e);
        }
        return popLinkWitnessV2;
    }

    /**
     * verifyPopLinkWitnessV2
     */
    protected boolean verifyPopLinkWitnessV2(
            PopLinkWitnessV2 popLinkWitnessV2,
            byte[] randomSeed,
            byte[] sharedSecret,
            String ident_string) {
        String method = "EnrollProfile: verifyPopLinkWitnessV2: ";

        if ((popLinkWitnessV2 == null) ||
                (randomSeed == null) ||
                (sharedSecret == null)) {
            logger.warn(method + " method parameters cannot be null");
            return false;
        }
        AlgorithmIdentifier keyGenAlg = popLinkWitnessV2.getKeyGenAlgorithm();
        AlgorithmIdentifier macAlg = popLinkWitnessV2.getMacAlgorithm();
        OCTET_STRING witness = popLinkWitnessV2.getWitness();
        if (keyGenAlg == null) {
            logger.warn(method + " keyGenAlg reurned by popLinkWitnessV2.getWitness is null");
            return false;
        }
        if (macAlg == null) {
            logger.warn(method + " macAlg reurned by popLinkWitnessV2.getWitness is null");
            return false;
        }
        if (witness == null) {
            logger.warn(method + " witness reurned by popLinkWitnessV2.getWitness is null");
            return false;
        }

        byte[] verifyBytes = null;
        try {
            DigestAlgorithm keyGenAlgID = DigestAlgorithm.fromOID(keyGenAlg.getOID());
            MessageDigest keyGenMDAlg = MessageDigest.getInstance(keyGenAlgID.toString());

            HMACAlgorithm macAlgID = HMACAlgorithm.fromOID(macAlg.getOID());
            MessageDigest macMDAlg = MessageDigest
                    .getInstance(CryptoUtil.getHMACtoMessageDigestName(macAlgID.toString()));

            byte[] witness_bytes = witness.toByteArray();

            ByteBuffer bb = null;

            if(ident_string != null) {
                bb = ByteBuffer.allocate(ident_string.getBytes().length + sharedSecret.length);
                bb.put(sharedSecret);
                bb.put(ident_string.getBytes());
                verifyBytes = bb.array();
            } else {
                verifyBytes = sharedSecret;
            }

            boolean result = verifyDigest(
                    verifyBytes,
                    randomSeed,
                    witness_bytes,
                    keyGenMDAlg, macMDAlg);

            //Check ident_string because, verifyBytes will be = sharedSecret otherwise.
            //Let caller clear sharedSecret when the time comes.
            if (ident_string != null) {
                CryptoUtil.obscureBytes(verifyBytes, "random");
            }

            return result;
        } catch (NoSuchAlgorithmException e) {
            logger.warn(method + e.getMessage(), e);
            return false;
        } catch (Exception e) {
            logger.warn(method + e.getMessage(), e);
            return false;
        } finally {
            if (ident_string != null) {
                CryptoUtil.obscureBytes(verifyBytes, "random");
            }
        }
    }

    /*
     * verifyPOPLinkWitness now handles POPLinkWitnessV2;
     */
    private boolean verifyPOPLinkWitness(
            UTF8String ident, byte[] randomSeed, TaggedRequest req,
            SEQUENCE bpids, SessionContext context,
            PKIData pkiData) {

        String method = "EnrollProfile: verifyPOPLinkWitness: ";
        logger.debug(method + "begins.");

        String ident_string = null;
        if (ident != null) {
            ident_string = ident.toString();
        }

        boolean sharedSecretFound = true;
        String configName = "SharedToken";
        char[] sharedSecret = null;
        byte[] sharedSecretBytes = null;
        CMSEngine engine = CMS.getCMSEngine();

        try {

            try {
                IAuthSubsystem authSS = (IAuthSubsystem) engine.getSubsystem(IAuthSubsystem.ID);

                IAuthManager sharedTokenAuth = authSS.getAuthManager(configName);
                if (sharedTokenAuth == null) {
                    logger.debug(method + " Failed to retrieve shared secret authentication plugin class");
                    sharedSecretFound = false;
                }

                IAuthToken authToken = (IAuthToken)
                    context.get(SessionContext.AUTH_TOKEN);

                ISharedToken tokenClass = (ISharedToken) sharedTokenAuth;

                if (ident_string != null) {
                    sharedSecret = tokenClass.getSharedToken(ident_string, authToken);
                } else {
                    sharedSecret = tokenClass.getSharedToken(pkiData);
                }
                if (sharedSecret == null) {
                    sharedSecretFound = false;
                } else {
                    sharedSecretBytes = CryptoUtil.charsToBytes(sharedSecret);
                }

            } catch (Exception e) {
                logger.warn("Unable to verify POP link witness: " + e.getMessage(), e);
                return false;
            }

            INTEGER reqId = null;
            byte[] bv = null;

            if (req.getType().equals(TaggedRequest.PKCS10)) {
                String methodPos = method + "PKCS10: ";
                logger.debug(methodPos + "begins");

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
                            logger.debug(methodPos + "found id_cmc_popLinkWitnessV2");
                            if (ident_string == null) {
                                bpids.addElement(reqId);
                                context.put("identification", bpids);
                                context.put("POPLinkWitnessV2", bpids);
                                String msg = "id_cmc_popLinkWitnessV2 must be accompanied by id_cmc_identification in this server";
                                logger.warn(methodPos + msg);
                                return false;
                            }

                            SET witnessVal = pkcs10Attr.getValues();
                            if (witnessVal.size() > 0) {
                                try {
                                    PopLinkWitnessV2 popLinkWitnessV2 = getPopLinkWitnessV2control(
                                            witnessVal.elementAt(0));
                                    boolean valid = verifyPopLinkWitnessV2(popLinkWitnessV2,
                                            randomSeed,
                                            sharedSecretBytes,
                                            ident_string);
                                    if (!valid) {
                                        bpids.addElement(reqId);
                                        context.put("POPLinkWitnessV2", bpids);
                                        return valid;
                                    }
                                    return true;
                                } catch (Exception ex) {
                                    logger.warn(methodPos + ex.getMessage(), ex);
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
                                    return verifyDigest(sharedSecretBytes,
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
                logger.debug(methodPos + "begins");

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
                            logger.debug(methodPos + "found id_cmc_popLinkWitnessV2");
                            if (ident_string == null) {
                                bpids.addElement(reqId);
                                context.put("identification", bpids);
                                context.put("POPLinkWitnessV2", bpids);
                                String msg = "id_cmc_popLinkWitnessV2 must be accompanied by id_cmc_identification in this server";
                                logger.warn(methodPos + msg);
                                return false;
                            }

                            ASN1Value value = ava.getValue();
                            PopLinkWitnessV2 popLinkWitnessV2 = getPopLinkWitnessV2control(value);

                            boolean valid = verifyPopLinkWitnessV2(popLinkWitnessV2,
                                    randomSeed,
                                    sharedSecretBytes,
                                    ident_string);
                            if (!valid) {
                                bpids.addElement(reqId);
                                context.put("POPLinkWitnessV2", bpids);
                                return valid;
                            }
                        } else if (ava.getOID().equals(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness)) {
                            logger.debug(methodPos + "found id_cmc_idPOPLinkWitness");
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

                            boolean valid = verifyDigest(sharedSecretBytes,
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

        } finally {
            CryptoUtil.obscureBytes(sharedSecretBytes, "random");
            CryptoUtil.obscureChars(sharedSecret);
        }
    }

    private boolean verifyDigest(byte[] sharedSecret, byte[] text, byte[] bv) {
        MessageDigest hashAlg;
        try {
            hashAlg = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException ex) {
            logger.warn("EnrollProfile:verifyDigest: " + ex.getMessage(), ex);
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
        logger.debug(method + "in verifyDigest: hashAlg=" + hashAlg.toString() +
                "; macAlg=" + macAlg.toString());

        if ((sharedSecret == null) ||
            (text == null) ||
            (bv == null) ||
            (hashAlg == null) ||
            (macAlg == null)) {
            logger.warn(method + "method parameters cannot be null");
            return false;
        }
        key = hashAlg.digest(sharedSecret);

	Mac hmac;
        byte[] finalDigest = null;

        try {
            hmac = Mac.getInstance(CryptoUtil.getHMACAlgName(macAlg.getAlgorithm() + "-HMAC"),"Mozilla-JSS");
            Key secKey = CryptoUtil.importHmacSha1Key(key);
            hmac.init(secKey);
            hmac.update(text);
            finalDigest = hmac.doFinal();
        } catch (Exception e) {
	    logger.debug(method + "hmac exception: " + e);
            //Old code expected to get something for finalDigest, possibly null
            finalDigest = null;
        }

        if (finalDigest.length != bv.length) {
            logger.warn(method + " The length of two HMAC digest are not the same.");
            return false;
        }

        for (int j = 0; j < bv.length; j++) {
            if (bv[j] != finalDigest[j]) {
                logger.warn(method + " The content of two HMAC digest are not the same.");
                return false;
            }
        }

        logger.info(method + " The content of two HMAC digest are the same.");
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
            SessionContext sessionContext,
            TaggedAttribute attr,
            UTF8String ident,
            SEQUENCE reqSeq,
            PKIData pkiData) {

        String method = "EnrollProfile:verifyIdentityProofV2: ";
        String msg = "";
        logger.debug(method + " begins");
        boolean verified = false;
        String auditMessage = method;

        if ((attr == null) ||
                (ident == null) ||
                (reqSeq == null)) {
            logger.warn(method + "method parameters cannot be null");
            // this is internal error
            return false;
        }

        CMSEngine engine = CMS.getCMSEngine();
        String ident_string = ident.toString();
        String auditAttemptedCred = null;

        SET vals = attr.getValues(); // getting the IdentityProofV2 structure
        if (vals.size() < 1) {
            msg = " invalid TaggedAttribute in request";
            logger.warn(method + msg);
            auditMessage = CMS.getLogMessage(
                    AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                    auditAttemptedCred,
                    ILogger.FAILURE,
                    method + msg);
            signedAuditLogger.log(auditMessage);
            return false;
        }

        try {
            String configName = "SharedToken";
            IAuthSubsystem authSS = (IAuthSubsystem) engine.getSubsystem(IAuthSubsystem.ID);

            IAuthManager sharedTokenAuth = authSS.getAuthManager(configName);
            if (sharedTokenAuth == null) {
                msg = " Failed to retrieve shared secret authentication plugin class";
                logger.warn(method + msg);
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                        auditAttemptedCred,
                        ILogger.FAILURE,
                        method + msg);
                signedAuditLogger.log(auditMessage);
                return false;
            }

            IAuthToken authToken = (IAuthToken)
                sessionContext.get(SessionContext.AUTH_TOKEN);

            ISharedToken tokenClass = (ISharedToken) sharedTokenAuth;

            char[] token = null;
            if (ident_string != null) {
                auditAttemptedCred = ident_string;
                token = tokenClass.getSharedToken(ident_string, authToken);
            } else
                token = tokenClass.getSharedToken(pkiData);

            if (token == null) {
                msg = " Failed to retrieve shared secret";
                logger.warn(method + msg);
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                        auditAttemptedCred,
                        ILogger.FAILURE,
                        method + msg);
                signedAuditLogger.log(auditMessage);
                return false;
            }

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
                logger.error(method + msg);
                throw new EBaseException(msg);
            }

            byte[] witness_bytes = witness.toByteArray();
            byte[] request_bytes = ASN1Util.encode(reqSeq); // PKIData reqSequence field

            byte[] verifyBytes = null;
            ByteBuffer bb = null;

            byte[] tokenBytes = CryptoUtil.charsToBytes(token);

            if(ident_string != null) {
                bb = ByteBuffer.allocate(ident_string.getBytes().length + token.length);
                bb.put(tokenBytes);
                bb.put(ident_string.getBytes());
                verifyBytes = bb.array();
            } else {
                verifyBytes = tokenBytes;
            }


            verified = verifyDigest(
                    verifyBytes,
                    request_bytes,
                    witness_bytes,
                    hashAlg, macAlg);

            String auditSubjectID = null;

            if(ident_string != null) {
                CryptoUtil.obscureBytes(verifyBytes, "random");
            }

            CryptoUtil.obscureChars(token);

            if (verified) {
                auditSubjectID = (String) sessionContext.get(SessionContext.USER_ID);
                logger.debug(method + "current auditSubjectID was:" + auditSubjectID);
                logger.debug(method + "identity verified. Updating auditSubjectID");
                logger.debug(method + "updated auditSubjectID is:" + ident_string);
                auditSubjectID = ident_string;
                sessionContext.put(SessionContext.USER_ID, auditSubjectID);

                // subjectdn from SharedSecret ldap auth
                // set in context and authToken to be used by profile
                // default and constraints plugins
                authToken.set(IAuthToken.TOKEN_SHARED_TOKEN_AUTHENTICATED_CERT_SUBJECT,
                        authToken.getInString(IAuthToken.TOKEN_CERT_SUBJECT));
                authToken.set(IAuthToken.TOKEN_AUTHENTICATED_CERT_SUBJECT,
                        authToken.getInString(IAuthToken.TOKEN_CERT_SUBJECT));
                sessionContext.put(IAuthToken.TOKEN_SHARED_TOKEN_AUTHENTICATED_CERT_SUBJECT,
                        authToken.getInString(IAuthToken.TOKEN_CERT_SUBJECT));

                auditMessage = CMS.getLogMessage(
                        AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        "method=" + method);
                signedAuditLogger.log(auditMessage);
            } else {
                msg = "IdentityProofV2 failed to verify";
                logger.error(method + msg);
                throw new EBaseException(msg);
            }
            return verified;
        } catch (Exception e) {
            logger.error(method + " Failed with Exception: " + e.getMessage(), e);
            auditMessage = CMS.getLogMessage(
                    AuditEvent.CMC_PROOF_OF_IDENTIFICATION,
                    auditAttemptedCred,
                    ILogger.FAILURE,
                    method + e.toString());
            signedAuditLogger.log(auditMessage);
            return false;
        }

    } // verifyIdentityProofV2

    private boolean verifyIdentityProof(TaggedAttribute attr, SEQUENCE reqSeq, PKIData pkiData) {

        String method = "verifyIdentityProof: ";
        boolean verified = false;

        SET vals = attr.getValues();
        if (vals.size() < 1)
            return false;

        String configName = "cmc.sharedSecret.class";
        CMSEngine engine = CMS.getCMSEngine();
        ISharedToken tokenClass = engine.getSharedTokenClass(configName);
        if (tokenClass == null) {
            logger.warn(method + " Failed to retrieve shared secret authentication plugin class");
            return false;
        }

        OCTET_STRING ostr = null;
        char[] token = null;
        try {
            token = tokenClass.getSharedToken(pkiData);
            ostr = (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                    ASN1Util.encode(vals.elementAt(0))));
        } catch (InvalidBERException e) {
            logger.warn(method + "Failed to decode the byte value: " + e.getMessage(), e);
            CryptoUtil.obscureChars(token);
            return false;
        } catch (Exception e) {
            logger.warn(method + "exception: " + e.getMessage(), e);
            return false;
        }
        byte[] b = ostr.toByteArray();
        byte[] text = ASN1Util.encode(reqSeq);

        byte[] verifyBytes = CryptoUtil.charsToBytes(token);
        verified = verifyDigest(verifyBytes, text, b);
        if (verified) {// update auditSubjectID
            //placeholder. Should probably just disable this v1 method
        }

        CryptoUtil.obscureBytes(verifyBytes, "random");
        CryptoUtil.obscureChars(token);

        return verified;
    }

    public void fillTaggedRequest(Locale locale, TaggedRequest tagreq, X509CertInfo info,
            IRequest req)
            throws EProfileException, ECMCPopFailedException, ECMCBadRequestException {

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        String method = "EnrollProfile: fillTaggedRequest: ";
        logger.debug(method + "begins");
        TaggedRequest.Type type = tagreq.getType();
        if (type == null) {
            logger.error(method + "TaggedRequest type == null");
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST")+
                    "TaggedRequest type null");
        }

        if (type.equals(TaggedRequest.PKCS10)) {
            String methodPos = method + "PKCS10: ";
            logger.debug(methodPos + " TaggedRequest type == pkcs10");
            boolean sigver = true;
            boolean tokenSwitched = false;
            CryptoManager cm = null;
            CryptoToken signToken = null;
            CryptoToken savedToken = null;
            try {
                // for PKCS10, "sigver" would provide the POP
                sigver = cs.getBoolean("ca.requestVerify.enabled", true);
                cm = CryptoManager.getInstance();
                if (sigver == true) {
                    logger.debug(methodPos + "sigver true, POP is to be verified");
                    String tokenName = cs.getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
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
                    logger.debug(methodPos + "sigver false, POP is not to be verified now, but instead will be challenged");
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
                    signedAuditLogger.log(auditMessage);
                }

                req.setExtData("bodyPartId", tcr.getBodyPartID());
                fillPKCS10(locale, pkcs10, info, req);
            } catch (Exception e) {
                logger.warn(method + e.getMessage(), e);
                // this will throw
                if (sigver)
                    popFailed(locale, auditSubjectID, auditMessage, e);
            }  finally {
                if ((sigver == true) && (tokenSwitched == true)){
                    cm.setThreadToken(savedToken);
                }
            }
            logger.debug(methodPos + "done");
        } else if (type.equals(TaggedRequest.CRMF)) {
            String methodPos = method + "CRMF: ";
            logger.debug(methodPos + " TaggedRequest type == crmf");
            CertReqMsg crm = tagreq.getCrm();
            SessionContext context = SessionContext.getContext();
            Integer nums = (Integer) (context.get("numOfControls"));

            boolean verifyAllow = false; //disable RA by default
            try {
                String configName = "cmc.lraPopWitness.verify.allow";
                logger.debug(methodPos + "getting :" + configName);
                verifyAllow = cs.getBoolean(configName, false);
                logger.debug(methodPos + "cmc.lraPopWitness.verify.allow is " + verifyAllow);
            } catch (Exception e) {
                // unlikely to get here
                String msg = methodPos + " Failed to retrieve cmc.lraPopWitness.verify.allow: " + e.getMessage();
                logger.error(msg, e);
                throw new EProfileException(method + msg, e);
            }
            if (verifyAllow) {
                // check if the LRA POP Witness Control attribute exists
                if (nums != null && nums.intValue() > 0) {
                    TaggedAttribute attr = (TaggedAttribute) (context.get(OBJECT_IDENTIFIER.id_cmc_lraPOPWitness));
                    if (attr != null) {
                        parseLRAPopWitness(locale, crm, attr);
                    } else {
                        logger.debug(
                                methodPos + " verify POP in CMC because LRA POP Witness control attribute doesnt exist in the CMC request.");
                        if (crm.hasPop()) {
                            logger.debug(methodPos + " hasPop true");
                            verifyPOP(locale, crm);
                        } else { // no signing POP, then do it the hard way
                            logger.debug(methodPos + "hasPop false, need to challenge");
                            req.setExtData("cmc_POPchallengeRequired", "true");
                        }
                    }
                } else {
                    logger.debug(
                            methodPos + " verify POP in CMC because LRA POP Witness control attribute doesnt exist in the CMC request.");
                    if (crm.hasPop()) {
                        logger.debug(methodPos + " hasPop true");
                        verifyPOP(locale, crm);
                    } else { // no signing POP, then do it the hard way
                        logger.debug(methodPos + "hasPop false, need to challenge");
                        req.setExtData("cmc_POPchallengeRequired", "true");
                    }
                }

            } else { //!verifyAllow

                if (crm.hasPop()) {
                    logger.debug(methodPos + " hasPop true");
                    verifyPOP(locale, crm);
                } else { // no signing POP, then do it the hard way
                    logger.debug(methodPos + "hasPop false, need to challenge");
                    req.setExtData("cmc_POPchallengeRequired", "true");
                }
            }

            fillCertReqMsg(locale, crm, info, req);
        } else {
            logger.error(method + " unsupported type (not CRMF or PKCS10)");
            throw new ECMCBadRequestException(
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
                logger.error("Unable to parse LRA POP Witness: " + e.getMessage(), e);
                throw new EProfileException(
                        CMS.getUserMessage(locale, "CMS_PROFILE_ENCODING_ERROR"), e);
            }

            SEQUENCE bodyIds = lraPop.getBodyIds();
            reqId = crm.getCertReq().getCertReqId();

            for (int i = 0; i < bodyIds.size(); i++) {
                INTEGER num = (INTEGER) (bodyIds.elementAt(i));
                if (num.toString().equals(reqId.toString())) {
                    donePOP = true;
                    logger.debug("EnrollProfile: skip POP for request: "
                            + reqId + " because LRA POP Witness control is found.");
                    break;
                }
            }
        }

        if (!donePOP) {
            logger.debug("EnrollProfile: not skip POP for request: "
                    + reqId
                    + " because this request id is not part of the body list in LRA Pop witness control.");
            verifyPOP(locale, crm);
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
            logger.warn("EnrollProfile: getPKIArchiveOptions " + e.getMessage(), e);
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
            logger.warn("EnrollProfile: toPKIArchiveOptions " + e.getMessage(), e);
        }
        return archOpts;
    }

    public byte[] toByteArray(PKIArchiveOptions options) {
        return ASN1Util.encode(options);
    }

    public void fillCertReqMsg(Locale locale, CertReqMsg certReqMsg, X509CertInfo info,
            IRequest req)
            throws EProfileException, ECMCUnsupportedExtException {
        String method = "EnrollProfile: fillCertReqMsg: ";
        logger.debug(method + "Start parseCertReqMsg ");

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        try {
            CertRequest certReq = certReqMsg.getCertReq();
            req.setExtData("bodyPartId", certReq.getCertReqId());
            // handle PKIArchiveOption (key archival)
            for (int i = 0; i < certReq.numControls(); i++) {
                AVA ava = certReq.controlAt(i);

                if (ava.getOID().equals(PKIARCHIVEOPTIONS_OID)) {
                    PKIArchiveOptions opt = getPKIArchiveOptions(ava);

                    //req.set(REQUEST_ARCHIVE_OPTIONS, opt);
                    req.setExtData(IRequest.REQUEST_ARCHIVE_OPTIONS,
                            toByteArray(opt));
                    try {
                        String transportCert = cs.getString("ca.connector.KRA.transportCert", "");
                        req.setExtData(IRequest.REQUEST_TRANSPORT_CERT, transportCert);
                    } catch (EBaseException ee) {
                        logger.warn("EnrollProfile: fillCertReqMsg - Exception reading transportCert: " + ee.getMessage(), ee);
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
            req.setExtData(IRequest.REQUEST_KEY, certKeyOut.toByteArray());

            // parse validity
            if (certTemplate.getNotBefore() != null ||
                    certTemplate.getNotAfter() != null) {
                logger.debug("EnrollProfile:  requested notBefore: " + certTemplate.getNotBefore());
                logger.debug("EnrollProfile:  requested notAfter:  " + certTemplate.getNotAfter());
                logger.debug("EnrollProfile:  current CA time:     " + new Date());
                CertificateValidity certValidity = new CertificateValidity(
                        certTemplate.getNotBefore(), certTemplate.getNotAfter());
                ByteArrayOutputStream certValidityOut =
                        new ByteArrayOutputStream();
                certValidity.encode(certValidityOut);
                req.setExtData(REQUEST_VALIDITY, certValidityOut.toByteArray());
            } else {
                logger.debug("EnrollProfile:  validity not supplied");
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

                req.setExtData(IRequest.REQUEST_SUBJECT_NAME,
                        new CertificateSubjectName(subject));
                try {
                    String subjectCN = subject.getCommonName();
                    if (subjectCN == null)
                        subjectCN = "";
                    req.setExtData(IRequest.REQUEST_SUBJECT_NAME + ".cn", subjectCN);
                } catch (Exception ee) {
                    req.setExtData(IRequest.REQUEST_SUBJECT_NAME + ".cn", "");
                }
                try {
                    String subjectUID = subject.getUserID();
                    if (subjectUID == null)
                        subjectUID = "";
                    req.setExtData(IRequest.REQUEST_SUBJECT_NAME + ".uid", subjectUID);
                } catch (Exception ee) {
                    req.setExtData(IRequest.REQUEST_SUBJECT_NAME + ".uid", "");
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
                    logger.debug(method + "found extension:" + jssoid.toString());
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
                        logger.debug(method + "found SUBJECT_KEY_IDENTIFIER extension");
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
            logger.error("Unable to fill certificate request message: " + e.getMessage(), e);
            throw new ECMCUnsupportedExtException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);

        } catch (InvalidKeyException e) {
            logger.error("Unable to fill certificate request message: " + e.getMessage(), e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        // } catch (CertificateException e) {
        //     logger.error(e);
        //     throw new EProfileException(e);
        }
    }

    public void fillPKCS10(Locale locale, PKCS10 pkcs10, X509CertInfo info, IRequest req)
            throws EProfileException, ECMCUnsupportedExtException {

        logger.info("EnrollProfile: Filling PKCS #10 data");

        X509Key key = pkcs10.getSubjectPublicKeyInfo();
        logger.info("EnrollProfile: Key algorithm: " + key.getAlgorithm());

        try {
            CertificateX509Key certKey = new CertificateX509Key(key);

            ByteArrayOutputStream certKeyOut = new ByteArrayOutputStream();
            certKey.encode(certKeyOut);
            req.setExtData(IRequest.REQUEST_KEY, certKeyOut.toByteArray());

            X500Name subjectName = pkcs10.getSubjectName();
            logger.info("EnrollProfile: Subject name: " + subjectName);

            req.setExtData(IRequest.REQUEST_SUBJECT_NAME, new CertificateSubjectName(subjectName));

            String subjectCN;
            try {
                subjectCN = subjectName.getCommonName();
                if (subjectCN == null) subjectCN = "";

            } catch (Exception e) {
                // TODO: Change X500Name.getCommonName() to return null if CN is missing.
                subjectCN = "";
            }

            logger.info("EnrollProfile: Subject CN: " + subjectCN);
            req.setExtData(IRequest.REQUEST_SUBJECT_NAME + ".cn", subjectCN);

            String subjectUID;
            try {
                subjectUID = subjectName.getUserID();
                if (subjectUID == "") subjectUID = "";

            } catch (Exception e) {
                // TODO: Change X500Name.getUserID() to return null if UID is missing.
                subjectUID = "";
            }

            logger.info("EnrollProfile: Subject UID: " + subjectUID);
            req.setExtData(IRequest.REQUEST_SUBJECT_NAME + ".uid", subjectUID);

            info.set(X509CertInfo.KEY, certKey);

            PKCS10Attributes p10Attrs = pkcs10.getAttributes();
            if (p10Attrs != null) {

                logger.info("EnrollProfile: Attributes:");

                for (Enumeration<PKCS10Attribute> e = p10Attrs.getElements(); e.hasMoreElements(); ) {
                    PKCS10Attribute p10Attr = e.nextElement();
                    logger.info("EnrollProfile: - " + p10Attr.getAttributeId());
                }

                PKCS10Attribute p10Attr = p10Attrs.getAttribute(CertificateExtensions.NAME);

                if (p10Attr != null &&
                        p10Attr.getAttributeId().equals(PKCS9Attribute.EXTENSION_REQUEST_OID)) {

                    logger.debug("EnrollProfile: Extensions:");

                    Extensions extensions = (Extensions) p10Attr.getAttributeValue();

                    Enumeration<String> extNames = extensions.getAttributeNames();
                    while (extNames.hasMoreElements()) {
                        String name = extNames.nextElement();
                        logger.info("EnrollProfile: - " + name);
                    }

                    DerOutputStream extOut = new DerOutputStream();

                    extensions.encode(extOut);
                    byte[] extB = extOut.toByteArray();
                    DerInputStream extIn = new DerInputStream(extB);

                    CertificateExtensions certExts = new CertificateExtensions(extIn);

                    // info.set(X509CertInfo.EXTENSIONS, certExts);
                    req.setExtData(REQUEST_EXTENSIONS, certExts);
                }
            }

        } catch (IOException e) {
            logger.error("Unable to fill PKCS #10 data: " + e.getMessage(), e);
            throw new ECMCUnsupportedExtException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);

        } catch (CertificateException e) {
            logger.error("Unable to fill PKCS #10 data: " + e.getMessage(), e);
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
            key.decode(Utils.base64decode(skey));

            info.set(X509CertInfo.KEY, new CertificateX509Key(key));
            //                      req.set(EnrollProfile.REQUEST_SUBJECT_NAME,
            //                              new CertificateSubjectName(new
            //                              X500Name("CN="+sn)));
            req.setExtData("screenname", sn);
            // keeping "aoluid" to be backward compatible
            req.setExtData("aoluid", sn);
            req.setExtData("uid", sn);

            logger.info("EnrollProfile: fillNSNKEY(): uid=" + sn);

        } catch (Exception e) {
            logger.error("Unable to fill NSNKEY: " + e.getMessage(), e);
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
            key.decode(Utils.base64decode(skey));

            info.set(X509CertInfo.KEY, new CertificateX509Key(key));
            //                      req.set(EnrollProfile.REQUEST_SUBJECT_NAME,
            //                              new CertificateSubjectName(new
            //                              X500Name("CN="+sn)));
            req.setExtData("tokencuid", tcuid);

            logger.info("EnrollProfile: fillNSNKEY(): tokencuid=" + tcuid);

        } catch (Exception e) {
            logger.error("Unable to fill NSHKEY: " + e.getMessage(), e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
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
            req.setExtData(IRequest.REQUEST_KEY, certKeyOut.toByteArray());
            info.set(X509CertInfo.KEY, certKey);

        } catch (IOException e) {
            logger.error("Unable to fill key gen: " + e.getMessage(), e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);

        } catch (CertificateException e) {
            logger.error("Unable to fill key gen: " + e.getMessage(), e);
            throw new EProfileException(
                    CMS.getUserMessage(locale, "CMS_PROFILE_INVALID_REQUEST"), e);
        }
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
     * @exception Exception an error related to this profile has occurred
     */
    public void populateInput(Map<String, String> ctx, IRequest request) throws Exception {
        super.populateInput(ctx, request);
    }

    public void populate(IRequest request)
            throws EProfileException {

        String method = "EnrollProfile: populate: ";
        logger.debug(method + "begins");

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

        logger.debug("EnrollProfile.validate: start");

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
                    logger.debug("EnrollProfile.validate: cert subject name:" +
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

            signedAuditLogger.log(auditMessage);
        } catch (CertificateException e) {
            logger.warn("EnrollProfile: populate " + e.getMessage(), e);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.PROFILE_CERT_REQUEST,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        auditProfileID,
                        auditCertificateSubjectName);

            signedAuditLogger.log(auditMessage);
        } catch (IOException e) {
            logger.warn("EnrollProfile: populate " + e.getMessage(), e);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.PROFILE_CERT_REQUEST,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        auditProfileID,
                        auditCertificateSubjectName);

            signedAuditLogger.log(auditMessage);
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
            logger.debug("EnrollProfile.validate: certInfo : \n" + info);
        } catch (NullPointerException e) {
            // do nothing
        }
        */
        logger.debug("EnrollProfile.validate: end");
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
            throws EProfileException, ECMCPopFailedException {
        String method = "EnrollProfile: verifyPOP: ";
        logger.debug(method + "for signing keys begins.");

        String auditMessage = method;
        String auditSubjectID = auditSubjectID();

        if (!certReqMsg.hasPop()) {
            logger.debug(method + "missing pop.");
            popFailed(locale, auditSubjectID, auditMessage);
        }
        ProofOfPossession pop = certReqMsg.getPop();
        ProofOfPossession.Type popType = pop.getType();

        if (popType != ProofOfPossession.SIGNATURE) {
            logger.debug(method + "pop type is not ProofOfPossession.SIGNATURE.");
            popFailed(locale, auditSubjectID, auditMessage);
        }

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        try {
            CryptoToken verifyToken = null;
            String tokenName = cs.getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
            if (CryptoUtil.isInternalToken(tokenName)) {
                logger.debug(method + "POP verification using internal token");
                certReqMsg.verify();
            } else {
                logger.debug(method + "POP verification using token:" + tokenName);
                verifyToken = CryptoUtil.getCryptoToken(tokenName);
                certReqMsg.verify(verifyToken);
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    AuditEvent.PROOF_OF_POSSESSION,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    "method="+method);
            signedAuditLogger.log(auditMessage);
        } catch (Exception e) {
            logger.debug(method + "Unable to verify POP: " + e);
            popFailed(locale, auditSubjectID, auditMessage, e);
        }
        logger.debug(method + "done.");
    }

    private void popFailed(Locale locale, String auditSubjectID, String msg)
            throws EProfileException, ECMCPopFailedException {
        popFailed(locale, auditSubjectID, msg, null);
    }
    private void popFailed(Locale locale, String auditSubjectID, String msg, Exception e)
            throws EProfileException, ECMCPopFailedException {

            if (e != null)
                msg = msg + e.toString();
            // store a message in the signed audit log file
            String auditMessage = CMS.getLogMessage(
                    AuditEvent.PROOF_OF_POSSESSION,
                    auditSubjectID,
                    ILogger.FAILURE,
                    msg);
            signedAuditLogger.log(auditMessage);

            if (e != null) {
                throw new ECMCPopFailedException(CMS.getUserMessage(locale,
                        "CMS_POP_VERIFICATION_ERROR"), e);
            } else {
                throw new ECMCPopFailedException(CMS.getUserMessage(locale,
                        "CMS_POP_VERIFICATION_ERROR"));
            }
    }
}
