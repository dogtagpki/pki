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
// package statement //
///////////////////////

package com.netscape.cms.authentication;

///////////////////////
// import statements //
///////////////////////

/* cert server imports */
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.pkcs10.CertificationRequest;
import org.mozilla.jss.pkcs11.PK11ECPublicKey;
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
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

import netscape.security.pkcs.PKCS10;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

//import com.netscape.cmscore.util.*;
//////////////////////
// class definition //
//////////////////////

/**
 * User Signed CMC authentication plug-in
 * note:
 * - this version differs from CMCAuth in that it allows non-agent users
 * to sign own cmc requests; It is expected to be used with
 * CMCUserSignedSubjectNameDefault and CMCUserSignedSubjectNameConstraint
 * so that the resulting cert will bear the same subjectDN of that of the CMC
 * signing cert
 * - it originates from CMCAuth with modification for user-signed cmc
 *
 * @author cfu - user signed cmc authentication
 *         <P>
 *
 * @version $Revision$, $Date$
 */
public class CMCUserSignedAuth implements IAuthManager, IExtendedPluginInfo,
        IProfileAuthenticator {

    ////////////////////////
    // default parameters //
    ////////////////////////

    // only one request for self-signed
    boolean selfSigned = false;
    SubjectKeyIdentifierExtension selfsign_skiExtn = null;
    PK11PubKey selfsign_pubK = null;
    byte[] selfsign_digest = null;

    /////////////////////////////
    // IAuthManager parameters //
    /////////////////////////////

    /* authentication plug-in configuration store */
    private IConfigStore mConfig;
    private static final String HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    private static final String TRAILER = "-----END NEW CERTIFICATE REQUEST-----";
    public static final String TOKEN_CERT_SERIAL = "certSerialToRevoke";
    public static final String REASON_CODE = "reasonCode";
    /* authentication plug-in name */
    private String mImplName = null;

    /* authentication plug-in instance name */
    private String mName = null;

    /* authentication plug-in fields */

    /* Holds authentication plug-in fields accepted by this implementation.
     * This list is passed to the configuration console so configuration
     * for instances of this implementation can be configured through the
     * console.
     */
    protected static String[] mConfigParams = new String[] {};

    /* authentication plug-in values */

    /* authentication plug-in properties */

    /* required credentials to authenticate. UID and CMC are strings. */
    public static final String CRED_CMC = "cmcRequest";

    protected static String[] mRequiredCreds = {};

    ////////////////////////////////////
    // IExtendedPluginInfo parameters //
    ////////////////////////////////////

    /* Vector of extendedPluginInfo strings */
    protected static Vector<String> mExtendedPluginInfo = null;
    //public static final String AGENT_AUTHMGR_ID = "agentAuthMgr";
    //public static final String AGENT_PLUGIN_ID = "agentAuthPlugin";

    /* actual help messages */
    static {
        mExtendedPluginInfo = new Vector<String>();

        mExtendedPluginInfo
                .add(IExtendedPluginInfo.HELP_TEXT +
                        ";Authenticate the CMC request. The \"Authentication Instance ID\" must be named \"CMCUserSignedAuth\"");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-authentication");
    }

    ///////////////////////
    // Logger parameters //
    ///////////////////////

    /* the system's logger */
    private ILogger mLogger = CMS.getLogger();

    /* signed audit parameters */
    private ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    private final static String SIGNED_AUDIT_ENROLLMENT_REQUEST_TYPE = "enrollment";
    private final static String SIGNED_AUDIT_REVOCATION_REQUEST_TYPE = "revocation";

    /////////////////////
    // default methods //
    /////////////////////

    /**
     * Default constructor, initialization must follow.
     */
    public CMCUserSignedAuth() {
    }

    //////////////////////////
    // IAuthManager methods //
    //////////////////////////

    /**
     * Initializes the CMCUserSignedAuth authentication plug-in.
     * <p>
     *
     * @param name The name for this authentication plug-in instance.
     * @param implName The name of the authentication plug-in.
     * @param config - The configuration store for this instance.
     * @exception EBaseException If an error occurs during initialization.
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        log(ILogger.LL_INFO, "Initialization complete!");
    }

    /**
     * Authenticates user by their CMC;
     * resulting AuthToken sets a TOKEN_SUBJECT for the subject name.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CMC_USER_SIGNED_REQUEST_SIG_VERIFY used when CMC
     *  (user-pre-signed or self-signed) cert
     * requests or revocation requests are submitted and signature is verified
     * </ul>
     *
     * @param authCred Authentication credentials, CRED_UID and CRED_CMC.
     * @return an AuthToken
     * @exception com.netscape.certsrv.authentication.EMissingCredential
     *                If a required authentication credential is missing.
     * @exception com.netscape.certsrv.authentication.EInvalidCredentials
     *                If credentials failed authentication.
     * @exception com.netscape.certsrv.base.EBaseException
     *                If an internal error occurred.
     * @see com.netscape.certsrv.authentication.AuthToken
     */
    public IAuthToken authenticate(IAuthCredentials authCred) throws EMissingCredential, EInvalidCredentials,
            EBaseException {
        String method = "CMCUserSignedAuth: authenticate: ";
        String msg = "";
        CMS.debug(method + "begins");

        String auditMessage = null;
        String auditSubjectID = getAuditSubjectID();
        String auditReqType = ILogger.UNIDENTIFIED;
        String requestCertSubject = ILogger.UNIDENTIFIED;
        String auditSignerInfo = ILogger.UNIDENTIFIED;

        SessionContext auditContext = SessionContext.getExistingContext();

        // create audit context if clientCert exists
        X509Certificate clientCert =
               (X509Certificate) auditContext.get(SessionContext.SSL_CLIENT_CERT);
        // null is okay, as it is not required in case of self-sign;
        // will be checked later
        if (clientCert != null) {
            try {
                createAuditSubjectFromCert(auditContext, clientCert);
            } catch (IOException e) { 
               //unlikely, and not necessarily required at this point
               CMS.debug("CMSUserSignedAuth: authenticate: after createAuditSubjectFromCert call; " + e);
            }
        }

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // get the CMC.

            Object argblock = authCred.getArgBlock();
            Object returnVal = null;
            if (argblock == null) {
                returnVal = authCred.get("cert_request");
                if (returnVal == null)
                    returnVal = authCred.get(CRED_CMC);
            } else {
                returnVal = authCred.get("cert_request");
                if (returnVal == null)
                    returnVal = authCred.getArgBlock().get(CRED_CMC);
            }
            String cmc = (String) returnVal;
            if (cmc == null) {
                CMS.debug(method + " Authentication failed. Missing CMC.");

                throw new EMissingCredential(CMS.getUserMessage(
                        "CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_CMC));
            }

            if (cmc.equals("")) {
                msg = "attempted login with empty cert_request in authCred.";
                CMS.debug(method + msg);

                throw new EInvalidCredentials(msg);
            }

            // authenticate by checking CMC.

            // everything OK.
            // now formulate the certificate info.
            // set the subject name at a minimum.
            // set anything else like version, extensions, etc.
            // if nothing except subject name is set the rest of
            // cert info will be filled in by policies and CA defaults.

            AuthToken authToken = new AuthToken(this);

            try {
                String asciiBASE64Blob;

                int startIndex = cmc.indexOf(HEADER);
                int endIndex = cmc.indexOf(TRAILER);
                if (startIndex != -1 && endIndex != -1) {
                    startIndex = startIndex + HEADER.length();
                    asciiBASE64Blob = cmc.substring(startIndex, endIndex);
                } else
                    asciiBASE64Blob = cmc;

                byte[] cmcBlob = CMS.AtoB(asciiBASE64Blob);
                ByteArrayInputStream cmcBlobIn = new ByteArrayInputStream(cmcBlob);

                org.mozilla.jss.pkix.cms.ContentInfo cmcReq = (org.mozilla.jss.pkix.cms.ContentInfo) org.mozilla.jss.pkix.cms.ContentInfo
                        .getTemplate().decode(
                                cmcBlobIn);

                String userid = ILogger.UNIDENTIFIED;
                String uid = ILogger.UNIDENTIFIED;

                SignedData cmcFullReq = null;
                OCTET_STRING content = null;
                OBJECT_IDENTIFIER id = null;
                org.mozilla.jss.pkix.cms.SignerInfo selfsign_signerInfo = null;
                if (cmcReq.getContentType().equals(
                        org.mozilla.jss.pkix.cms.ContentInfo.SIGNED_DATA)) {
                    CMS.debug(method + "cmc request content is signed data");
                    cmcFullReq = (SignedData) cmcReq.getInterpretedContent();

                    IConfigStore cmc_config = CMS.getConfigStore();
                    boolean checkSignerInfo = cmc_config.getBoolean("cmc.signerInfo.verify", true);
                    if (checkSignerInfo) {
                        // selfSigned will be set in verifySignerInfo if applicable
                        IAuthToken userToken = verifySignerInfo(auditContext, authToken, cmcFullReq);
                        if (userToken == null) {
                            msg = "userToken null; verifySignerInfo failure";
                            CMS.debug(method + msg);
                            throw new EBaseException(msg);
                        } else {
                            if (selfSigned) {
                                CMS.debug(method
                                        + " self-signed cmc request will not have user identification info at this point.");
                                auditSignerInfo = "selfSigned";
                            } else {
                                CMS.debug(method + "signed with user cert");
                                userid = userToken.getInString("userid");
                                uid = userToken.getInString("id");
                                if (userid == null && uid == null) {
                                    msg = " verifySignerInfo failure... missing id";
                                    CMS.debug(method + msg);
                                    throw new EBaseException(msg);
                                }
                                // reset value of auditSignerInfo
                                if (uid != null && !uid.equals(ILogger.UNIDENTIFIED)) {
                                    //CMS.debug(method + "setting auditSignerInfo to uid:" + uid.trim());
                                    //auditSignerInfo = uid.trim();
                                    auditSubjectID = uid.trim();
                                    authToken.set(IAuthToken.USER_ID, auditSubjectID);
                                } else if (userid != null && !userid.equals(ILogger.UNIDENTIFIED)) {
                                    //CMS.debug(method + "setting auditSignerInfo to userid:" + userid);
                                    //auditSignerInfo = userid.trim();
                                    auditSubjectID = userid.trim();
                                    authToken.set(IAuthToken.USER_ID, auditSubjectID);
                                }
                            }
                        }
                    } else {
                        CMS.debug(method + " signerInfo verification bypassed");
                    }

                    EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();
                    SET sis = cmcFullReq.getSignerInfos();
                    // only one SignerInfo for selfSigned
                    selfsign_signerInfo = (org.mozilla.jss.pkix.cms.SignerInfo) sis.elementAt(0);

                    id = ci.getContentType();

                    if (!id.equals(OBJECT_IDENTIFIER.id_cct_PKIData) ||
                            !ci.hasContent()) {
                        msg = "request EncapsulatedContentInfo content type not OBJECT_IDENTIFIER.id_cct_PKIData";
                        CMS.debug(method + msg);

                        throw new EBaseException(msg);
                    }

                    content = ci.getContent();
                } else if (cmcReq.getContentType().equals( //unsigned
                        org.mozilla.jss.pkix.cms.ContentInfo.DATA)) {
                    CMS.debug(method + "cmc request content is unsigned data...verifySignerInfo will not be called;");
                    content = (OCTET_STRING) cmcReq.getInterpretedContent();
                } else {
                    cmcBlobIn.close();
                    msg = "unsupported cmc rquest content type; must be either ContentInfo.SIGNED_DATA or ContentInfo.DATA;";
                    CMS.debug(msg);
                    throw new EBaseException(msg);
                }

                ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
                PKIData pkiData = (PKIData) (new PKIData.Template()).decode(s);

                SEQUENCE reqSequence = pkiData.getReqSequence();

                int numReqs = reqSequence.size();

                if (numReqs == 0) {
                    CMS.debug(method + "numReqs 0, assume revocation request");
                    // revocation request

                    // reset value of auditReqType
                    auditReqType = SIGNED_AUDIT_REVOCATION_REQUEST_TYPE;

                    SEQUENCE controlSequence = pkiData.getControlSequence();
                    int controlSize = controlSequence.size();

                    if (controlSize > 0) {
                        for (int i = 0; i < controlSize; i++) {
                            TaggedAttribute taggedAttribute = (TaggedAttribute) controlSequence.elementAt(i);
                            OBJECT_IDENTIFIER type = taggedAttribute.getType();

                            if (type.equals(
                                    OBJECT_IDENTIFIER.id_cmc_revokeRequest)) {
                                //further checks and actual revocation happen in CMCOutputTemplate

                                // if( i ==1 ) {
                                //     taggedAttribute.getType() ==
                                //       OBJECT_IDENTIFIER.id_cmc_revokeRequest
                                // }

                                SET values = taggedAttribute.getValues();
                                int numVals = values.size();
                                BigInteger[] bigIntArray = null;

                                bigIntArray = new BigInteger[numVals];
                                for (int j = 0; j < numVals; j++) {
                                    // serialNumber    INTEGER

                                    // SEQUENCE RevokeRequest = (SEQUENCE)
                                    //     values.elementAt(j);
                                    byte[] encoded = ASN1Util.encode(
                                            values.elementAt(j));
                                    org.mozilla.jss.asn1.ASN1Template template = new org.mozilla.jss.pkix.cmc.RevokeRequest.Template();
                                    org.mozilla.jss.pkix.cmc.RevokeRequest revRequest = (org.mozilla.jss.pkix.cmc.RevokeRequest) ASN1Util
                                            .decode(template, encoded);

                                    // SEQUENCE RevokeRequest = (SEQUENCE)
                                    //     ASN1Util.decode(
                                    //         SEQUENCE.getTemplate(),
                                    //         ASN1Util.encode(
                                    //         values.elementAt(j)));

                                    // SEQUENCE RevokeRequest =
                                    //     values.elementAt(j);
                                    // int revReqSize = RevokeRequest.size();
                                    // if( revReqSize > 3 ) {
                                    //     INTEGER serialNumber =
                                    //         new INTEGER((long)0);
                                    // }

                                    INTEGER temp = revRequest.getSerialNumber();

                                    bigIntArray[j] = temp;
                                    authToken.set(TOKEN_CERT_SERIAL, bigIntArray);

                                    long reasonCode = revRequest.getReason().getValue();
                                    Integer IntObject = Integer.valueOf((int) reasonCode);
                                    authToken.set(REASON_CODE, IntObject);

                                    //authToken.set("uid", uid);
                                    //authToken.set("userid", userid);

                                }
                            }
                        }

                    }
                } else {
                    CMS.debug(method + "numReqs not 0, assume enrollment request");
                    // enrollment request

                    // reset value of auditReqType
                    auditReqType = SIGNED_AUDIT_ENROLLMENT_REQUEST_TYPE;

                    X509CertInfo[] certInfoArray = new X509CertInfo[numReqs];
                    String[] reqIdArray = new String[numReqs];

                    for (int i = 0; i < numReqs; i++) {
                        // decode message.
                        TaggedRequest taggedRequest = (TaggedRequest) reqSequence.elementAt(i);

                        TaggedRequest.Type type = taggedRequest.getType();

                        if (type.equals(TaggedRequest.PKCS10)) {
                            CMS.debug(method + " type is PKCS10");
                            authToken.set("cert_request_type", "cmc-pkcs10");

                            TaggedCertificationRequest tcr = taggedRequest.getTcr();
                            int p10Id = tcr.getBodyPartID().intValue();

                            reqIdArray[i] = String.valueOf(p10Id);

                            CertificationRequest p10 = tcr.getCertificationRequest();

                            // transfer to sun class
                            ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                            p10.encode(ostream);
                            boolean sigver = true;
                            boolean tokenSwitched = false;
                            CryptoManager cm = null;
                            CryptoToken signToken = null;
                            CryptoToken savedToken = null;

                            // for PKCS10, "sigver" would offer the POP
                            sigver = CMS.getConfigStore().getBoolean("ca.requestVerify.enabled", true);
                            try {
                                cm = CryptoManager.getInstance();
                                if (sigver == true) {
                                    String tokenName = CMS.getConfigStore().getString("ca.requestVerify.token",
                                            CryptoUtil.INTERNAL_TOKEN_NAME);
                                    savedToken = cm.getThreadToken();
                                    signToken = CryptoUtil.getCryptoToken(tokenName);
                                    if (!savedToken.getName().equals(signToken.getName())) {
                                        cm.setThreadToken(signToken);
                                        tokenSwitched = true;
                                    }
                                }

                                PKCS10 pkcs10 = new PKCS10(ostream.toByteArray(), sigver);
                                // reset value of requestCertSubject
                                X500Name tempName = pkcs10.getSubjectName();
                                CMS.debug(method + "request subject name=" + tempName.toString());
                                if (tempName != null) {
                                    requestCertSubject = tempName.toString().trim();
                                    if (requestCertSubject.equals("")) {
                                        requestCertSubject = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
                                    }
                                    authToken.set(AuthToken.TOKEN_CERT_SUBJECT,
                                            requestCertSubject/*tempName.toString()*/);
                                    auditContext.put(SessionContext.CMC_REQUEST_CERT_SUBJECT, requestCertSubject);
                                }

                                if (selfSigned) {
                                    // prepare for checking SKI extension
                                    try {
                                        selfsign_skiExtn = (SubjectKeyIdentifierExtension) CryptoUtil
                                                .getExtensionFromPKCS10(pkcs10, "SubjectKeyIdentifier");
                                        if (selfsign_skiExtn != null)
                                            CMS.debug(method + "SubjectKeyIdentifierExtension found:");
                                        else {
                                            msg = "missing SubjectKeyIdentifierExtension in request";
                                            CMS.debug(method + msg);
                                            throw new EBaseException(msg);
                                        }
                                    } catch (IOException e) {
                                        msg = method + "SubjectKeyIdentifierExtension not found:" + e;
                                        CMS.debug(msg);
                                        throw new EBaseException(msg);
                                    } catch (Exception e) {
                                        msg = method + "SubjectKeyIdentifierExtension not found:" + e;
                                        CMS.debug(msg);
                                        throw new EBaseException(msg);
                                    }

                                    X509Key pubKey = pkcs10.getSubjectPublicKeyInfo();
                                    PrivateKey.Type keyType = null;
                                    String alg = pubKey.getAlgorithm();

                                    if (alg.equals("RSA")) {
                                        CMS.debug(method + "signing key alg=RSA");
                                        keyType = PrivateKey.RSA;
                                        selfsign_pubK = PK11PubKey.fromRaw(keyType, pubKey.getKey());
                                    } else if (alg.equals("EC")) {
                                        CMS.debug(method + "signing key alg=EC");
                                        keyType = PrivateKey.EC;
                                        byte publicKeyData[] = (pubKey).getEncoded();
                                        selfsign_pubK = PK11ECPublicKey.fromSPKI(/*keyType,*/ publicKeyData);
                                    } else {
                                        msg = "unsupported signature algorithm: " + alg;
                                        CMS.debug(method + msg);
                                        throw new EInvalidCredentials(msg);
                                    }
                                    CMS.debug(method + "public key retrieved");
                                    verifySelfSignedCMC(selfsign_signerInfo, id);

                                } //selfSigned

                                // xxx do we need to do anything else?
                                X509CertInfo certInfo = CMS.getDefaultX509CertInfo();

                                // fillPKCS10(certInfo,pkcs10,authToken,null);

                                // authToken.set(
                                //     pkcs10.getSubjectPublicKeyInfo());

                                /*
                                authToken.set("uid", uid);
                                authToken.set("userid", userid);
                                */

                                certInfoArray[i] = certInfo;
                            } catch (Exception e) {
                                e.printStackTrace();
                                throw new EBaseException(e.toString());
                            } finally {
                                if ((sigver == true) && (tokenSwitched == true)) {
                                    cm.setThreadToken(savedToken);
                                }
                            }
                        } else if (type.equals(TaggedRequest.CRMF)) {

                            CMS.debug(method + " type is CRMF");
                            authToken.set("cert_request_type", "cmc-crmf");
                            try {
                                CertReqMsg crm = taggedRequest.getCrm();
                                CertRequest certReq = crm.getCertReq();
                                INTEGER reqID = certReq.getCertReqId();
                                reqIdArray[i] = reqID.toString();
                                CertTemplate template = certReq.getCertTemplate();
                                Name name = template.getSubject();

                                // xxx do we need to do anything else?
                                X509CertInfo certInfo = CMS.getDefaultX509CertInfo();

                                // reset value of requestCertSubject
                                if (name != null) {
                                    String ss = name.getRFC1485();

                                    CMS.debug(method + "setting requestCertSubject to: " + ss);
                                    requestCertSubject = ss;
                                    if (requestCertSubject.equals("")) {
                                        requestCertSubject = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
                                    }

                                    authToken.set(AuthToken.TOKEN_CERT_SUBJECT, ss);
                                    auditContext.put(SessionContext.CMC_REQUEST_CERT_SUBJECT, requestCertSubject);
                                    //authToken.set("uid", uid);
                                    //authToken.set("userid", userid);
                                }
                                certInfoArray[i] = certInfo;

                                if (selfSigned) {
                                    selfsign_skiExtn = (SubjectKeyIdentifierExtension) CryptoUtil
                                            .getExtensionFromCertTemplate(template, PKIXExtensions.SubjectKey_Id);
                                    if (selfsign_skiExtn != null) {
                                        CMS.debug(method +
                                                "SubjectKeyIdentifierExtension found");
                                    } else {
                                        CMS.debug(method +
                                                "SubjectKeyIdentifierExtension not found");
                                    }

                                    // get public key for verifying signature later
                                    SubjectPublicKeyInfo pkinfo = template.getPublicKey();
                                    PrivateKey.Type keyType = null;
                                    String alg = pkinfo.getAlgorithm();
                                    BIT_STRING bitString = pkinfo.getSubjectPublicKey();
                                    byte[] publicKeyData = bitString.getBits();
                                    if (alg.equals("RSA")) {
                                        CMS.debug(method + "signing key alg=RSA");
                                        keyType = PrivateKey.RSA;
                                        selfsign_pubK = PK11PubKey.fromRaw(keyType, publicKeyData);
                                    } else if (alg.equals("EC")) {
                                        CMS.debug(method + "signing key alg=EC");
                                        keyType = PrivateKey.EC;
                                        selfsign_pubK = PK11ECPublicKey.fromSPKI(/*keyType,*/ publicKeyData);
                                    } else {
                                        msg = "unsupported signature algorithm: " + alg;
                                        CMS.debug(method + msg);
                                        throw new EInvalidCredentials(msg);
                                    }
                                    CMS.debug(method + "public key retrieved");

                                    verifySelfSignedCMC(selfsign_signerInfo, id);
                                } //selfSigned

                            } catch (Exception e) {
                                e.printStackTrace();
                                cmcBlobIn.close();
                                s.close();
                                throw new EBaseException(e.toString());
                            }
                        }

                    }
                }

                authToken.set("uid", uid);
                authToken.set("userid", userid);
            } catch (EMissingCredential e) {
                throw e;
            } catch (EInvalidCredentials e) {
                throw e;
            } catch (Exception e) {
                //CMS.debug(method + e);
                //Debug.printStackTrace(e);
                //throw new EInvalidCredentials(e.toString());
                throw e;
            }

            // For accuracy, make sure revocation by shared secret doesn't
            // log CMC_USER_SIGNED_REQUEST_SIG_VERIFY_SUCCESS
            if (authToken.get(IAuthManager.CRED_CMC_SIGNING_CERT) != null ||
                    authToken.get(IAuthManager.CRED_CMC_SELF_SIGNED) != null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CMC_USER_SIGNED_REQUEST_SIG_VERIFY_SUCCESS,
                        getAuditSubjectID(),
                        ILogger.SUCCESS,
                        auditReqType,
                        getRequestCertSubject(auditContext),
                        getAuditSignerInfo(auditContext));

                audit(auditMessage);
            } else {
                CMS.debug(method
                        + "audit event CMC_USER_SIGNED_REQUEST_SIG_VERIFY_SUCCESS not logged due to unsigned data for revocation with shared secret.");
            }

            CMS.debug(method + "ends successfully; returning authToken");
            return authToken;
        } catch (EMissingCredential eAudit1) {
            CMS.debug(method + eAudit1);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (EInvalidCredentials eAudit2) {
            CMS.debug(method + eAudit2);
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    AuditEvent.CMC_USER_SIGNED_REQUEST_SIG_VERIFY_FAILURE,
                    getAuditSubjectID(),
                    ILogger.FAILURE,
                    auditReqType,
                    getRequestCertSubject(auditContext),
                    getAuditSignerInfo(auditContext),
                    eAudit2.toString());

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
        } catch (EBaseException eAudit3) {
            CMS.debug(method + eAudit3);
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    AuditEvent.CMC_USER_SIGNED_REQUEST_SIG_VERIFY_FAILURE,
                    getAuditSubjectID(),
                    ILogger.FAILURE,
                    auditReqType,
                    getRequestCertSubject(auditContext),
                    getAuditSignerInfo(auditContext),
                    eAudit3.toString());

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit3;
        } catch (Exception eAudit4) {
            CMS.debug(method + eAudit4);
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    AuditEvent.CMC_USER_SIGNED_REQUEST_SIG_VERIFY_FAILURE,
                    getAuditSubjectID(),
                    ILogger.FAILURE,
                    auditReqType,
                    getRequestCertSubject(auditContext),
                    getAuditSignerInfo(auditContext),
                    eAudit4.toString());

            audit(auditMessage);

            // rethrow the exception to be handled later
            throw new EBaseException(eAudit4);
        }
    }

    /*
    * verifySelfSignedCMC() verifies the following
    * a. the required (per RFC 5272) SKI extension in the request matches that in the
    *    SignerIdentifier
    * b. the signature in the request
    */
    protected void verifySelfSignedCMC(
            org.mozilla.jss.pkix.cms.SignerInfo signerInfo,
            OBJECT_IDENTIFIER id)
            throws EBaseException {
        String method = "CMCUserSignedAuth: verifySelfSignedCMC: ";
        CMS.debug(method + "begins");
        try {
            SignerIdentifier sid = signerInfo.getSignerIdentifier();
            OCTET_STRING subjKeyId = sid.getSubjectKeyIdentifier();
            KeyIdentifier keyIdObj =
                    (KeyIdentifier) selfsign_skiExtn.get(SubjectKeyIdentifierExtension.KEY_ID);
            boolean match = CryptoUtil.compare(subjKeyId.toByteArray(), keyIdObj.getIdentifier());
            if (match) {
                CMS.debug(method +
                        " SignerIdentifier SUBJECT_KEY_IDENTIFIER matches SKI of request");
            } else {
                CMS.debug(method +
                        " SignerIdentifier SUBJECT_KEY_IDENTIFIER failed to match");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
            // verify sig using public key in request
            CMS.debug(method + "verifying request signature with public key");
            signerInfo.verify(selfsign_digest, id, selfsign_pubK);
            CMS.debug(method + " signature verified");
        } catch (Exception e) {
            CMS.debug(method + e.toString());
            throw new EBaseException(method + e.toString());
        }
    }

    /**
     * Returns a list of configuration parameter names.
     * The list is passed to the configuration console so instances of
     * this implementation can be configured through the console.
     * <p>
     *
     * @return String array of configuration parameter names.
     */
    public String[] getConfigParams() {
        return (mConfigParams);
    }

    /**
     * gets the configuration substore used by this authentication
     * plug-in
     * <p>
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * gets the plug-in name of this authentication plug-in.
     */
    public String getImplName() {
        return mImplName;
    }

    /**
     * gets the name of this authentication plug-in instance
     */
    public String getName() {
        return mName;
    }

    /**
     * get the list of required credentials.
     * <p>
     *
     * @return list of required credentials as strings.
     */
    public String[] getRequiredCreds() {
        return (mRequiredCreds);
    }

    /**
     * prepares for shutdown.
     */
    public void shutdown() {
    }

    /////////////////////////////////
    // IExtendedPluginInfo methods //
    /////////////////////////////////

    /**
     * Activate the help system.
     * <p>
     *
     * @return help messages
     */
    public String[] getExtendedPluginInfo() {
        String method = "CMCUserSignedAuth: getExtendedPluginInfo: ";
        CMS.debug(method + " begins");
        String[] s = Utils.getStringArrayFromVector(mExtendedPluginInfo);

        CMS.debug(method + " s.length = " + s.length);
        for (int i = 0; i < s.length; i++) {
            CMS.debug("" + i + " " + s[i]);
        }
        return s;
    }

    ////////////////////
    // Logger methods //
    ////////////////////

    /**
     * Logs a message for this class in the system log file.
     * <p>
     *
     * @param level The log level.
     * @param msg The message to log.
     * @see com.netscape.certsrv.logging.ILogger
     */
    protected void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHENTICATION,
                level, "CMC User Signed Authentication: " + msg);
    }

    /**
     * User-signed CMC requests can be signed in two ways:
     * a. signed with previously issued user signing cert
     * b. self-signed with the private key paired with the public key in
     * the request
     *
     * In case "a", the resulting authToke would contain
     * (IAuthManager.CRED_CMC_SIGNING_CERT, signing cert serial number)
     * In case "b", the resulting authToke would not contain the attribute
     * IAuthManager.CRED_CMC_SIGNING_CERT
     */
    protected IAuthToken verifySignerInfo(
            SessionContext auditContext, // to capture info in case of failure
            AuthToken authToken,
            SignedData cmcFullReq)
            throws EBaseException, EInvalidCredentials, EMissingCredential {
        String method = "CMCUserSignedAuth: verifySignerInfo: ";
        String msg = "";
        CMS.debug(method + "begins");
        EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();
        OBJECT_IDENTIFIER id = ci.getContentType();
        OCTET_STRING content = ci.getContent();

        boolean tokenSwitched = false;
        CryptoToken signToken = null;
        CryptoToken savedToken = null;
        CryptoManager cm = null;
        try {
            cm = CryptoManager.getInstance();
            ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
            PKIData pkiData = (PKIData) (new PKIData.Template()).decode(s);

            SET dais = cmcFullReq.getDigestAlgorithmIdentifiers();
            int numDig = dais.size();
            Hashtable<String, byte[]> digs = new Hashtable<String, byte[]>();

            //if request key is used for signing, there MUST be only one signerInfo
            //object in the signedData object.
            for (int i = 0; i < numDig; i++) {
                AlgorithmIdentifier dai = (AlgorithmIdentifier) dais.elementAt(i);
                String name = DigestAlgorithm.fromOID(dai.getOID()).toString();

                MessageDigest md = MessageDigest.getInstance(name);

                byte[] digest = md.digest(content.toByteArray());

                digs.put(name, digest);
            }

            SET sis = cmcFullReq.getSignerInfos();
            int numSis = sis.size();

            for (int i = 0; i < numSis; i++) {
                org.mozilla.jss.pkix.cms.SignerInfo si = (org.mozilla.jss.pkix.cms.SignerInfo) sis.elementAt(i);
                //selfsign_SignerInfo = (org.mozilla.jss.pkix.cms.SignerInfo) sis.elementAt(i);

                String name = si.getDigestAlgorithm().toString();
                byte[] digest = digs.get(name);

                if (digest == null) {
                    MessageDigest md = MessageDigest.getInstance(name);
                    ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                    pkiData.encode(ostream);
                    digest = md.digest(ostream.toByteArray());

                }

                // signed  by  previously certified signature key
                SignerIdentifier sid = si.getSignerIdentifier();
                if (sid.getType().equals(SignerIdentifier.ISSUER_AND_SERIALNUMBER)) {
                    CMS.debug(method + "SignerIdentifier type: ISSUER_AND_SERIALNUMBER");
                    selfSigned = false;
                    CMS.debug(method + "selfSigned is false");

                    IssuerAndSerialNumber issuerAndSerialNumber = sid.getIssuerAndSerialNumber();
                    // find from the certs in the signedData
                    java.security.cert.X509Certificate cert = null;

                    if (cmcFullReq.hasCertificates()) {
                        SET certs = cmcFullReq.getCertificates();
                        int numCerts = certs.size();
                        X509Certificate[] x509Certs = new X509Certificate[1];
                        byte[] certByteArray = new byte[0];
                        for (int j = 0; j < numCerts; j++) {
                            Certificate certJss = (Certificate) certs.elementAt(j);
                            CertificateInfo certI = certJss.getInfo();
                            Name issuer = certI.getIssuer();

                            byte[] issuerB = ASN1Util.encode(issuer);
                            INTEGER sn = certI.getSerialNumber();
                            // if this cert is the signer cert, not a cert in the chain
                            if (new String(issuerB).equals(new String(
                                    ASN1Util.encode(issuerAndSerialNumber.getIssuer())))
                                    && sn.toString().equals(issuerAndSerialNumber.getSerialNumber().toString())) {
                                ByteArrayOutputStream os = new ByteArrayOutputStream();

                                certJss.encode(os);
                                certByteArray = os.toByteArray();

                                X509CertImpl tempcert = new X509CertImpl(os.toByteArray());

                                cert = tempcert;
                                x509Certs[0] = cert;
                                // xxx validate the cert length

                            }
                        }

                        CMS.debug(method + "start checking signature");
                        if (cert == null) {
                            // find from certDB
                            CMS.debug(method + "verifying signature");
                            si.verify(digest, id);
                        } else {
                            CMS.debug(method + "found CMC signing cert... verifying");

                            X509Certificate clientCert =
                                    (X509Certificate) auditContext.get(SessionContext.SSL_CLIENT_CERT);
                            // user-signed case requires ssl client authentication
                            if (clientCert == null) {
                                createAuditSubjectFromCert(auditContext, x509Certs[0]);
                                msg = "missing SSL client authentication certificate;";
                                CMS.debug(method + msg);
                                s.close();
                                throw new EMissingCredential(
                                        CMS.getUserMessage("CMS_AUTHENTICATION_NO_CERT"));
                            }
                            netscape.security.x509.X500Name clientPrincipal =
                                    (X500Name) clientCert.getSubjectDN();

                            netscape.security.x509.X500Name cmcPrincipal =
                                    (X500Name) x509Certs[0].getSubjectDN();

                            // capture signer principal to be checked against
                            // cert subject principal later in CMCOutputTemplate
                            // in case of user signed revocation
                            auditContext.put(SessionContext.CMC_SIGNER_PRINCIPAL, cmcPrincipal);
                            auditContext.put(SessionContext.CMC_SIGNER_INFO,
                                cmcPrincipal.toString());

                            // check ssl client cert against cmc signer
                            if (!clientPrincipal.equals(cmcPrincipal)) {
                                msg = "SSL client authentication certificate and CMC signer do not match";
                                CMS.debug(method + msg);
                                s.close();
                                throw new EInvalidCredentials(
                                        CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                            } else {
                                CMS.debug(method + "ssl client cert principal and cmc signer principal match");
                            }

                            PublicKey signKey = cert.getPublicKey();
                            PrivateKey.Type keyType = null;
                            String alg = signKey.getAlgorithm();

                            PK11PubKey pubK = null;
                            if (alg.equals("RSA")) {
                                CMS.debug(method + "signing key alg=RSA");
                                keyType = PrivateKey.RSA;
                                pubK = PK11PubKey.fromRaw(keyType, ((X509Key) signKey).getKey());
                            } else if (alg.equals("EC")) {
                                CMS.debug(method + "signing key alg=EC");
                                keyType = PrivateKey.EC;
                                byte publicKeyData[] = ((X509Key) signKey).getEncoded();
                                pubK = PK11ECPublicKey.fromSPKI(/*keyType,*/ publicKeyData);
                            } else {
                                msg = "unsupported signature algorithm: " + alg;
                                CMS.debug(method +  msg);
                                s.close();
                                throw new EInvalidCredentials(
                                        CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                            }

                            String tokenName = CMS.getConfigStore().getString("ca.requestVerify.token",
                                    CryptoUtil.INTERNAL_TOKEN_NAME);
                            // by default JSS will use internal crypto token
                            if (!CryptoUtil.isInternalToken(tokenName)) {
                                savedToken = cm.getThreadToken();
                                signToken = CryptoUtil.getCryptoToken(tokenName);
                                if (signToken != null) {
                                    cm.setThreadToken(signToken);
                                    tokenSwitched = true;
                                    CMS.debug(method + "verifySignerInfo token switched:" + tokenName);
                                } else {
                                    CMS.debug(method + "verifySignerInfo token not found:" + tokenName
                                            + ", trying internal");
                                }
                            }

                            CMS.debug(method + "verifying signature with public key");
                            si.verify(digest, id, pubK);
                        }
                        CMS.debug(method + "finished checking signature");

                        // verify signer's certificate using the revocator
                        // ...or not;  I think it just checks usage and
                        // validity, but not revocation status
                        if (!cm.isCertValid(certByteArray, true, CryptoManager.CertUsage.SSLClient)) {
                            msg = "CMC signing cert is invalid";
                            CMS.debug(method + msg);
                            s.close();
                            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                        } else {
                            CMS.debug(method + "CMC signature verified; but signer not yet;");
                        }
                        // At this point, the signature has been verified;

                        // now check revocation status of the cert
                        if (CMS.isRevoked(x509Certs)) {
                            msg = "CMC signing cert is a revoked certificate";
                            CMS.debug(method + msg);
                            s.close();
                            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                        }
                        try { //do this again anyways
                            cert.checkValidity();
                        } catch (CertificateExpiredException e) {
                            msg = "CMC signing cert is an expired certificate";
                            CMS.debug(method + msg);
                            s.close();
                            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                        } catch (Exception e) {
                            CMS.debug(method + e.toString());
                            s.close();
                            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + e.toString());
                        }

                        IAuthToken tempToken = new AuthToken(null);
                        netscape.security.x509.X500Name tempPrincipal = (X500Name) x509Certs[0].getSubjectDN();
                        String ID = tempPrincipal.toString(); //tempToken.get("userid");
                        CMS.debug(method + " Principal name = " + ID);

                        BigInteger certSerial = x509Certs[0].getSerialNumber();
                        CMS.debug(method + " verified cert serial=" + certSerial.toString());
                        authToken.set(IAuthManager.CRED_CMC_SIGNING_CERT, certSerial.toString());
                        tempToken.set("id", ID);

                        s.close();
                        return tempToken;

                    } else {
                        msg = "no certificate found in cmcFullReq";
                        CMS.debug(method + msg);
                        throw new EMissingCredential(msg);
                    }
                } else if (sid.getType().equals(SignerIdentifier.SUBJECT_KEY_IDENTIFIER)) {
                    CMS.debug(method + "SignerIdentifier type: SUBJECT_KEY_IDENTIFIER");
                    CMS.debug(method + "selfSigned is true");
                    selfSigned = true;
                    selfsign_digest = digest;

                    IAuthToken tempToken = new AuthToken(null);
                    authToken.set(IAuthManager.CRED_CMC_SELF_SIGNED, "true");
                    s.close();
                    return tempToken;
                } else {
                    msg = "unsupported SignerIdentifier type";
                    CMS.debug(method + msg);
                    throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                }
            } //for

        } catch (EMissingCredential e) {
            throw e;
        } catch (EInvalidCredentials e) {
            throw e;
        } catch (InvalidBERException e) {
            CMS.debug(method + e);
        } catch (Exception e) {
            CMS.debug(method + e);
        } finally {
            if ((tokenSwitched == true) && (savedToken != null)) {
                cm.setThreadToken(savedToken);
                CMS.debug(method + "verifySignerInfo token restored");
            }
        }
        return null;

    }

    private void createAuditSubjectFromCert (
            SessionContext auditContext,
            X509Certificate cert)
            throws IOException {
        String method = "CMCUserSignedAuth:createAuditSubjectFromCert: ";

        // capture auditSubjectID first in case of failure
        netscape.security.x509.X500Name principal =
                (X500Name) cert.getSubjectDN();

        CMS.debug(method + " Principal name = " + principal.toString());
        auditContext.put(SessionContext.USER_ID, principal.toString());
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        return null;
    }

    // Profile-related methods

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_CMS_SIGN_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_CMS_SIGN_TEXT");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    public Enumeration<String> getValueNames() {
        Vector<String> v = new Vector<String>();
        v.addElement("cert_request");
        return v.elements();
    }

    public boolean isValueWriteable(String name) {
        return false;
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(CRED_CMC)) {
            return new Descriptor(IDescriptor.STRING_LIST, null, null,
                    "CMC request");
        }
        return null;
    }

    public void populate(IAuthToken token, IRequest request)
            throws EProfileException {
        request.setExtData(IProfileAuthenticator.AUTHENTICATED_NAME,
                token.getInString(AuthToken.TOKEN_CERT_SUBJECT));
    }

    public boolean isSSLClientRequired() {
        return false;
    }

    /**
     * Signed Audit Log
     *
     * This method is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    private void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }

    protected void audit(AuditEvent event) {

        String template = event.getMessage();
        Object[] params = event.getParameters();

        String message = CMS.getLogMessage(template, params);

        audit(message);
    }

    /**
     * Signed Audit Log Subject ID
     *
     * This method is called to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    private String getAuditSubjectID() {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String) auditContext.get(SessionContext.USER_ID);

            if (subjectID != null) {
                subjectID = subjectID.trim();
            } else {
                subjectID = ILogger.NONROLEUSER;
            }
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }

    private String getAuditSignerInfo(SessionContext auditContext) {
        String signerSubject = (String)auditContext.get(SessionContext.CMC_SIGNER_INFO);
        if (signerSubject == null)
            signerSubject = "$Unidentified$";

        return signerSubject;
    }

    private String getRequestCertSubject(SessionContext auditContext) {
        String certSubject = (String)auditContext.get(SessionContext.CMC_REQUEST_CERT_SUBJECT);
        if (certSubject == null)
            certSubject = "$Unidentified$";

        return certSubject;
    }

}
