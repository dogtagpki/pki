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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import netscape.security.pkcs.PKCS10;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
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
import org.mozilla.jss.pkcs11.PK11ECPublicKey;
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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.util.Utils;

//import com.netscape.cmscore.util.*;
//////////////////////
// class definition //
//////////////////////

/**
 * UID/CMC authentication plug-in
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class CMCAuth implements IAuthManager, IExtendedPluginInfo,
        IProfileAuthenticator {

    ////////////////////////
    // default parameters //
    ////////////////////////

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
    protected static String[] mConfigParams =
            new String[] {};

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
                    ";Authenticate the CMC request. The signer must be an agent. The \"Authentication Instance ID\" must be named \"CMCAuth\"");
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
    private final static String SIGNED_AUDIT_ENROLLMENT_REQUEST_TYPE =
            "enrollment";
    private final static String SIGNED_AUDIT_REVOCATION_REQUEST_TYPE =
            "revocation";
    private final static String LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY =
            "LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY_5";

    /////////////////////
    // default methods //
    /////////////////////

    /**
     * Default constructor, initialization must follow.
     */
    public CMCAuth() {
    }

    //////////////////////////
    // IAuthManager methods //
    //////////////////////////

    /**
     * Initializes the CMCAuth authentication plug-in.
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
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY used when CMC (agent-pre-signed) cert
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
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditReqType = ILogger.UNIDENTIFIED;
        String auditCertSubject = ILogger.UNIDENTIFIED;
        String auditSignerInfo = ILogger.UNIDENTIFIED;

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
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditReqType,
                        auditCertSubject,
                        auditSignerInfo);

                audit(auditMessage);

                throw new EMissingCredential(CMS.getUserMessage(
                        "CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_CMC));
            }

            if (cmc.equals("")) {
                log(ILogger.LL_FAILURE,
                        "cmc : attempted login with empty CMC.");

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditReqType,
                        auditCertSubject,
                        auditSignerInfo);

                audit(auditMessage);

                throw new EInvalidCredentials(CMS.getUserMessage(
                        "CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
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
                ByteArrayInputStream cmcBlobIn = new
                                                 ByteArrayInputStream(cmcBlob);

                org.mozilla.jss.pkix.cms.ContentInfo cmcReq =
                        (org.mozilla.jss.pkix.cms.ContentInfo)
                        org.mozilla.jss.pkix.cms.ContentInfo.getTemplate().decode(
                                cmcBlobIn);

                if (!cmcReq.getContentType().equals(
                        org.mozilla.jss.pkix.cms.ContentInfo.SIGNED_DATA) ||
                        !cmcReq.hasContent()) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditReqType,
                            auditCertSubject,
                            auditSignerInfo);

                    audit(auditMessage);

                    // throw new ECMSGWException(CMSGWResources.NO_CMC_CONTENT);

                    throw new EBaseException("NO_CMC_CONTENT");
                }

                SignedData cmcFullReq = (SignedData)
                                        cmcReq.getInterpretedContent();

                IConfigStore cmc_config = CMS.getConfigStore();
                boolean checkSignerInfo =
                        cmc_config.getBoolean("cmc.signerInfo.verify", true);
                String userid = "defUser";
                String uid = "defUser";
                if (checkSignerInfo) {
                    IAuthToken agentToken = verifySignerInfo(authToken, cmcFullReq);
                    if (agentToken == null) {
                        CMS.debug("CMCAuth: authenticate() agentToken null");
                        throw new EBaseException("CMCAuth: agent verifySignerInfo failure");
                    }
                    userid = agentToken.getInString("userid");
                    uid = agentToken.getInString("cn");
                } else {
                    CMS.debug("CMCAuth: authenticate() signerInfo verification bypassed");
                }
                // reset value of auditSignerInfo
                if (uid != null) {
                    auditSignerInfo = uid.trim();
                }

                EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();

                OBJECT_IDENTIFIER id = ci.getContentType();

                if (!id.equals(OBJECT_IDENTIFIER.id_cct_PKIData) ||
                        !ci.hasContent()) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditReqType,
                            auditCertSubject,
                            auditSignerInfo);

                    audit(auditMessage);

                    //  throw new ECMSGWException(
                    // CMSGWResources.NO_PKIDATA);

                    throw new EBaseException("NO_PKIDATA");
                }

                OCTET_STRING content = ci.getContent();

                ByteArrayInputStream s = new
                        ByteArrayInputStream(content.toByteArray());
                PKIData pkiData = (PKIData) (new PKIData.Template()).decode(s);

                SEQUENCE reqSequence = pkiData.getReqSequence();

                int numReqs = reqSequence.size();

                if (numReqs == 0) {
                    // revocation request

                    // reset value of auditReqType
                    auditReqType = SIGNED_AUDIT_REVOCATION_REQUEST_TYPE;

                    SEQUENCE controlSequence = pkiData.getControlSequence();
                    int controlSize = controlSequence.size();

                    if (controlSize > 0) {
                        for (int i = 0; i < controlSize; i++) {
                            TaggedAttribute taggedAttribute =
                                    (TaggedAttribute) controlSequence.elementAt(i);
                            OBJECT_IDENTIFIER type = taggedAttribute.getType();

                            if (type.equals(
                                    OBJECT_IDENTIFIER.id_cmc_revokeRequest)) {
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

                                    // SEQUENCE RevRequest = (SEQUENCE)
                                    //     values.elementAt(j);
                                    byte[] encoded = ASN1Util.encode(
                                            values.elementAt(j));
                                    org.mozilla.jss.asn1.ASN1Template template = new
                                            org.mozilla.jss.pkix.cmmf.RevRequest.Template();
                                    org.mozilla.jss.pkix.cmmf.RevRequest revRequest =
                                            (org.mozilla.jss.pkix.cmmf.RevRequest)
                                            ASN1Util.decode(template, encoded);

                                    // SEQUENCE RevRequest = (SEQUENCE)
                                    //     ASN1Util.decode(
                                    //         SEQUENCE.getTemplate(),
                                    //         ASN1Util.encode(
                                    //         values.elementAt(j)));

                                    // SEQUENCE RevRequest =
                                    //     values.elementAt(j);
                                    // int revReqSize = RevRequest.size();
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

                                    authToken.set("uid", uid);
                                    authToken.set("userid", userid);
                                }
                            }
                        }

                    }
                } else {
                    // enrollment request

                    // reset value of auditReqType
                    auditReqType = SIGNED_AUDIT_ENROLLMENT_REQUEST_TYPE;

                    X509CertInfo[] certInfoArray = new X509CertInfo[numReqs];
                    String[] reqIdArray = new String[numReqs];

                    for (int i = 0; i < numReqs; i++) {
                        // decode message.
                        TaggedRequest taggedRequest =
                                (TaggedRequest) reqSequence.elementAt(i);

                        TaggedRequest.Type type = taggedRequest.getType();

                        if (type.equals(TaggedRequest.PKCS10)) {
                            CMS.debug("CMCAuth: type is PKCS10");
                            TaggedCertificationRequest tcr =
                                    taggedRequest.getTcr();
                            int p10Id = tcr.getBodyPartID().intValue();

                            reqIdArray[i] = String.valueOf(p10Id);

                            CertificationRequest p10 =
                                    tcr.getCertificationRequest();

                            // transfer to sun class
                            ByteArrayOutputStream ostream =
                                    new ByteArrayOutputStream();

                            p10.encode(ostream);
                            boolean sigver = true;
                            boolean tokenSwitched = false;
                            CryptoManager cm = null;
                            CryptoToken signToken = null;
                            CryptoToken savedToken = null;
                            sigver = CMS.getConfigStore().getBoolean("ca.requestVerify.enabled", true);
                            try {
                                cm = CryptoManager.getInstance();
                                if (sigver == true) {
                                    String tokenName =
                                        CMS.getConfigStore().getString("ca.requestVerify.token", "internal");
                                    savedToken = cm.getThreadToken();
                                    if (tokenName.equals("internal")) {
                                        signToken = cm.getInternalCryptoToken();
                                    } else {
                                        signToken = cm.getTokenByName(tokenName);
                                    }
                                    if (!savedToken.getName().equals(signToken.getName())) {
                                        cm.setThreadToken(signToken);
                                        tokenSwitched = true;
                                    }
                                }

                                PKCS10 pkcs10 =
                                        new PKCS10(ostream.toByteArray(), sigver);

                                // xxx do we need to do anything else?
                                X509CertInfo certInfo =
                                        CMS.getDefaultX509CertInfo();

                                // fillPKCS10(certInfo,pkcs10,authToken,null);

                                // authToken.set(
                                //     pkcs10.getSubjectPublicKeyInfo());

                                X500Name tempName = pkcs10.getSubjectName();

                                // reset value of auditCertSubject
                                if (tempName != null) {
                                    auditCertSubject =
                                            tempName.toString().trim();
                                    if (auditCertSubject.equals("")) {
                                        auditCertSubject =
                                                ILogger.SIGNED_AUDIT_EMPTY_VALUE;
                                    }
                                    authToken.set(AuthToken.TOKEN_CERT_SUBJECT,
                                              tempName.toString());
                                }

                                authToken.set("uid", uid);
                                authToken.set("userid", userid);

                                certInfoArray[i] = certInfo;
                            } catch (Exception e) {
                                // store a message in the signed audit log file
                                auditMessage = CMS.getLogMessage(
                                        LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                                        auditSubjectID,
                                        ILogger.FAILURE,
                                        auditReqType,
                                        auditCertSubject,
                                        auditSignerInfo);

                                audit(auditMessage);

                                //throw new ECMSGWException(
                                //CMSGWResources.ERROR_PKCS101, e.toString());

                                e.printStackTrace();
                                throw new EBaseException(e.toString());
                            } finally {
                                if ((sigver == true) && (tokenSwitched == true)){
                                    cm.setThreadToken(savedToken);
                                }
                             }
                        } else if (type.equals(TaggedRequest.CRMF)) {

                            CMS.debug("CMCAuth: type is CRMF");
                            try {
                                CertReqMsg crm =
                                        taggedRequest.getCrm();
                                CertRequest certReq = crm.getCertReq();
                                INTEGER reqID = certReq.getCertReqId();
                                reqIdArray[i] = reqID.toString();
                                CertTemplate template = certReq.getCertTemplate();
                                Name name = template.getSubject();

                                // xxx do we need to do anything else?
                                X509CertInfo certInfo =
                                        CMS.getDefaultX509CertInfo();

                                // reset value of auditCertSubject
                                if (name != null) {
                                    String ss = name.getRFC1485();

                                    auditCertSubject = ss;
                                    if (auditCertSubject.equals("")) {
                                        auditCertSubject =
                                                ILogger.SIGNED_AUDIT_EMPTY_VALUE;
                                    }

                                    authToken.set(AuthToken.TOKEN_CERT_SUBJECT, ss);
                                    authToken.set("uid", uid);
                                    authToken.set("userid", userid);
                                }
                                certInfoArray[i] = certInfo;
                            } catch (Exception e) {
                                // store a message in the signed audit log file
                                auditMessage = CMS.getLogMessage(
                                        LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                                        auditSubjectID,
                                        ILogger.FAILURE,
                                        auditReqType,
                                        auditCertSubject,
                                        auditSignerInfo);

                                audit(auditMessage);

                                //throw new ECMSGWException(
                                //CMSGWResources.ERROR_PKCS101, e.toString());

                                e.printStackTrace();
                                throw new EBaseException(e.toString());
                            }
                        }

                        // authToken.set(AgentAuthentication.CRED_CERT, new
                        //     com.netscape.certsrv.usrgrp.Certificates(
                        //     x509Certs));
                    }
                }
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditReqType,
                        auditCertSubject,
                        auditSignerInfo);

                audit(auditMessage);

                //Debug.printStackTrace(e);
                throw new EInvalidCredentials(CMS.getUserMessage(
                        "CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    auditReqType,
                    auditCertSubject,
                    auditSignerInfo);

            audit(auditMessage);

            return authToken;
        } catch (EMissingCredential eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                    auditSubjectID,
                    ILogger.FAILURE,
                    auditReqType,
                    auditCertSubject,
                    auditSignerInfo);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (EInvalidCredentials eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                    auditSubjectID,
                    ILogger.FAILURE,
                    auditReqType,
                    auditCertSubject,
                    auditSignerInfo);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
        } catch (EBaseException eAudit3) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY,
                    auditSubjectID,
                    ILogger.FAILURE,
                    auditReqType,
                    auditCertSubject,
                    auditSignerInfo);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit3;
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
        CMS.debug("CMCAuth: getExtendedPluginInfo()");
        String[] s = Utils.getStringArrayFromVector(mExtendedPluginInfo);

        CMS.debug("CMCAuth: s.length = " + s.length);
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
                level, "CMC Authentication: " + msg);
    }

    protected IAuthToken verifySignerInfo(AuthToken authToken, SignedData cmcFullReq) throws EBaseException {

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
                org.mozilla.jss.pkix.cms.SignerInfo si = (org.mozilla.jss.pkix.cms.SignerInfo) sis.elementAt(i);

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
                    IssuerAndSerialNumber issuerAndSerialNumber = sid.getIssuerAndSerialNumber();
                    // find from the certs in the signedData
                    java.security.cert.X509Certificate cert = null;

                    if (cmcFullReq.hasCertificates()) {
                        SET certs = cmcFullReq.getCertificates();
                        int numCerts = certs.size();
                        java.security.cert.X509Certificate[] x509Certs = new java.security.cert.X509Certificate[1];
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
                                ByteArrayOutputStream os = new
                                        ByteArrayOutputStream();

                                certJss.encode(os);
                                certByteArray = os.toByteArray();

                                X509CertImpl tempcert = new X509CertImpl(os.toByteArray());

                                cert = tempcert;
                                x509Certs[0] = cert;
                                // xxx validate the cert length

                            }
                        }
                        CMS.debug("CMCAuth: start checking signature");
                        if (cert == null) {
                            // find from certDB
                            CMS.debug("CMCAuth: verifying signature");
                            si.verify(digest, id);
                        } else {
                            CMS.debug("CMCAuth: found signing cert... verifying");
                            PublicKey signKey = cert.getPublicKey();
                            PrivateKey.Type keyType = null;
                            String alg = signKey.getAlgorithm();

                            PK11PubKey pubK = null;
                            if (alg.equals("RSA")) {
                                CMS.debug("CMCAuth: signing key alg=RSA");
                                keyType = PrivateKey.RSA;
                                pubK = PK11PubKey.fromRaw(keyType, ((X509Key) signKey).getKey());
                            } else if (alg.equals("EC")) {
                                CMS.debug("CMCAuth: signing key alg=EC");
                                keyType = PrivateKey.EC;
                                byte publicKeyData[] = ((X509Key) signKey).getEncoded();
                                pubK = (PK11PubKey) PK11ECPublicKey.fromSPKI(/*keyType,*/ publicKeyData);
                            } else if (alg.equals("DSA")) {
                                CMS.debug("CMCAuth: signing key alg=DSA");
                                keyType = PrivateKey.DSA;
                                pubK = PK11PubKey.fromSPKI(/*keyType,*/ ((X509Key) signKey).getKey());
                            }

                            String tokenName =
                                CMS.getConfigStore().getString("ca.requestVerify.token", "internal");
                            // by default JSS will use internal crypto token
                            if (!tokenName.equals("internal")) {
                                savedToken = cm.getThreadToken();
                                signToken = cm.getTokenByName(tokenName);
                                if(signToken != null) {
                                    cm.setThreadToken(signToken);
                                    tokenSwitched = true;
                                    CMS.debug("CMCAuth: verifySignerInfo token switched:"+ tokenName);
                                } else {
                                    CMS.debug("CMCAuth: verifySignerInfo token not found:"+ tokenName+ ", trying internal");
                                }
                            }

                            CMS.debug("CMCAuth: verifying signature with public key");
                            si.verify(digest, id, pubK);
                        }
                        CMS.debug("CMCAuth: finished checking signature");
                        // verify signer's certificate using the revocator
                        if (!cm.isCertValid(certByteArray, true, CryptoManager.CertUsage.SSLClient))
                            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

                        // authenticate signer's certificate using the userdb
                        IAuthSubsystem authSS = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);

                        IAuthManager agentAuth = authSS.getAuthManager(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID);//AGENT_AUTHMGR_ID);
                        if (agentAuth == null) {
                            throw new EBaseException(CMS.getUserMessage("CMS_AUTHENTICATION_MANAGER_NOT_FOUND", IAuthSubsystem.CERTUSERDB_AUTHMGR_ID));
                        }
                        IAuthCredentials agentCred = new com.netscape.certsrv.authentication.AuthCredentials();

                        agentCred.set(IAuthManager.CRED_SSL_CLIENT_CERT, x509Certs);

                        IAuthToken tempToken = agentAuth.authenticate(agentCred);
                        netscape.security.x509.X500Name tempPrincipal = (X500Name) x509Certs[0].getSubjectDN();
                        String CN = tempPrincipal.getCommonName(); //tempToken.get("userid");

                        BigInteger agentCertSerial = x509Certs[0].getSerialNumber();
                        authToken.set(IAuthManager.CRED_SSL_CLIENT_CERT, agentCertSerial.toString());
                        tempToken.set("cn", CN);
                        return tempToken;

                    }
                    // find from internaldb if it's ca. (ra does not have that.)
                    // find from internaldb usrgrp info

                    // find from certDB
                    si.verify(digest, id);

                } //
            }
        } catch (InvalidBERException e) {
            CMS.debug("CMCAuth: " + e.toString());
        } catch (IOException e) {
            CMS.debug("CMCAuth: " + e.toString());
        } catch (NotInitializedException e) {
            CMS.debug("CMCAuth: " + e.toString());
        } catch (Exception e) {
            CMS.debug("CMCAuth: " + e.toString());
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        } finally {
            if ((tokenSwitched == true) && (savedToken != null)){
                cm.setThreadToken(savedToken);
                CMS.debug("CMCAuth: verifySignerInfo token restored");
            }
        }
        return null;

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

    /**
     * Signed Audit Log Subject ID
     *
     * This method is called to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    private String auditSubjectID() {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String)
                    auditContext.get(SessionContext.USER_ID);

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
}
