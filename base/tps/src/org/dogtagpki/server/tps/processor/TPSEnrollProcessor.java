package org.dogtagpki.server.tps.processor;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.DataFormatException;

import org.dogtagpki.server.tps.TPSSession;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.TPSTokenPolicy;
import org.dogtagpki.server.tps.authentication.TPSAuthenticator;
import org.dogtagpki.server.tps.channel.SecureChannel;
import org.dogtagpki.server.tps.channel.SecureChannel.TokenKeyType;
import org.dogtagpki.server.tps.cms.CAEnrollCertResponse;
import org.dogtagpki.server.tps.cms.CARemoteRequestHandler;
import org.dogtagpki.server.tps.cms.CARenewCertResponse;
import org.dogtagpki.server.tps.cms.CARetrieveCertResponse;
import org.dogtagpki.server.tps.cms.CARevokeCertResponse;
import org.dogtagpki.server.tps.cms.KRARecoverKeyResponse;
import org.dogtagpki.server.tps.cms.KRAServerSideKeyGenResponse;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TPSCertRecord;
import org.dogtagpki.server.tps.dbs.TokenCertStatus;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.server.tps.engine.TPSEngine.ENROLL_MODES;
import org.dogtagpki.server.tps.main.AttributeSpec;
import org.dogtagpki.server.tps.main.ExternalRegAttrs;
import org.dogtagpki.server.tps.main.ExternalRegCertToRecover;
import org.dogtagpki.server.tps.main.ObjectSpec;
import org.dogtagpki.server.tps.main.PKCS11Obj;
import org.dogtagpki.server.tps.mapping.BaseMappingResolver;
import org.dogtagpki.server.tps.mapping.FilterMappingParams;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.main.Util;
import org.dogtagpki.tps.msg.BeginOpMsg;
import org.dogtagpki.tps.msg.EndOpMsg;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkcs11.PK11RSAPublicKey;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.util.Utils;

import netscape.security.provider.RSAPublicKey;
import netscape.security.util.BigInt;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.X509CertImpl;
import sun.security.pkcs11.wrapper.PKCS11Constants;

public class TPSEnrollProcessor extends TPSProcessor {

    public TPSEnrollProcessor(TPSSession session) {
        super(session);
    }

    @Override
    public void process(BeginOpMsg beginMsg) throws TPSException, IOException {

        if (beginMsg == null) {
            throw new TPSException("TPSEnrollrocessor.process: invalid input data, not beginMsg provided.",
                    TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }
        setBeginMessage(beginMsg);
        setCurrentTokenOperation("enroll");
        checkIsExternalReg();

        enroll();

    }

    private void enroll() throws TPSException, IOException {
        String method = "TPSEnrollProcessor.enroll:";
        CMS.debug(method + " entering...");
        String logMsg = null;
        String auditInfo = null;
        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        TPSTokenPolicy tokenPolicy = new TPSTokenPolicy(tps);
        IConfigStore configStore = CMS.getConfigStore();
        String configName;

        AppletInfo appletInfo = null;
        TokenRecord tokenRecord = null;

        byte lifecycleState = (byte) 0xf0;
        int appletUpgraded = 0;

        lifecycleState = getLifecycleState();

        try {
            appletInfo = getAppletInfo();
            auditOpRequest("enroll", appletInfo, "success", null);
        } catch (TPSException e) {
            auditInfo = e.toString();
            // appletInfo is null as expected at this point
            // but audit for the record anyway
            auditOpRequest("enroll", appletInfo, "failure", auditInfo);
            tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), auditInfo,
                    "failure");

            throw e;
        }
        appletInfo.setAid(getCardManagerAID());

        CMS.debug(method + " token cuid: " + appletInfo.getCUIDhexStringPlain());
        boolean isTokenPresent = false;

        tokenRecord = isTokenRecordPresent(appletInfo);

        if (tokenRecord != null) {
            CMS.debug(method + " found token...");
            isTokenPresent = true;
        } else {
            CMS.debug(method + " token does not exist in tokendb... create one in memory");
            tokenRecord = new TokenRecord();
            tokenRecord.setId(appletInfo.getCUIDhexStringPlain());
        }

        fillTokenRecord(tokenRecord, appletInfo);
        String cuid = appletInfo.getCUIDhexStringPlain();
        session.setTokenRecord(tokenRecord);
        String tokenType = null;
        ExternalRegAttrs erAttrs = null;

        if (isExternalReg) {
            CMS.debug("In TPSEnrollProcessor.enroll isExternalReg: ON");
            /*
             * need to reach out to the Registration DB (authid)
             * Entire user entry should be retrieved and parsed, if needed
             * The following are retrieved, e.g.:
             *     externalReg.tokenTypeAttributeName=tokenType
             *     externalReg.certs.recoverAttributeName=certsToRecover
             *     externalReg.tokenCuidName=userKey
             */
            configName = "externalReg.authId";
            String authId;
            try {
                authId = configStore.getString(configName);
            } catch (EBaseException e) {
                CMS.debug(method + " Internal Error obtaining mandatory config values. Error: " + e);
                logMsg = "TPS error getting config values from config store." + e.toString();
                tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }

            TPSAuthenticator userAuth = null;
            try {
                CMS.debug("In TPSEnrollProcessor.enroll: isExternalReg: calling requestUserId");
                userAuth = getAuthentication(authId);
                processAuthentication(TPSEngine.ENROLL_OP, userAuth, cuid, tokenRecord);
                auditAuthSuccess(userid, currentTokenOperation, appletInfo, authId);

            } catch (Exception e) {
                // all exceptions are considered login failure
                auditAuthFailure(userid, currentTokenOperation, appletInfo,
                        (userAuth != null) ? userAuth.getID() : null);

                CMS.debug(method + ": authentication exception thrown: " + e);
                logMsg = "ExternalReg authentication failed, status = STATUS_ERROR_LOGIN";

                tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg,
                        TPSStatus.STATUS_ERROR_LOGIN);
            }

            try {
                erAttrs = processExternalRegAttrs(authId);
            } catch (Exception ee) {
                logMsg = "after processExternalRegAttrs: " + ee.toString();
                tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }

            /*
             * If cuid is provided on the user registration record, then
             * we have to compare that with the current token cuid;
             *
             * If, the cuid is not provided on the user registration record,
             * then any token can be used.
             */
            if (erAttrs.getTokenCUID() != null) {
                CMS.debug(method + " checking if token cuid matches record cuid");
                CMS.debug(method + " erAttrs.getTokenCUID()=" + erAttrs.getTokenCUID());
                CMS.debug(method + " tokenRecord.getId()=" + tokenRecord.getId());
                if (!tokenRecord.getId().equalsIgnoreCase(erAttrs.getTokenCUID())) {
                    logMsg = "isExternalReg: token CUID not matching record:" + tokenRecord.getId() + " : " +
                            erAttrs.getTokenCUID();
                    CMS.debug(method + logMsg);
                    tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                            "failure");
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_NOT_TOKEN_OWNER);
                } else {
                    logMsg = "isExternalReg: token CUID matches record";
                    CMS.debug(method + logMsg);
                }
            } else {
                CMS.debug(method + " no need to check if token cuid matches record");
            }

            session.setExternalRegAttrs(erAttrs);
            setExternalRegSelectedTokenType(erAttrs);

            CMS.debug("In TPSEnrollProcessor.enroll isExternalReg: about to process keySet resolver");
            /*
             * Note: externalReg.mappingResolver=none indicates no resolver
             *    plugin used
             */
            try {
                String resolverInstName = getKeySetResolverInstanceName();

                if (!resolverInstName.equals("none") && (selectedKeySet == null)) {
                    FilterMappingParams mappingParams = createFilterMappingParams(resolverInstName,
                            appletInfo.getCUIDhexStringPlain(), appletInfo.getMSNString(),
                            appletInfo.getMajorVersion(), appletInfo.getMinorVersion());
                    TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
                    BaseMappingResolver resolverInst = subsystem.getMappingResolverManager()
                            .getResolverInstance(resolverInstName);
                    String keySet = resolverInst.getResolvedMapping(mappingParams, "keySet");
                    setSelectedKeySet(keySet);
                    CMS.debug(method + " resolved keySet: " + keySet);
                }
            } catch (TPSException e) {
                logMsg = e.toString();
                tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }
        } else {
            CMS.debug("In TPSEnrollProcessor.enroll isExternalReg: OFF");
            /*
             * Note: op.enroll.mappingResolver=none indicates no resolver
             *    plugin used (tokenType resolved perhaps via authentication)
             */
            try {
                String resolverInstName = getResolverInstanceName();

                if (!resolverInstName.equals("none") && (selectedTokenType == null)) {
                    FilterMappingParams mappingParams = createFilterMappingParams(resolverInstName,
                            appletInfo.getCUIDhexStringPlain(), appletInfo.getMSNString(),
                            appletInfo.getMajorVersion(), appletInfo.getMinorVersion());
                    TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
                    BaseMappingResolver resolverInst = subsystem.getMappingResolverManager()
                            .getResolverInstance(resolverInstName);
                    tokenType = resolverInst.getResolvedMapping(mappingParams);
                    setSelectedTokenType(tokenType);
                    CMS.debug(method + " resolved tokenType: " + tokenType);
                }
            } catch (TPSException e) {
                logMsg = e.toString();
                tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }
        }

        checkProfileStateOK();

        boolean do_force_format = false;
        if (isTokenPresent) {
            CMS.debug(method + " token exists in tokendb");

            TokenStatus newState = TokenStatus.ACTIVE;
            // Check for transition to ACTIVE status.

            if (!tps.isOperationTransitionAllowed(tokenRecord, newState)) {
                CMS.debug(method + " token transition disallowed " +
                        tokenRecord.getTokenStatus() +
                        " to " + newState);
                logMsg = "Operation for CUID " + cuid +
                        " Disabled, illegal transition attempted " + tokenRecord.getTokenStatus() +
                        " to " + newState;
                tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg,
                        TPSStatus.STATUS_ERROR_DISABLED_TOKEN);
            } else {
                CMS.debug("TPSPEnrollrocessor.enroll: token transition allowed " +
                        tokenRecord.getTokenStatus() +
                        " to " + newState);
            }

            do_force_format = tokenPolicy.isForceTokenFormat(cuid);
            if (do_force_format)
                CMS.debug(method + " Will force format first due to policy.");

            if (!isExternalReg &&
                    !tokenPolicy.isAllowdTokenReenroll(cuid) &&
                    !tokenPolicy.isAllowdTokenRenew(cuid)) {
                CMS.debug(method + " token renewal or reEnroll disallowed ");
                logMsg = "Operation renewal or reEnroll for CUID " + cuid +
                        " Disabled";
                tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg,
                        TPSStatus.STATUS_ERROR_DISABLED_TOKEN);
            } else {
                logMsg = "isExternalReg: skip token policy (reenroll, renewal) check";
                CMS.debug(method + logMsg);
            }
        } else {
            CMS.debug(method + " token does not exist");
            checkAllowUnknownToken(TPSEngine.OP_FORMAT_PREFIX);
            CMS.debug(method + "force a format");
            do_force_format = true;
        }

        // isExternalReg : user already authenticated earlier
        if (!isExternalReg)
            checkAndAuthenticateUser(appletInfo, getSelectedTokenType());

        //Do this here after all authentication has taken place, so we have a (userid)

        boolean allowMultiTokens = checkAllowMultiActiveTokensUser(isExternalReg);

        if (allowMultiTokens == false) {
            boolean alreadyHasActiveToken = checkUserAlreadyHasOtherActiveToken(userid, cuid);

            if (alreadyHasActiveToken == true) {
                //We don't allow the user to have more than one active token, nip it in the bud right now
                //If this token is brand new and not known to the system

                throw new TPSException(method
                        + " User already has an active token when trying to enroll this new token!",
                        TPSStatus.STATUS_ERROR_HAS_AT_LEAST_ONE_ACTIVE_TOKEN);
            }

        }

        if (do_force_format) {
            //We will skip the auth step inside of format
            format(true);
        } else {
            appletUpgraded = checkAndUpgradeApplet(appletInfo);
            //Get new applet info
            appletInfo = getAppletInfo();
        }

        CMS.debug(method + " Finished updating applet if needed.");

        //Check and upgrade keys if called for
        SecureChannel channel = checkAndUpgradeSymKeys(appletInfo, tokenRecord);
        channel.externalAuthenticate();

        //Reset the token's pin, create one if we don't have one already
        checkAndHandlePinReset(channel);
        tokenRecord.setKeyInfo(channel.getKeyInfoData().toHexStringPlain());
        String tksConnId = getTKSConnectorID();
        TPSBuffer plaintextChallenge = computeRandomData(16, tksConnId);

        CMS.debug(method + " plaintextChallenge: " + plaintextChallenge.toHexString());

        //These will be used shortly
        TPSBuffer wrappedChallenge = encryptData(appletInfo, channel.getKeyInfoData(), plaintextChallenge, tksConnId,
                this.getProtocol());
        PKCS11Obj pkcs11objx = null;

        try {
            pkcs11objx = getCurrentObjectsOnToken(channel);
        } catch (DataFormatException e) {
            logMsg = method + " Failed to parse original token data: " + e.toString();
            tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");

            throw new TPSException(logMsg);
        }

        pkcs11objx.setCUID(appletInfo.getCUID());

        statusUpdate(10, "PROGRESS_PROCESS_PROFILE");

        EnrolledCertsInfo certsInfo = new EnrolledCertsInfo();
        certsInfo.setWrappedChallenge(wrappedChallenge);
        certsInfo.setPlaintextChallenge(plaintextChallenge);
        certsInfo.setPKCS11Obj(pkcs11objx);
        certsInfo.setStartProgress(15);
        certsInfo.setEndProgress(90);

        boolean renewed = false;
        boolean recovered = false;

        TPSStatus status = TPSStatus.STATUS_NO_ERROR;

        if (!isExternalReg) {
            status = generateCertsAfterRenewalRecoveryPolicy(certsInfo, channel, appletInfo);
        }

        //most failed would have thrown an exception
        logMsg = " generateCertsAfterRenewalRecoveryPolicy returned status=" + status;
        String statusString = "Unknown"; // gives some meaningful debug message
        if (status == TPSStatus.STATUS_NO_ERROR)
            statusString = "Enrollment to follow";
        else if (status == TPSStatus.STATUS_ERROR_RECOVERY_IS_PROCESSED) {
            statusString = "Recovery processed";
            recovered = true;
            tps.tdb.tdbActivity(ActivityDatabase.OP_RECOVERY, tokenRecord, session.getIpAddress(), logMsg, "success");
        } else if (status == TPSStatus.STATUS_ERROR_RENEWAL_IS_PROCESSED) {
            statusString = "Renewal processed";
            renewed = true;
            tps.tdb.tdbActivity(ActivityDatabase.OP_RENEWAL, tokenRecord, session.getIpAddress(), logMsg, "success");
        } else {
            CMS.debug(method + logMsg);
            tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");
            throw new TPSException(logMsg);
        }
        if (!isExternalReg) {
            logMsg = "generateCertsAfterRenewalRecoveryPolicy returns status:"
                    + EndOpMsg.statusToInt(status) + " : " + statusString;
            CMS.debug(method + logMsg);
        }
        if (status == TPSStatus.STATUS_NO_ERROR) {
            if (!generateCertificates(certsInfo, channel, appletInfo)) {
                CMS.debug(method + "generateCertificates returned false means cert enrollment unsuccessful");
                // in case isExternalReg, leave the token alone, do not format
                if (!isExternalReg) {
                    CMS.debug(method
                            + "generateCertificates returned false means some certs failed enrollment;  clean up (format) the token");
                    format(true /*skipAuth*/);
                }
                tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");
                throw new TPSException("generateCertificates failed");
            } else {
                CMS.debug(method + "generateCertificates returned true means cert enrollment successful");
                /*
                 * isExternalReg -
                 * ??  Renew if token has "RENEW=YES" set by admin
                 *   recovery and delete/revoke happens:
                 *       recover certsToRecover
                 *       delete/revoke certsToDelete
                 *       (per latest design, delete is implied for certs
                 *       not existing in the recover list)
                 */

                if (isExternalReg) {
                    try {
                        TPSStatus recoverStatus = externalRegRecover(cuid, userid, channel, certsInfo, appletInfo,
                                tokenRecord);
                        CMS.debug(method + " after externalRegRecover status is:" + recoverStatus);
                        if (recoverStatus == TPSStatus.STATUS_ERROR_RECOVERY_IS_PROCESSED) {
                            recovered = true;
                            logMsg = method + " externalRegRecover returned: recoverStatus=" + recoverStatus;
                            tps.tdb.tdbActivity(ActivityDatabase.OP_RECOVERY, tokenRecord, session.getIpAddress(),
                                    logMsg, "success");
                        } else {
                            logMsg = method + " externalRegRecover returned: recoverStatus=" + recoverStatus;
                            CMS.debug(logMsg);
                            tps.tdb.tdbActivity(ActivityDatabase.OP_RECOVERY, tokenRecord, session.getIpAddress(),
                                    logMsg,
                                    "failure");

                            throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_BAD_STATUS);
                        }
                    } catch (EBaseException e) {
                        logMsg = method + " externalRegRecover: " + e;
                        CMS.debug(logMsg);
                        tps.tdb.tdbActivity(ActivityDatabase.OP_RECOVERY, tokenRecord, session.getIpAddress(),
                                logMsg,
                                "failure");

                        throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_BAD_STATUS);
                    }
                } else {
                    //TODO:
                    //tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                    //"success");
                }
            }
        }
        // at this point, enrollment, renewal, or recovery have been processed accordingly;
        if (!isExternalReg &&
                status == TPSStatus.STATUS_ERROR_RENEWAL_IS_PROCESSED &&
                tokenPolicy.isAllowdTokenRenew(cuid)) {
            renewed = true;
            CMS.debug(method + " renewal happened.. ");
        }

        /*
         * TODO:
         * find the point to do the following...
         * when total available memory is exceeded on the token ...
         *     if(!renewed) //Renewal should leave what they have on the token.
         *         format(true);
         */
        String tokenLabel = buildTokenLabel(certsInfo, appletInfo);

        pkcs11objx.setTokenName(new TPSBuffer(tokenLabel.getBytes()));

        int lastObjVer = pkcs11objx.getOldObjectVersion();

        CMS.debug(method + " getOldObjectVersion: returning: " + lastObjVer);

        if (lastObjVer != 0) {
            while (lastObjVer == 0xff) {
                JssSubsystem jssSubsystem = (JssSubsystem) CMS.getSubsystem(JssSubsystem.ID);
                SecureRandom randomGenerator = jssSubsystem.getRandomNumberGenerator();
                lastObjVer = randomGenerator.nextInt(1000);
            }

            lastObjVer = lastObjVer + 1;
            CMS.debug(method + " Setting objectVersion to: " + lastObjVer);
            pkcs11objx.setObjectVersion(lastObjVer);

        }

        pkcs11objx.setFormatVersion(pkcs11objx.getOldFormatVersion());

        // Make sure we have a good secure channel before writing out the final objects
        channel = setupSecureChannel(appletInfo);

        statusUpdate(92, "PROGRESS_WRITE_OBJECTS");

        // Purge the object list of certs that have not been explicilty saved from deletion
        if (isExternalReg) {
            status = cleanObjectListBeforeExternalRecovery(certsInfo);
            if (status != TPSStatus.STATUS_NO_ERROR) {
                throw new TPSException("cleanObjectListBeforeExternalRecovery returns error: " + status);
            }
        }

        writeFinalPKCS11ObjectToToken(pkcs11objx, appletInfo, channel);
        statusUpdate(98, "PROGRESS_ISSUER_INFO");
        writeIssuerInfoToToken(channel, appletInfo);

        statusUpdate(99, "PROGRESS_SET_LIFECYCLE");

        if (lifecycleState != 0x0f || appletUpgraded == 1) {
            CMS.debug(method + " Need to reset the lifecycle state. current state: " + lifecycleState
                    + " Was applet upgraded: " + appletUpgraded);
            channel.setLifecycleState((byte) 0x0f);
            CMS.debug(method + " after channel.setLifecycleState");
        } else {
            CMS.debug(method + " No need to reset lifecycle state, it is already at the proper value.");
        }

        ArrayList<ExternalRegCertToRecover> erCertsToRecover = null;
        erAttrs = session.getExternalRegAttrs();
        if (isExternalReg && (erAttrs!= null)) {
            erCertsToRecover = erAttrs.getCertsToRecover();
        }

        /**
         * Update the tokendb with new certs:
         * 1. Clean up the cert records on the token, with the exception
         * of certs to be retained
         * 2. Transform EnrolledCertsInfo to arry of TPSCertRecord's
         * 3. Add the certs from TPSCertRecord array onto the token, with the
         * exception of the retained certs already on token
         */

        CMS.debug(method + " updating tokendb with certs.");
        try {
            // clean up the cert records used to belong to this token in tokendb;
            // spare the retained certs
            tps.tdb.tdbRemoveCertificatesByCUID(tokenRecord.getId(), erCertsToRecover);
        } catch (Exception e) {
            logMsg = "Attempt to clean up record with tdbRemoveCertificatesByCUID failed; token probably clean; continue anyway:"
                    + e;
            CMS.debug(method + logMsg);
        }

        // transform EnrolledCertsInfo to TPSCertRecords
        ArrayList<TPSCertRecord> certRecords = certsInfo.toTPSCertRecords(tokenRecord.getId(), tokenRecord.getUserID());

        CMS.debug(method + " adding certs to token with tdbAddCertificatesForCUID...");
        tps.tdb.tdbAddCertificatesForCUID(tokenRecord.getId(), certRecords);
        CMS.debug(method + " tokendb updated with certs to the cuid so that it reflects what's on the token");

        logMsg = "appletVersion=" + lastObjVer + "; tokenType =" + selectedTokenType + "; userid =" + userid;
        CMS.debug(method + logMsg);
        try {
            tokenRecord.setTokenStatus(TokenStatus.ACTIVE);
            tps.tdb.tdbUpdateTokenEntry(tokenRecord);
            tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg, "success");
        } catch (Exception e) {
            logMsg = logMsg + ":" + e.toString();
            tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");
            throw new TPSException(logMsg);
        }

        //Now let's clear off any key slots if the enrollment left any unused but occupied with key data on the applet

        TPSBuffer keyList = pkcs11objx.getKeyIndexList();

        channel.clearAppletKeySlotData(keyList);

        CMS.debug(method + " leaving ...");

        statusUpdate(100, "PROGRESS_DONE_ENROLLMENT");
    }

    /*
     * cleanObjectListBeforeExternalRecovery
     *  - in the ExternalReg case, certs not to be retained are cleaned off the pkcs11obj before further processing
     *  - certs to be retained are represented in the certsToAdd attribute as <serialNum, caConn>  without the keyId and kraConn
     */
    private TPSStatus cleanObjectListBeforeExternalRecovery(EnrolledCertsInfo certsInfo) {
        TPSStatus status = TPSStatus.STATUS_NO_ERROR;
        final String method = "TPSEnrollProcessor.cleanObjectListBeforeExternalRecovery :";
        final int MAX_CERTS = 30;
        IConfigStore configStore = CMS.getConfigStore();

        /*
         * Arrays that hold simple indexes of certsToDelete and certsToSave.
         * certsToDelete is a list of certs NOT in the recovery list.
         * certsToSave is a list of certs to spare from deletion because they
         * were enrolled by the regular token profile.
         */
        int certsToDelete[] = new int[MAX_CERTS];
        int certsToSave[] = new int[MAX_CERTS];
        int numCertsToDelete = 0;
        int numCertsToSave = 0;

        CMS.debug(method + ": begins");
        if (certsInfo == null) {
            CMS.debug(method + "certsInfo cannot be null");
            return TPSStatus.STATUS_ERROR_MISCONFIGURATION;
        }
        PKCS11Obj pkcs11obj = certsInfo.getPKCS11Obj();
        if (pkcs11obj == null) {
            CMS.debug(method + "no pkcs11obj to work with");
            return TPSStatus.STATUS_ERROR_MISCONFIGURATION;
        }
        ExternalRegAttrs erAttrs = session.getExternalRegAttrs();
        if (session == null || erAttrs == null ||
                erAttrs.getCertsToRecover() == null) {
            CMS.debug(method + "no externalReg attrs to work with");
            return TPSStatus.STATUS_ERROR_MISCONFIGURATION;
        }

        int count = erAttrs.getCertsToRecoverCount();
        CMS.debug(method + "number of certs to recover=" + count);
        if (count == 0) {
            CMS.debug(method + " nothing to process. Returning status: "
                    + status);
            return status;
        }
        String tokenType = erAttrs.getTokenType();
        if (tokenType == null) {
            CMS.debug(method + " erAttrs tokenType null. Returning status: "
                    + status);
            return TPSStatus.STATUS_ERROR_MISCONFIGURATION;
        }

        /*
         * Now let's try to save the just freshly enrolled certificates
         * based on regular profile from deletion.
         */
        String configName = "op.enroll." +
                tokenType + "." +
                "keyGen.keyType.num";

        int keyTypeNum = 0;
        try {
            CMS.debug(method + " getting config : " + configName);
            Integer keyTypeNumI = configStore.getInteger(configName);
            keyTypeNum = keyTypeNumI.intValue();
        } catch (Exception e) {
            //return TPSStatus.STATUS_ERROR_MISCONFIGURATION;
            // some externalReg profiles are for "recovering only"
            keyTypeNum = 0;
        }
        CMS.debug(method + " config keyTypeNum: " + keyTypeNum);

        int index = -1;
        for (int i = 0; i < keyTypeNum; i++) {
            configName = "op.enroll." +
                    tokenType + "." +
                    "keyGen.keyType.value." + i;
            String keyTypeValue;
            try {
                CMS.debug(method + " getting config : " + configName);
                keyTypeValue = configStore.getString(configName);
            } catch (EPropertyNotFound e) {
                e.printStackTrace();
                return TPSStatus.STATUS_ERROR_MISCONFIGURATION;
            } catch (EBaseException e) {
                e.printStackTrace();
                return TPSStatus.STATUS_ERROR_MISCONFIGURATION;
            }
            CMS.debug(method + " config keyTypeValue: " + keyTypeValue);
            String keyTypePrefix = "op.enroll." +
                    tokenType + ".keyGen." + keyTypeValue;
            CMS.debug(method + " keyTypePrefix is: " + keyTypePrefix);

            configName = keyTypePrefix + ".certId";
            String certId;
            try {
                CMS.debug(method + " getting config : " + configName);
                certId = configStore.getString(configName);
            } catch (EPropertyNotFound e) {
                e.printStackTrace();
                return TPSStatus.STATUS_ERROR_MISCONFIGURATION;
            } catch (EBaseException e) {
                e.printStackTrace();
                return TPSStatus.STATUS_ERROR_MISCONFIGURATION;
            }
            if (certId != null && certId.length() > 1) {
                index = ObjectSpec.getObjectIndex(certId);
            }
            //CMS.debug(method + " certId is: " + certId + " index is: " + index);

            if (index >= 0 && numCertsToSave < MAX_CERTS) {
                /* Set an entry in the list in order to save from subsequent deletion. */
                CMS.debug(method + " saving object index to certsToSave: " + index);
                certsToSave[numCertsToSave++] = index;
            }
        }

        int num_objs = pkcs11obj.getObjectSpecCount();
        CMS.debug(method + " pkcs11obj num_objs =" + num_objs);
        // char[] bytesA = new char[3];

        /*
         * Go through the object spec list and remove stuff we have marked
         * for deletion. Remove Cert and all associated objects of that cert.
         */
        for (int i = 0; i < num_objs; i++) {
            ObjectSpec os = pkcs11obj.getObjectSpec(i);

            char type = os.getObjectType();
            int objIndex = os.getObjectIndex();
            CMS.debug(method + "i=" + i + " objIndex =" + objIndex);

            if (type == 'C') { /* Is this a cert object ? */
                CMS.debug(method + "obj type is cert... processing");
                for (int j = 0; j < os.getAttributeSpecCount(); j++) {
                    AttributeSpec as = os.getAttributeSpec(j);
                    if (as.getAttributeID() == PKCS11Constants.CKA_VALUE) {
                        if (as.getType() == (byte) 0) {
                            TPSBuffer certBuff = as.getValue();
                            X509CertImpl xCert = null;
                            try {
                                xCert = new X509CertImpl(certBuff.toBytesArray());
                            } catch (CertificateException e) {
                                CMS.debug(method + e);
                                e.printStackTrace();
                                return TPSStatus.STATUS_ERROR_CONTACT_ADMIN;
                            }
                            ExternalRegCertToRecover certToRecover =
                                    isInCertsToRecoverList(xCert);

                            int certId = objIndex;

                            if (certToRecover == null) {
                                CMS.debug(method + " cert not found in recovery list, possible deletion... id:"
                                        + certId);
                                /*
                                 * Now check the certsToSave list to see if this cert is protected
                                 */
                                boolean protect = false;
                                for (int p = 0; p < numCertsToSave; p++) {
                                    if (certsToSave[p] == certId) {
                                        protect = true;
                                        break;
                                    }
                                }
                                CMS.debug(method + " protect cert " + certId +
                                        ": " + protect);
                                /*
                                 * Delete this cert if it is NOT protected by
                                 * the certs generated by the profile enrollment.
                                 */
                                if ((numCertsToDelete < MAX_CERTS) &&
                                        (protect == false)) {
                                    certsToDelete[numCertsToDelete++] = certId;
                                }
                            } else {
                                CMS.debug(method + " cert found in recovery list, to be retained. id:" + certId);
                                // Add retained certs so tokendb will reflect;
                                // Do not add "recovered" certs, as that would
                                // cause duplication
                                if (certToRecover.getIsRetainable()) {
                                    CMS.debug(method + "cert is retainable; add to certsInfo");
                                    certsInfo.addCertificate(xCert);
                                }
                            }
                        }
                        break;
                    }
                }
            } else {
                CMS.debug(method + "obj type is not cert... next");
            }
        }

        /*
         * Now rifle through the certsToDeleteList and remove those that
         *  need to be deleted
         */
        CMS.debug(method + "numCertsToDelete: " + numCertsToDelete);
        for (int k = 0; k < numCertsToDelete; k++) {
            CMS.debug(method + "cert to delete: " + certsToDelete[k]);
            removeCertFromObjectList(certsToDelete[k], pkcs11obj);
        }

        num_objs = pkcs11obj.getObjectSpecCount();
        CMS.debug(method + "after removeCertFromObjectList(); final obj count: " + num_objs);

        CMS.debug(method + " ends. Returning status: "
                + status);
        return status;
    }

    /*
     * Remove a certificate from the Object Spec List based on Cert index ,
     *     C(1), C(2), etc
     */
    void removeCertFromObjectList(int cIndex, PKCS11Obj pkcs11obj) {
        String method = "TPSEnrollProcessor.removeCertFromObjectList: ";
        if (pkcs11obj == null) {
            CMS.debug(method + " pkcs11obj null");
            return;
        }

        CMS.debug(method + " index of cert to delete is: " + cIndex);

        int C = cIndex;
        int c = cIndex;
        int k1 = 2 * cIndex;
        int k2 = 2 * cIndex + 1;

        // loop through all objects on token
        int index = 0;
        for (int i = 0; i < pkcs11obj.getObjectSpecCount(); i++) {
            ObjectSpec spec = pkcs11obj.getObjectSpec(i);
            char c1 = spec.getObjectType();
            index = spec.getObjectIndex();
            /* locate all certificate objects */
            if (c1 == 'c' || c1 == 'C') {
                if (index == C || index == c) {
                    CMS.debug(method + " found index:" + index +
                            "; Removing cert Object");
                    pkcs11obj.removeObjectSpec(i);
                    i--;
                }
            }

            if (c1 == 'k') {
                if (index == k1 || index == k2) {
                    CMS.debug(method + " found index:" + index +
                            "; Removing key Object");
                    pkcs11obj.removeObjectSpec(i);
                    i--;
                }
            }
        }

    }

    private void writeFinalPKCS11ObjectToToken(PKCS11Obj pkcs11objx, AppletInfo ainfo, SecureChannel channel)
            throws TPSException, IOException {
        if (pkcs11objx == null || ainfo == null || channel == null) {
            throw new TPSException("TPSErollProcessor.writeFinalPKCS11ObjectToToken: invalid input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  entering...");

        IConfigStore configStore = CMS.getConfigStore();

        String compressConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + "pkcs11obj.compress.enable";

        CMS.debug("TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  config to check: " + compressConfig);

        boolean doCompress = false;

        try {
            doCompress = configStore.getBoolean(compressConfig, true);
        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.writeFinalPKCS11ObjectToToken: internal error obtaining config value " + e);
        }

        CMS.debug("TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  doCompress: " + doCompress);

        TPSBuffer tokenData = null;

        if (doCompress) {
            tokenData = pkcs11objx.getCompressedData();

        } else {
            tokenData = pkcs11objx.getData();
        }

        if (tokenData.size() > ainfo.getTotalMem()) {

            throw new TPSException(
                    "TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  NOt enough memory to write certificates!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

        byte[] zobjectid = { (byte) 'z', (byte) '0', 0, 0 };
        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };
        TPSBuffer zobjidBuf = new TPSBuffer(zobjectid);

        channel.createObject(zobjidBuf, new TPSBuffer(perms), tokenData.size());

        channel.writeObject(zobjidBuf, tokenData);

        CMS.debug("TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  leaving successfully ...");

    }

    private PKCS11Obj getCurrentObjectsOnToken(SecureChannel channel) throws TPSException, IOException,
            DataFormatException {

        byte seq = 0;

        TPSBuffer objects = null;

        int lastFormatVersion = 0x0100;
        int lastObjectVersion;

        JssSubsystem jssSubsystem = (JssSubsystem) CMS.getSubsystem(JssSubsystem.ID);
        SecureRandom randomGenerator = jssSubsystem.getRandomNumberGenerator();

        lastObjectVersion = randomGenerator.nextInt(1000);

        CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: Random lastObjectVersion: " + lastObjectVersion);

        PKCS11Obj pkcs11objx = new PKCS11Obj();
        pkcs11objx.setOldFormatVersion(lastFormatVersion);
        pkcs11objx.setOldObjectVersion(lastObjectVersion);

        do {

            objects = listObjects(seq);

            if (objects != null) {
                //CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: objects: " + objects.toHexString());
                CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: objects exist ");
            }

            if (objects == null) {
                pkcs11objx.setOldObjectVersion(lastObjectVersion);
                seq = 0;
            } else {
                seq = 1; // get next entry

                TPSBuffer objectID = objects.substr(0, 4);
                TPSBuffer objectLen = objects.substr(4, 4);

                long objectIDVal = objectID.getLongFrom4Bytes(0);

                long objectLenVal = objectLen.getLongFrom4Bytes(0);

                TPSBuffer obj = channel.readObject(objectID, 0, (int) objectLenVal);

                if (obj != null) {
                    //CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: obj: " + obj.toHexString());
                    CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: obj exists");
                }

                if ((char) objectID.at(0) == (byte) 'z' && objectID.at(1) == (byte) '0') {
                    lastFormatVersion = obj.getIntFrom2Bytes(0);
                    lastObjectVersion = obj.getIntFrom2Bytes(2);

                    CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: Versions read from token:  lastFormatVersion : "
                            + lastFormatVersion
                            + " lastObjectVersion: " + lastObjectVersion);

                    pkcs11objx = PKCS11Obj.parse(obj, 0);

                    pkcs11objx.setOldFormatVersion(lastFormatVersion);
                    pkcs11objx.setOldObjectVersion(lastObjectVersion);
                    seq = 0;

                } else {
                    ObjectSpec objSpec = ObjectSpec.parseFromTokenData(objectIDVal, obj);
                    pkcs11objx.addObjectSpec(objSpec);
                }

                //CMS.debug("TPSEnrollProcessor.getCurrentObjectsOnToken. just read object from token: "
                //        + obj.toHexString());
                CMS.debug("TPSEnrollProcessor.getCurrentObjectsOnToken. just read object from token");
            }

        } while (seq != 0);

        return pkcs11objx;
    }

    /**
     * Does given cert exist in the ExternalRegAttrs CertsToRecoverList?
     * We need to know if this cert is to be retained for an ExternalReg Recovery operation.
     *
     * If cert is in the list, it will be retained and not erased, otherwise it will go away.
     * Returns the ExternalRegCertToRecover if found; null otherwise;
     */
    private ExternalRegCertToRecover isInCertsToRecoverList(X509CertImpl xCert) {
        final String method = "TPSEnrollProcessor.isInCertsToRecoverList :";
        ExternalRegCertToRecover foundObj = null;
        if (xCert == null) {
            CMS.debug(method + "xCert is null. return false");
            return null;
        }
        ExternalRegAttrs erAttrs = session.getExternalRegAttrs();
        ArrayList<ExternalRegCertToRecover> erCertsToRecover = erAttrs.getCertsToRecover();
        CMS.debug(method + " begins checking for cert, serial:" + xCert.getSerialNumber());

        int count = erAttrs.getCertsToRecoverCount();
        if (count <= 0) {
            CMS.debug(method + "ends. recover list empty. returning: null");
            return null;
        }

        for (ExternalRegCertToRecover certToRecover : erCertsToRecover) {
            if (certToRecover == null) {
                continue;
            }
            // TODO: could enhance the comparison to include more than serials
            if (xCert.getSerialNumber().compareTo(certToRecover.getSerial()) == 0) {
                foundObj = certToRecover;
                break;
            }
        }

        CMS.debug(method + " ends. returning certToRecover");
        return foundObj;
    }

    /*
     * generateCertsAfterRenewalRecoveryPolicy determines whether a renewal or recovery is needed;
     * if recovery is needed, it determines which certificates (from which old token)
     *  to recover onto the new token.
     *
     * Note: renewal and recovery are invoked in this method;  However, if a new enrollment is determined
     * to be the proper course of action, it is done after this method.
     */
    private TPSStatus generateCertsAfterRenewalRecoveryPolicy(EnrolledCertsInfo certsInfo, SecureChannel channel,
            AppletInfo aInfo)
            throws TPSException, IOException {
        TPSStatus status = TPSStatus.STATUS_NO_ERROR;
        String logMsg;
        final String method = "TPSEnrollProcessor.generateCertsAfterRenewalRecoveryPolicy";
        CMS.debug(method + ": begins");
        IConfigStore configStore = CMS.getConfigStore();
        String configName;
        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        TPSTokenPolicy tokenPolicy = new TPSTokenPolicy(tps);

        ArrayList<TokenRecord> tokenRecords = null;
        try {
            tokenRecords = tps.tdb.tdbFindTokenRecordsByUID(userid);
        } catch (Exception e) {
            //TODO: when do you get here?
            // no existing record, means no "renewal" or "recovery" actions needed
            logMsg = "no token associated with user: " + userid;
            CMS.debug(method + logMsg);
            throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_INACTIVE_TOKEN_NOT_FOUND);
        }
        CMS.debug(method + " found " + tokenRecords.size() + " tokens for user:" + userid);
        boolean isRecover = false;

        TokenRecord lostToken = null;
        for (TokenRecord tokenRecord : tokenRecords) {
            CMS.debug(method + " token id:"
                    + tokenRecord.getId() + "; status="
                    + tokenRecord.getTokenStatus());

            //Is this the same token (current token)?
            if (tokenRecord.getId().equals(aInfo.getCUIDhexStringPlain())) {
                //same token
                logMsg = "found current token entry";
                CMS.debug(method + ":" + logMsg);

                if (tokenRecord.getTokenStatus() == TokenStatus.FORMATTED) {
                    // this is the current token
                    if (tokenRecords.size() == 1) {
                        // the current token is the only token owned by the user
                        CMS.debug(method + ": need to do enrollment");
                        // need to do enrollment outside
                        break;
                    } else {
                        CMS.debug(method + ": There are multiple token entries for user "
                                + userid);

                        //We already know the current token is not active
                        if (checkUserAlreadyHasActiveToken(userid) == false) {
                            isRecover = true;
                            continue; // TODO: or break?
                        }
                    }

                } else if (tokenRecord.getTokenStatus() == TokenStatus.ACTIVE) {
                    // current token is already active; renew if allowed
                    if (tokenPolicy.isAllowdTokenRenew(aInfo.getCUIDhexStringPlain())) {
                        return processRenewal(certsInfo, channel, aInfo, tokenRecord);
                    } else {
                        logMsg = "token is already active; can't renew because renewal is not allowed; will re-enroll if allowed";
                        CMS.debug(method + ":" + logMsg);
                    }
                    break;

                } else if (tokenRecord.getTokenStatus() == TokenStatus.TERMINATED) {
                    logMsg = "terminated token cuid="
                            + aInfo.getCUIDhexStringPlain() + " cannot be reused";
                    CMS.debug(method + ":" + logMsg);
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_CONTACT_ADMIN);

                } else if (tokenRecord.getTokenStatus() == TokenStatus.PERM_LOST) {
                    logMsg = "This token cannot be reused because it has been reported lost";
                    CMS.debug(method + ": " + logMsg);
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_UNUSABLE_TOKEN_KEYCOMPROMISE);

                } else if (tokenRecord.getTokenStatus() == TokenStatus.SUSPENDED) {

                    logMsg = "User needs to contact administrator to report lost token (it should be put on Hold).";
                    CMS.debug(method + ": " + logMsg);
                    break;

                } else if (tokenRecord.getTokenStatus() == TokenStatus.DAMAGED) {
                    logMsg = "This destroyed lost case should not be executed because the token is so damaged. It should not get here";
                    CMS.debug(method + ": "
                            + logMsg);
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_TOKEN_DISABLED);

                } else {
                    logMsg = "No such token status for this cuid=" + aInfo.getCUIDhexStringPlain();
                    CMS.debug(method + ":" + logMsg);
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_NO_SUCH_TOKEN_STATE);
                }

            } else { //cuid != current token
                logMsg = "found token entry different from current token";
                CMS.debug(method + ":" + logMsg);
                TokenStatus st = tokenRecord.getTokenStatus();
                if (st == TokenStatus.PERM_LOST || st == TokenStatus.SUSPENDED || st == TokenStatus.DAMAGED) {
                    //lostToken keeps track of the latest token that's lost
                    //last one in the look should be the latest
                    lostToken = tokenRecord;
                    logMsg = "found a lost token: cuid = " + tokenRecord.getId();
                    CMS.debug(method + ":" + logMsg);
                }
                continue;
            }
        }

        if (isRecover == true) { // this could be set in previous iteration
            if (lostToken == null) {
                logMsg = "No lost token to be recovered; do enrollment";
                CMS.debug(method + ":" + logMsg);
                //shouldn't even get here;  But if we do, just enroll
            } else {
                String reasonStr = lostToken.getReason();
                //RevocationReason reason = RevocationReason.valueOf(reasonStr);
                logMsg = "isRecover true; reasonStr =" + reasonStr;
                CMS.debug(method + ":" + logMsg);

                if (reasonStr.equals("keyCompromise")) {
                    return processRecovery(lostToken, certsInfo, channel, aInfo);
                } else if (reasonStr.equals("onHold")) {
                    /*
                     * the inactive one becomes the temp token
                     * No recovery scheme, basically we are going to
                     * do the brand new enrollment
                     *
                     *
                     */

                    // ToDo: This section has not been tested to work.. Make sure this works.

                    configStore = CMS.getConfigStore();
                    configName = TPSEngine.OP_ENROLL_PREFIX + "." + getSelectedTokenType()
                            + ".temporaryToken.tokenType";
                    try {
                        String tmpTokenType = configStore.getString(configName);
                        setSelectedTokenType(tmpTokenType);
                    } catch (EPropertyNotFound e) {
                        logMsg = " configuration " + configName + " not found";
                        CMS.debug(method + ":" + logMsg);
                        throw new TPSException(method + ":" + logMsg);
                    } catch (EBaseException e) {
                        logMsg = " configuration " + configName + " not found";
                        CMS.debug(method + ":" + logMsg);
                        throw new TPSException(method + ":" + logMsg);
                    }
                    return processRecovery(lostToken, certsInfo, channel, aInfo);

                } else if (reasonStr.equals("destroyed")) {
                    return processRecovery(lostToken, certsInfo, channel, aInfo);
                } else {
                    logMsg = "No such lost reason: " + reasonStr + " for this cuid: " + aInfo.getCUIDhexStringPlain();
                    CMS.debug(method + ":" + logMsg);
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_NO_SUCH_LOST_REASON);
                }
            }
        }

        CMS.debug(method + ": ends");
        return status;
    }

    /*
     * (for isExternalReg)
     * externalRegRecover
     *    reaches out to CA for retrieving cert to recover
     *    reaches out to KRA for key recovery.
     *    All the certs to have keys recovered are in
     *    session.getExternalRegAttrs().getCertsToRecover()
     *
     * when returned successfully, externalRegCertToRecover should have
     * completed externalReg recovery
     */
    private TPSStatus externalRegRecover(
            String cuid,
            String userid,
            SecureChannel channel,
            EnrolledCertsInfo certsInfo,
            AppletInfo appletInfo,
            TokenRecord tokenRecord)
            throws EBaseException, IOException {

        String method = "TPSEnrollProcessor.externalRegRecover:";
        String logMsg;
        String auditInfo;
        CMS.debug(method + "begins");
        TPSStatus status = TPSStatus.STATUS_ERROR_RECOVERY_IS_PROCESSED;
        if (session == null || session.getExternalRegAttrs() == null ||
                session.getExternalRegAttrs().getCertsToRecover() == null) {
            CMS.debug(method + "nothing to recover...");
            return status;
        }
        if (certsInfo == null) {
            CMS.debug(method + "method param certsInfo cannot be null");
            return status;
        }
        CMS.debug(method + "currentCertIndex = " + certsInfo.getCurrentCertIndex());

        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);

        ArrayList<CertEnrollInfo> preRecoveredCerts = certsInfo.getExternalRegRecoveryEnrollList();

        CMS.debug(method + "number of certs to recover=" +
                session.getExternalRegAttrs().getCertsToRecoverCount());
        ArrayList<ExternalRegCertToRecover> erCertsToRecover = session.getExternalRegAttrs().getCertsToRecover();

        for (ExternalRegCertToRecover erCert : erCertsToRecover) {
            BigInteger keyid = erCert.getKeyid();
            BigInteger serial = erCert.getSerial();
            String caConn = erCert.getCaConn();
            String kraConn = erCert.getKraConn();

            if (serial == null || caConn == null) {
                //bail out right away;  we don't do half-baked recovery
                CMS.debug(method + "invalid exterenalReg cert");
                status = TPSStatus.STATUS_ERROR_RECOVERY_FAILED;
                return status;
            }
            logMsg = "ExternalReg cert record: serial=" +
                    serial.toString();
            CMS.debug(method + logMsg);

            // recover cert
            CARemoteRequestHandler caRH = new CARemoteRequestHandler(caConn);
            CARetrieveCertResponse certResp = caRH.retrieveCertificate(serial);
            if (certResp == null) {
                logMsg = "In recovery mode, CARetieveCertResponse object not found!";
                CMS.debug(method + logMsg);
                return TPSStatus.STATUS_ERROR_RECOVERY_FAILED;
            }

            String retCertB64 = certResp.getCertB64();

            if (retCertB64 != null) {
                //CMS.debug(method + "recovered:  retCertB64: " + retCertB64);
                CMS.debug(method + "recovered retCertB64");

                //byte[] cert_bytes;
                //cert_bytes = Utils.base64decode(retCertB64);
                //TPSBuffer cert_bytes_buf = new TPSBuffer(cert_bytes);
                //CMS.debug(method + "recovered: retCertB64: "
                //        + cert_bytes_buf.toHexString());
            } else {
                logMsg = "recovering cert b64 not found";
                CMS.debug(method + logMsg);
                return TPSStatus.STATUS_ERROR_RECOVERY_FAILED;
            }

            TokenCertStatus recoveredCertStatus = getRetrievedCertStatus(certResp);
            if ((recoveredCertStatus != TokenCertStatus.ACTIVE) &&
                    !allowRecoverInvalidCert()) {
                logMsg = "invalid cert not allowed on token per policy; serial=" + serial.toString() + "; cert status="
                        + recoveredCertStatus.toString();
                CMS.debug(method + logMsg);
                return TPSStatus.STATUS_ERROR_RECOVERY_FAILED;
            }

            certsInfo.addCertStatus(recoveredCertStatus);

            // default: externalReg.recover.byKeyID=false
            String b64cert = null;
            if (getExternalRegRecoverByKeyID() == false) {
                b64cert = certResp.getCertB64();
                //CMS.debug("TPSEnrollProcessor.processRecovery: cert blob to recover key with: " + b64cert);
            }

            /*
             * Recover either by keyID or by cert
             * When recovering by keyid:
             *   - keyid in record indicates actual recovery;
             *   - missing of which means retention;
             * When recovering by cert:
             *   - keyid field needs to be present
             *     but the value is not relevant (a "0" would be fine)
             *   - missing of keyid still means retention;
             */
            if (keyid == null) {
                logMsg = " no keyid; retention; skip key recovery; continue";
                CMS.debug(method + logMsg);
                continue;
            } else {
                logMsg = " keyid in user record: " + keyid.toString();
                CMS.debug(method + logMsg);
                if ((getExternalRegRecoverByKeyID() == false) &&
                        keyid.compareTo(BigInteger.valueOf(0)) != 0) {
                    logMsg = " Recovering by cert; keyid is irrelevant from user record";
                    CMS.debug(method + logMsg);
                }
            }

            // recover keys
            KRARecoverKeyResponse keyResp = null;
            if (kraConn != null) {
                logMsg = "kraConn not null:" + kraConn;
                CMS.debug(method + logMsg);

                if (channel.getDRMWrappedDesKey() == null) {
                    logMsg = "channel.getDRMWrappedDesKey() null";
                    CMS.debug(method + logMsg);
                    return TPSStatus.STATUS_ERROR_RECOVERY_FAILED;
                } else {
                    logMsg = "channel.getDRMWrappedDesKey() not null";
                    CMS.debug(method + logMsg);
                }

                keyResp = tps.getEngine().recoverKey(cuid,
                        userid,
                        channel.getDRMWrappedDesKey(),
                        getExternalRegRecoverByKeyID() ? null : b64cert,
                        kraConn, keyid);

                if (keyResp == null) {
                    auditInfo = "recovering key not found";
                    auditRecovery(userid, appletInfo, "failure",
                            channel.getKeyInfoData().toHexStringPlain(),
                            serial, caConn,
                            kraConn, auditInfo);
                    CMS.debug(method + auditInfo);
                    return TPSStatus.STATUS_ERROR_RECOVERY_FAILED;
                }
                auditRecovery(userid, appletInfo, "success",
                        channel.getKeyInfoData().toHexStringPlain(),
                        serial, caConn,
                        kraConn, null);
            }

            CertEnrollInfo cEnrollInfo = new CertEnrollInfo();
            cEnrollInfo.setTokenToBeRecovered(tokenRecord);
            cEnrollInfo.setRecoveredCertData(certResp);
            cEnrollInfo.setRecoveredKeyData(keyResp);
            preRecoveredCerts.add(cEnrollInfo);

        }

        // Now that we know we have the data for all the certs recovered, let's actually touch the token
        // and recover the certificates.

        if (preRecoveredCerts != null && preRecoveredCerts.size() != 0) {
            PKCS11Obj pkcs11obj = certsInfo.getPKCS11Obj();

            int numCerts = preRecoveredCerts.size();

            certsInfo.setNumCertsToEnroll(numCerts);

            for (int i = 0; i < preRecoveredCerts.size(); i++) {

                CertEnrollInfo certRecoveredInfo = preRecoveredCerts.get(i);

                if (certRecoveredInfo != null) {

                    int newCertId = pkcs11obj.getNextFreeCertIdNumber();
                    certsInfo.setCurrentCertIndex(i);

                    CMS.debug(method + "before calling generateCertificate, certsInfo.getCurrentCertIndex() ="
                            + certsInfo.getCurrentCertIndex());
                    generateCertificate(certsInfo, channel, appletInfo,
                            "encryption",
                            TPSEngine.ENROLL_MODES.MODE_RECOVERY,
                            newCertId, certRecoveredInfo);

                    CMS.debug(method + "after generateCertificate() with MODE_RECOVERY");
                }

            }
        }

        CMS.debug(method + "ends");
        return status;
    }

    /*
    * Renewal logic
    *  1. Create Optional local TPS grace period per token profile,
    *     per token type, such as signing or encryption.
    *    This grace period must match how the CA is configured. Ex:
    *    op.enroll.userKey.renewal.encryption.enable=true
    *    op.enroll.userKey.renewal.encryption.gracePeriod.enable=true
    *    op.enroll.userKey.renewal.encryption.gracePeriod.before=30
    *    op.enroll.userKey.renewal.encryption.gracePeriod.after=30
    *  2. In case of a grace period failure the code will go on
    *     and attempt to renew the next certificate in the list.
    *  3. In case of any other code failure, the code will abort
    *     and leave the token untouched, while informing the user
    *     with an error message.
    *
    */
    private TPSStatus processRenewal(EnrolledCertsInfo certsInfo, SecureChannel channel, AppletInfo aInfo,
            TokenRecord tokenRecord)
            throws TPSException, IOException {
        TPSStatus status = TPSStatus.STATUS_ERROR_RENEWAL_FAILED;
        String method = "TPSEnrollProcess.processRenewal";
        String logMsg;
        CMS.debug(method + ": begins");

        boolean noFailedCerts = true;

        if (certsInfo == null || aInfo == null || channel == null) {
            throw new TPSException(method + ": Bad Input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        int keyTypeNum = getNumberCertsToRenew();
        /*
         * Get certs from the tokendb for this token to find out about
         * renewal possibility
         */
        Collection<TPSCertRecord> allCerts = tps.tdb.tdbGetCertRecordsByCUID(tokenRecord.getId());

        Collection<TPSCertRecord> oldEncCertsToRecover = new ArrayList<TPSCertRecord>();

        certsInfo.setNumCertsToEnroll(keyTypeNum);

        CMS.debug(method + ": Number of certs to renew: " + keyTypeNum);

        int numActuallyRenewed = 0;

        for (int i = 0; i < keyTypeNum; i++) {
            /*
             * e.g. op.enroll.userKey.renewal.keyType.value.0=signing
             * e.g. op.enroll.userKey.renewal.keyType.value.1=encryption
             */
            String keyType = getRenewConfigKeyType(i);
            boolean renewEnabled = getRenewEnabled(keyType);
            CMS.debug(method + ": key type " + keyType);
            if (!renewEnabled) {
                CMS.debug(method + ": renew not enabled");
                continue;
            }

            CMS.debug(method + ": renew enabled");

            certsInfo.setCurrentCertIndex(i);

            CertEnrollInfo cEnrollInfo = new CertEnrollInfo();
            IConfigStore configStore = CMS.getConfigStore();

            // find all config
            String configName = null;
            boolean graceEnabled = false;
            String graceBeforeS = null;
            String graceAfterS = null;
            try {
                String keyTypePrefix = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + ".renewal." + keyType;

                //TODO: profileId is actually gotten in the CARemoteRequestHandler.
                configName = keyTypePrefix + ".ca.profileId";
                String profileId;
                profileId = configStore.getString(configName);
                CMS.debug(method + ": profileId: " + profileId);

                configName = keyTypePrefix + ".gracePeriod.enable";
                graceEnabled = configStore.getBoolean(configName, false);
                if (graceEnabled) {
                    CMS.debug(method + ": grace period check is enabled");
                    configName = keyTypePrefix + ".gracePeriod.before";
                    graceBeforeS = configStore.getString(configName, "");
                    configName = keyTypePrefix + ".gracePeriod.after";
                    graceAfterS = configStore.getString(configName, "");
                } else {
                    CMS.debug(method + ": grace period check is not enabled");
                }

                configName = keyTypePrefix + ".certId";
                String certId = configStore.getString(configName, "C0");
                CMS.debug(method + ": certId: " + certId);

                configName = keyTypePrefix + ".certAttrId";
                String certAttrId = configStore.getString(configName, "c0");
                CMS.debug(method + ": certAttrId: " + certAttrId);

                configName = keyTypePrefix + ".privateKeyAttrId";
                String priKeyAttrId = configStore.getString(configName, "k0");
                CMS.debug(method + ": privateKeyAttrId: " + priKeyAttrId);

                configName = keyTypePrefix + ".publicKeyAttrId";
                String publicKeyAttrId = configStore.getString(configName, "k1");
                CMS.debug(method + ": publicKeyAttrId: " + publicKeyAttrId);

            } catch (EBaseException e) {
                throw new TPSException(method + ": Internal error finding config value: " + configName + ":"
                        + e,
                        TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }

            // find the certs that match the keyType to renew
            for (TPSCertRecord cert : allCerts) {
                if (keyType.equals(cert.getKeyType())) {
                    try {
                        CMS.debug(method + ": cert " + cert.getId() + " with status:" + cert.getStatus());
                        if (cert.getStatus().equals("revoked") ||
                                cert.getStatus().equals("renewed")) {
                            CMS.debug(method + ": cert status is not to be renewed");
                            continue;
                        }

                        // check if within grace period to save us a trip (note: CA makes the final decision)
                        if (graceEnabled) {
                            try {
                                if (!isCertWithinRenewalGracePeriod(cert, graceBeforeS, graceAfterS))
                                    continue;
                            } catch (TPSException ge) {
                                // error in this will just log and keep going
                                CMS.debug(method + ":" + ge + "; continue to try renewal");
                            }
                        }

                        //Renew and fetch the renewed cert blob.

                        CARenewCertResponse certResponse = tps.getEngine().renewCertificate(cert,
                                cert.getSerialNumber(), selectedTokenType, keyType,
                                getCAConnectorID("renewal", keyType));
                        cEnrollInfo.setRenewedCertData(certResponse);

                        generateCertificate(certsInfo, channel, aInfo, keyType, TPSEngine.ENROLL_MODES.MODE_RENEWAL,
                                -1, cEnrollInfo);

                        numActuallyRenewed++;

                        if (keyType.equals(TPSEngine.CFG_ENCRYPTION)) {
                            CMS.debug(method
                                    + ": found old encryption cert (just renewed) to attempt to recover back to token, in order to read old emails.");
                            CMS.debug(method + " adding cert: " + cert);
                            oldEncCertsToRecover.add(cert);

                        }

                        if (numActuallyRenewed == keyTypeNum) {
                            CMS.debug(method
                                    + " We have already renewed the proper number of certs, bailing from loop.");
                            status = TPSStatus.STATUS_ERROR_RENEWAL_IS_PROCESSED;
                            break;
                        }

                        //renewCertificate(cert, certsInfo, channel, aInfo, keyType);
                        status = TPSStatus.STATUS_ERROR_RENEWAL_IS_PROCESSED;
                    } catch (TPSException e) {
                        CMS.debug(method + "renewCertificate: exception:" + e);
                        noFailedCerts = false;
                        break; //need to clean up half-done token later
                    }
                }
            }
        }

        if (!noFailedCerts) {
            // TODO: handle cleanup
            logMsg = "There has been failed cert renewal";
            CMS.debug(method + ":" + logMsg);
            throw new TPSException(logMsg + TPSStatus.STATUS_ERROR_RENEWAL_FAILED);
        }

        //Handle recovery of old encryption certs

        //See if policy calls for this feature

        TPSTokenPolicy tokenPolicy = new TPSTokenPolicy(tps);

        boolean recoverOldEncCerts = tokenPolicy.isAllowdRenewSaveOldEncCerts(tokenRecord.getId());
        CMS.debug(method + " Recover Old Encryption Certs for Renewed Certs: " + recoverOldEncCerts);
        if (oldEncCertsToRecover.size() > 0 && recoverOldEncCerts == true) {
            CMS.debug("About to attempt to recover old encryption certs just renewed.");

            Iterator<TPSCertRecord> iterator = oldEncCertsToRecover.iterator();

            // while loop
            while (iterator.hasNext()) {
                TPSCertRecord toBeRecovered = iterator.next();
                String serialToRecover = toBeRecovered.getSerialNumber();

                try {

                    CARetrieveCertResponse certResponse = tps.getEngine().recoverCertificate(toBeRecovered,
                            serialToRecover, TPSEngine.CFG_ENCRYPTION, getCAConnectorID());

                    String b64cert = certResponse.getCertB64();
                    CMS.debug("TPSEnrollProcessor.processRecovery: cert blob recovered");

                    KRARecoverKeyResponse keyResponse = tps.getEngine().recoverKey(toBeRecovered.getId(),
                            toBeRecovered.getUserID(),
                            channel.getDRMWrappedDesKey(), b64cert, getDRMConnectorID());

                    //Try to write recovered cert to token

                    CertEnrollInfo cEnrollInfo = new CertEnrollInfo();

                    cEnrollInfo.setTokenToBeRecovered(tokenRecord);
                    cEnrollInfo.setRecoveredCertData(certResponse);
                    cEnrollInfo.setRecoveredKeyData(keyResponse);

                    PKCS11Obj pkcs11obj = certsInfo.getPKCS11Obj();
                    int newCertId = pkcs11obj.getNextFreeCertIdNumber();

                    CMS.debug(method + " newCertId = " + newCertId);

                    CMS.debug(method + "before calling generateCertificate, certsInfo.getCurrentCertIndex() ="
                            + newCertId);
                    generateCertificate(certsInfo, channel, aInfo,
                            "encryption",
                            TPSEngine.ENROLL_MODES.MODE_RECOVERY,
                            newCertId, cEnrollInfo);

                    //We don't want this quasi old encryption cert in the official list.
                    // This cert is on the token ONLY to decrypt old emails after the real cert
                    // has been renewed. We want to keep the official cert list to contain only the
                    // legit certs, in order to not confuse other processes such as recovery.
                    CMS.debug(method + " About to remove old encryption cert recovered from official token db list: ");
                    certsInfo.removeCertificate(certResponse.getCert());

                } catch (TPSException e) {
                    CMS.debug(method + "Failure to recoverd old encryption certs during renewal operation.");

                }
            }
        }

        return status;
    }

    /*
     * isCertWithinRenewalGracePeriod - check if a cert is within the renewal grace period
     * @param cert the cert to be renewed
     * @param renewGraceBeforeS string representation of the # of days "before" cert expiration date
     * @param renewGraceAfterS string representation of the # of days "after" cert expiration date
     */
    private boolean isCertWithinRenewalGracePeriod(TPSCertRecord cert, String renewGraceBeforeS,
            String renewGraceAfterS)
            throws TPSException {
        String method = "TPSEnrollProcessor.isCertWithinRenewalGracePeriod";
        int renewGraceBefore = 0;
        int renewGraceAfter = 0;

        if (cert == null || renewGraceBeforeS == null || renewGraceAfterS == null) {
            CMS.debug(method + ": missing some input");
            throw new TPSException(method + ": Bad Input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        BigInteger renewGraceBeforeBI = new BigInteger(renewGraceBeforeS);
        BigInteger renewGraceAfterBI = new BigInteger(renewGraceAfterS);

        // -1 means no limit
        if (renewGraceBeforeS == "")
            renewGraceBefore = -1;
        else
            renewGraceBefore = Integer.parseInt(renewGraceBeforeS);

        if (renewGraceAfterS == "")
            renewGraceAfter = -1;
        else
            renewGraceAfter = Integer.parseInt(renewGraceAfterS);

        if (renewGraceBefore > 0)
            renewGraceBeforeBI = renewGraceBeforeBI.multiply(BigInteger.valueOf(1000 * 86400));
        if (renewGraceAfter > 0)
            renewGraceAfterBI = renewGraceAfterBI.multiply(BigInteger.valueOf(1000 * 86400));

        Date origExpDate = cert.getValidNotAfter();
        Date current = CMS.getCurrentDate();
        long millisDiff = origExpDate.getTime() - current.getTime();
        CMS.debug(method + ": millisDiff="
                + millisDiff + " origExpDate=" + origExpDate.getTime() + " current=" + current.getTime());

        /*
         * "days", if positive, has to be less than renew_grace_before
         * "days", if negative, means already past expiration date,
         *     (abs value) has to be less than renew_grace_after
         * if renew_grace_before or renew_grace_after are negative
         *    the one with negative value is ignored
         */
        if (millisDiff >= 0) {
            if ((renewGraceBefore > 0) && (millisDiff > renewGraceBeforeBI.longValue())) {
                CMS.debug(method + ": renewal attempted outside of grace period;" +
                        renewGraceBefore + " days before and " +
                        renewGraceAfter + " days after original cert expiration date");
                return false;
            }
        } else {
            if ((renewGraceAfter > 0) && ((0 - millisDiff) > renewGraceAfterBI.longValue())) {
                CMS.debug(method + ": renewal attempted outside of grace period;" +
                        renewGraceBefore + " days before and " +
                        renewGraceAfter + " days after original cert expiration date");
                return false;
            }
        }
        return true;
    }

    private boolean getRenewEnabled(String keyType) {
        String method = "TPSEnrollProcessor.getRenewEnabled";
        IConfigStore configStore = CMS.getConfigStore();
        boolean enabled = false;

        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + ".renewal."
                    + keyType + "." + "enable";
            enabled = configStore.getBoolean(
                    configValue, false);

        } catch (EBaseException e) {
            //default to false
        }

        CMS.debug(method + ": returning " + enabled);
        return enabled;
    }

    /**
     * getExternalRegRecoverByKeyID returns whether externalReg
     * recovery is recovering by keyID or not; default is by cert
     */
    private boolean getExternalRegRecoverByKeyID() {
        String method = "TPSEnrollProcessor.getExternalRegRecoverByKeyID";
        IConfigStore configStore = CMS.getConfigStore();
        boolean recoverByKeyID = false;

        try {
            String configValue = "externalReg.recover.byKeyID";
            recoverByKeyID = configStore.getBoolean(configValue, false);
        } catch (EBaseException e) {
            // should never get here anyway
            // but if it does, just take the default "false"
            CMS.debug(method + " exception, take default: " + e);
        }
        CMS.debug(method + ": returning " + recoverByKeyID);
        return recoverByKeyID;
    }

    private String getRenewConfigKeyType(int keyTypeIndex) throws TPSException {
        String method = "TPSEnrollProcessor.getRenewConfigKeyType";
        IConfigStore configStore = CMS.getConfigStore();
        String keyType = null;

        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "."
                    + TPSEngine.CFG_RENEW_KEYTYPE_VALUE + "." + keyTypeIndex;
            keyType = configStore.getString(
                    configValue, null);

        } catch (EBaseException e) {
            throw new TPSException(
                    method + ": Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        //We would really like one of these to exist
        if (keyType == null) {
            throw new TPSException(
                    method + ": Internal error finding config value: ",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug(method + ": returning: " + keyType);

        return keyType;

    }

    private int getNumberCertsToRenew() throws TPSException {
        String method = "TPSEnrollProcessor.getNumberCertsToRenew";

        IConfigStore configStore = CMS.getConfigStore();
        int keyTypeNum = 0;
        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "."
                    + TPSEngine.CFG_RENEW_KEYTYPE_NUM;
            keyTypeNum = configStore.getInteger(
                    configValue, 0);

        } catch (EBaseException e) {
            throw new TPSException(method + ": Internal error finding config value: "
                    + e,
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }

        if (keyTypeNum == 0) {
            throw new TPSException(
                    method + ": invalid number of certificates to renew configured!",
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }
        CMS.debug(method + ": returning: " + keyTypeNum);

        return keyTypeNum;
    }

    private TPSStatus processRecovery(TokenRecord toBeRecovered, EnrolledCertsInfo certsInfo, SecureChannel channel,
            AppletInfo aInfo) throws TPSException, IOException {
        String method = "TPSEnrollProcessor.processRecover";
        String logMsg;
        TPSStatus status = TPSStatus.STATUS_ERROR_RECOVERY_IS_PROCESSED;

        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        IConfigStore configStore = CMS.getConfigStore();

        CMS.debug("TPSEnrollProcessor.processRecovery: entering:");

        if (toBeRecovered == null || certsInfo == null || channel == null || aInfo == null) {
            throw new TPSException("TPSEnrollProcessor.processRecovery: Invalid reason!",
                    TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
        }

        String reason = toBeRecovered.getReason();

        int num = getNumberCertsForRecovery(reason);

        int totalNumCerts = 0;

        //We will have to rifle through the configuration to see if there any recovery operations with
        //scheme "GenerateNewKeyandRecoverLast" which allows for recovering the old key AND generating a new
        // one for the encryption type only. If this scheme is present, the number of certs for bump by
        // 1 for each occurrence.

        String keyTypeValue = null;
        String scheme = null;
        CMS.debug(
                "TPSEnrollProcessor.processRecovery: About to find if we have any GenerateNewAndRecoverLast schemes.");
        for (int i = 0; i < num; i++) {
            keyTypeValue = getRecoveryKeyTypeValue(reason, i);
            scheme = getRecoveryScheme(reason, keyTypeValue);

            if (scheme.equals(TPSEngine.RECOVERY_SCHEME_GENERATE_NEW_KEY_AND_RECOVER_LAST)) {

                //Make sure we are not signing:
                if (keyTypeValue.equals(TPSEngine.CFG_SIGNING)) {
                    throw new TPSException(
                            "TPSEnrollProcessor.processRecovery: Can't have GenerateNewAndRecoverLast scheme with a signing key!",
                            TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
                }
                totalNumCerts++;
            }
            totalNumCerts++;
        }

        CMS.debug("TPSEnrollProcessor.processRecovery: About to perform actual recoveries: totalNumCerts: "
                + totalNumCerts);

        if (!(totalNumCerts > num)) {
            totalNumCerts = num;
        }

        boolean isGenerateAndRecover = false;
        int actualCertIndex = 0;
        boolean legalScheme = false;

        //Go through again and do the recoveries/enrollments

        certsInfo.setNumCertsToEnroll(totalNumCerts);
        for (int i = 0; i < num; i++) {

            keyTypeValue = getRecoveryKeyTypeValue(reason, i);
            scheme = getRecoveryScheme(reason, keyTypeValue);

            if (scheme.equals(TPSEngine.RECOVERY_SCHEME_GENERATE_NEW_KEY_AND_RECOVER_LAST)) {
                CMS.debug("TPSEnrollProcessor.processRecovery: scheme GenerateNewKeyAndRecoverLast found.");
                isGenerateAndRecover = true;

            } else {
                isGenerateAndRecover = false;
            }

            if (scheme.equals(TPSEngine.RECOVERY_GENERATE_NEW_KEY) || isGenerateAndRecover) {
                legalScheme = true;
                CertEnrollInfo cEnrollInfo = new CertEnrollInfo();
                generateCertificate(certsInfo, channel, aInfo, keyTypeValue, TPSEngine.ENROLL_MODES.MODE_ENROLL,
                        actualCertIndex, cEnrollInfo);

                actualCertIndex = cEnrollInfo.getCertIdIndex();
                CMS.debug(
                        "TPSEnrollProcessor.processRecovery: scheme GenerateNewKey found, or isGenerateAndRecove is true: actualCertIndex, after enrollment: "
                                + actualCertIndex);

            }

            if (scheme.equals(TPSEngine.RECOVERY_RECOVER_LAST) || isGenerateAndRecover) {
                legalScheme = true;
                CMS.debug(
                        "TPSEnrollProcessor.processRecovery: scheme RecoverLast found, or isGenerateAndRecove is true");
                if (isGenerateAndRecover) {
                    CMS.debug("TPSEnrollProcessor.processRecovery: isGenerateAndRecover is true.");
                    actualCertIndex++;
                }

                Collection<TPSCertRecord> certs = tps.tdb.tdbGetCertRecordsByCUID(toBeRecovered.getId());

                String serialToRecover = null;
                TPSCertRecord certToRecover = null;
                for (TPSCertRecord rec : certs) {

                    //Just take the end of the list most recent cert of given type.
                    CMS.debug("TPSEnrollProcessor.processRecovery: Looking for keyType record: " + keyTypeValue
                            + " curSererial: " + rec.getSerialNumber());

                    if (rec.getKeyType().equals(keyTypeValue)) {
                        serialToRecover = rec.getSerialNumber();
                        certToRecover = rec;
                        CMS.debug("TPSCertRecord: serial number: " + serialToRecover);
                    }

                }
                String b64cert = null;
                if (serialToRecover != null) {
                    // get recovery conn id
                    String caConnId;
                    String config = "op.enroll." + certToRecover.getType() + ".keyGen." + certToRecover.getKeyType()
                            + ".ca.conn";
                    try {
                        caConnId = configStore.getString(config);
                    } catch (Exception e) {
                        logMsg = "cannot find config:" + config;
                        CMS.debug(method + ":" + logMsg);
                        throw new TPSException(
                                method + ":" + logMsg,
                                TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
                    }
                    CMS.debug("TPSEnrollProcessor.processRecovery: Selecting cert to recover: " + serialToRecover);

                    CARetrieveCertResponse certResponse = tps.getEngine().recoverCertificate(certToRecover,
                            serialToRecover, keyTypeValue, caConnId);

                    b64cert = certResponse.getCertB64();
                    //CMS.debug("TPSEnrollProcessor.processRecovery: recoverd cert blob: " + b64cert);
                    CMS.debug("TPSEnrollProcessor.processRecovery: cert blob recovered");

                    KRARecoverKeyResponse keyResponse = tps.getEngine().recoverKey(toBeRecovered.getId(),
                            toBeRecovered.getUserID(),
                            channel.getDRMWrappedDesKey(), b64cert, getDRMConnectorID());

                    CertEnrollInfo cEnrollInfo = new CertEnrollInfo();

                    cEnrollInfo.setTokenToBeRecovered(toBeRecovered);
                    cEnrollInfo.setRecoveredCertData(certResponse);
                    cEnrollInfo.setRecoveredKeyData(keyResponse);

                    generateCertificate(certsInfo, channel, aInfo, keyTypeValue, TPSEngine.ENROLL_MODES.MODE_RECOVERY,
                            actualCertIndex, cEnrollInfo);

                    // unrevoke cert if needed
                    if (certToRecover.getStatus().equalsIgnoreCase(TokenCertStatus.ONHOLD.toString())) {
                        logMsg = "unrevoking cert...";
                        CMS.debug(method + ":" + logMsg);

                        CARemoteRequestHandler caRH = null;
                        try {
                            caRH = new CARemoteRequestHandler(caConnId);

                            CARevokeCertResponse response = caRH.revokeCertificate(false /*unrevoke*/,
                                    serialToRecover,
                                    certToRecover.getCertificate(),
                                    null);
                            CMS.debug(method + ": response status =" + response.getStatus());
                            auditRevoke(certToRecover.getTokenID(), false /*off-hold*/, -1 /*na*/,
                                    String.valueOf(response.getStatus()), serialToRecover, caConnId, null);
                            // successful unrevoke should mark the cert "active"
                            CMS.debug(
                                    method + ": unrevoke successful. Setting cert status to active for actualCertIndex:"
                                            + actualCertIndex);
                            certsInfo.setCertStatus(actualCertIndex, TokenCertStatus.ACTIVE);
                        } catch (EBaseException e) {
                            logMsg = "failed getting CARemoteRequestHandler";
                            CMS.debug(method + ":" + logMsg);
                            auditRevoke(certToRecover.getTokenID(), false/*off-hold*/, -1 /*na*/, "failure",
                                    serialToRecover, caConnId, logMsg);
                            throw new TPSException(method + ":" + logMsg, TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
                        }
                    }
                } else {

                }

            }

            if (!legalScheme) {
                throw new TPSException("TPSEnrollProcessor.processRecovery: Invalid recovery configuration!",
                        TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
            }
            actualCertIndex++;

        }

        return status;
    }

    //Stub to generate a certificate, more to come
    private boolean generateCertificates(EnrolledCertsInfo certsInfo, SecureChannel channel, AppletInfo aInfo)
            throws TPSException, IOException {

        CMS.debug("TPSEnrollProcess.generateCertificates: begins ");
        boolean noFailedCerts = true;

        if (certsInfo == null || aInfo == null || channel == null) {
            throw new TPSException("TPSEnrollProcessor.generateCertificates: Bad Input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        int keyTypeNum = getNumberCertsToEnroll();

        if (isExternalReg && keyTypeNum == 0) {
            CMS.debug("TPSEnrollProcess.generateCertificates: isExternalReg with tokenType:" + selectedTokenType
                    + "; no certs to enroll per configuration");
            return noFailedCerts;
        }

        certsInfo.setNumCertsToEnroll(keyTypeNum);

        CMS.debug("TPSEnrollProcessor.generateCertificates: Number of certs to enroll: " + keyTypeNum);

        for (int i = 0; i < keyTypeNum; i++) {
            String keyType = getConfiguredKeyType(i);
            certsInfo.setCurrentCertIndex(i);
            try {
                generateCertificate(certsInfo, channel, aInfo, keyType, TPSEngine.ENROLL_MODES.MODE_ENROLL, -1, null);
            } catch (TPSException e) {
                CMS.debug("TPSEnrollProcessor.generateCertificate: exception:" + e);
                noFailedCerts = false;
                break; //need to clean up half-done token later
            }
        }

        /*
         * In this special case of RE_ENROLL, Revoke current certs for this token
         * if so configured
         */
        /*TODO: format that follows should do this already based on the returned noFailedCerts value
        if (noFailedCerts == true) {
            revokeCertificates(aInfo.getCUIDhexStringPlain());
        }
        */

        CMS.debug("TPSEnrollProcessor.generateCertificates: ends ");
        return noFailedCerts;
    }

    private String buildTokenLabel(EnrolledCertsInfo certsInfo, AppletInfo ainfo) throws TPSException {
        String label = null;

        if (certsInfo == null || ainfo == null) {
            throw new TPSException("TPSEnrollProcessor.buildTokenLabel: invalide input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSEnrollProcessor.buildTokenLabel: entering...");

        IConfigStore configStore = CMS.getConfigStore();

        String configName = TPSEngine.OP_ENROLL_PREFIX + "." + getSelectedTokenType() + ".keyGen.tokenName";
        String pattern = null;

        try {
            pattern = configStore.getString(configName, "$cuid$");
        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.buildTokenLabel: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

        CMS.debug("TPSEnrollProcessor.buildTokenLabel: pattern: " + pattern);

        Map<String, String> nv = new LinkedHashMap<String, String>();

        nv.put("cuid", ainfo.getCUIDhexString());
        nv.put("msn", ainfo.getMSNString());
        nv.put("userid", userid);
        nv.put("auth.cn", userid);
        nv.put("profileId", getSelectedTokenType());

        label = mapPattern((LinkedHashMap<String, String>) nv, pattern);

        CMS.debug("TPSEnrollProcessor.buildTokenLabel: returning: " + label);

        return label;

    }

    /* This routine will be able to handle:
     * regular enrollment
     * recovery enrollment
     * renewal enrollment
     */
    private void generateCertificate(EnrolledCertsInfo certsInfo, SecureChannel channel, AppletInfo aInfo,
            String keyType, TPSEngine.ENROLL_MODES mode, int certIdNumOverride, CertEnrollInfo cEnrollInfo)
            throws TPSException, IOException {

        CMS.debug("TPSEnrollProcessor.generateCertificate: entering ... certIdNumOverride: " + certIdNumOverride
                + " mode: " + mode);

        if (certsInfo == null || aInfo == null || channel == null) {
            throw new TPSException("TPSEnrollProcessor.generateCertificate: Bad Input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        //get the params needed all at once

        IConfigStore configStore = CMS.getConfigStore();

        boolean isRenewal = false;

        // This operation modifier allows us to get config entries for either
        // regular enrollment and renewal. Allows the re-use of repetitive config processing code below.
        String operationModifier = "keyGen";
        if (mode == ENROLL_MODES.MODE_RENEWAL) {
            isRenewal = true;
            operationModifier = "renewal";
        }

        if (cEnrollInfo == null)
            cEnrollInfo = new CertEnrollInfo();

        try {

            String keyTypePrefix = TPSEngine.OP_ENROLL_PREFIX + "." + getSelectedTokenType() + "." + operationModifier
                    + "." + keyType;
            CMS.debug("TPSEnrollProcessor.generateCertificate: keyTypePrefix: " + keyTypePrefix);

            String configName = keyTypePrefix + ".ca.profileId";
            String profileId = null;
            if (isExternalReg) {
                profileId = configStore.getString(configName, "NA"); // if not supplied then does not apply due to recovery
            } else {
                profileId = configStore.getString(configName);
                CMS.debug("TPSEnrollProcessor.generateCertificate: profileId: " + profileId);
            }

            configName = keyTypePrefix + ".certId";
            String certId = configStore.getString(configName, "C0");
            CMS.debug("TPSEnrollProcessor.generateCertificate: certId: " + certId);

            configName = keyTypePrefix + ".certAttrId";
            String certAttrId = configStore.getString(configName, "c0");
            CMS.debug("TPSEnrollProcessor.generateCertificate: certAttrId: " + certAttrId);

            configName = keyTypePrefix + ".privateKeyAttrId";
            String priKeyAttrId = configStore.getString(configName, "k0");
            CMS.debug("TPSEnrollProcessor.generateCertificate: priKeyAttrId: " + priKeyAttrId);

            configName = keyTypePrefix + ".publicKeyAttrId";
            String publicKeyAttrId = configStore.getString(configName, "k1");
            CMS.debug("TPSEnrollProcessor.generateCertificate: publicKeyAttrId: " + publicKeyAttrId);

            configName = keyTypePrefix + ".keySize";
            int keySize = configStore.getInteger(configName, 1024);
            CMS.debug("TPSEnrollProcessor.generateCertificate: keySize: " + keySize);

            //Default RSA_CRT=2
            configName = keyTypePrefix + ".alg";
            int algorithm = configStore.getInteger(configName, 2);
            CMS.debug("TPSEnrollProcessor.generateCertificate: algorithm: " + algorithm);

            configName = keyTypePrefix + ".publisherId";
            String publisherId = configStore.getString(configName, "");
            CMS.debug("TPSEnrollProcessor.generateCertificate: publisherId: " + publisherId);

            configName = keyTypePrefix + ".keyUsage";
            int keyUsage = configStore.getInteger(configName, 0);
            CMS.debug("TPSEnrollProcessor.generateCertificate: keyUsage: " + keyUsage);

            configName = keyTypePrefix + ".keyUser";
            int keyUser = configStore.getInteger(configName, 0);
            CMS.debug("TPSEnrollProcessor.generateCertificate: keyUser: " + keyUser);

            configName = keyTypePrefix + ".privateKeyNumber";
            int priKeyNumber = configStore.getInteger(configName, 0);
            CMS.debug("TPSEnrollProcessor.generateCertificate: privateKeyNumber: " + priKeyNumber);

            configName = keyTypePrefix + ".publicKeyNumber";
            int pubKeyNumber = configStore.getInteger(configName, 0);
            CMS.debug("TPSEnrollProcessor.generateCertificate: pubKeyNumber: " + pubKeyNumber);

            // get key capabilites to determine if the key type is SIGNING,
            // ENCRYPTION, or SIGNING_AND_ENCRYPTION

            configName = keyTypePrefix + ".private.keyCapabilities.sign";
            boolean isSigning = configStore.getBoolean(configName, false);
            CMS.debug("TPSEnrollProcessor.generateCertificate: isSigning: " + isSigning);

            configName = keyTypePrefix + ".public.keyCapabilities.encrypt";
            CMS.debug("TPSEnrollProcessor.generateCertificate: encrypt config name: " + configName);
            boolean isEncrypt = configStore.getBoolean(configName, true);
            CMS.debug("TPSEnrollProcessor.generateCertificate: isEncrypt: " + isEncrypt);

            TokenKeyType keyTypeEnum;

            if (isSigning && isEncrypt) {
                keyTypeEnum = TokenKeyType.KEY_TYPE_SIGNING_AND_ENCRYPTION;
            } else if (isSigning) {
                keyTypeEnum = TokenKeyType.KEY_TYPE_SIGNING;
            } else if (isEncrypt) {
                keyTypeEnum = TokenKeyType.KEY_TYPE_ENCRYPTION;
            } else {
                CMS.debug("TPSEnrollProcessor.generateCertificate: Illegal toke key type!");
                throw new TPSException("TPSEnrollProcessor.generateCertificate: Illegal toke key type!",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

            CMS.debug("TPSEnrollProcessor.generateCertificate: keyTypeEnum value: " + keyTypeEnum);

            // The certIdNumOverride allows us to place the certs and keys into a different slot.
            // Thus overriding what is found in the config.
            // Used in recovery mostly up to this point.

            if (certIdNumOverride >= 0) {
                CMS.debug("TPSEnrollProcessor.generateCertificate: called with overridden cert id number: "
                        + certIdNumOverride);

                pubKeyNumber = 2 * certIdNumOverride + 1;
                priKeyNumber = 2 * certIdNumOverride;

                certId = "C" + certIdNumOverride;
                certAttrId = "c" + certIdNumOverride;
                priKeyAttrId = "k" + priKeyNumber;
                publicKeyAttrId = "k" + pubKeyNumber;

                CMS.debug("TPSEnrollProcessor.generateCertificate: called with overridden cert no: certId: " + certId
                        + " certAttrId: " + certAttrId + " priKeyAttrId: " + priKeyAttrId + " publicKeyAttrId: "
                        + publicKeyAttrId);

            }

            cEnrollInfo.setKeyTypeEnum(keyTypeEnum);
            cEnrollInfo.setProfileId(profileId);
            cEnrollInfo.setCertId(certId);
            cEnrollInfo.setCertAttrId(certAttrId);
            cEnrollInfo.setKeyType(keyType);

            // These setting are key related and have no meaning in renewal.
            if (isRenewal == false) {
                cEnrollInfo.setPrivateKeyAttrId(priKeyAttrId);
                cEnrollInfo.setPublicKeyAttrId(publicKeyAttrId);
                cEnrollInfo.setKeySize(keySize);
                cEnrollInfo.setAlgorithm(algorithm);
                cEnrollInfo.setPublisherId(publisherId);
                cEnrollInfo.setKeyUsage(keyUsage);
                cEnrollInfo.setKeyUser(keyUser);
                cEnrollInfo.setPrivateKeyNumber(priKeyNumber);
                cEnrollInfo.setPublicKeyNumber(pubKeyNumber);
                cEnrollInfo.setKeyTypePrefix(keyTypePrefix);
            }

            int certsStartProgress = certsInfo.getStartProgressValue();
            int certsEndProgress = certsInfo.getEndProgressValue();
            int currentCertIndex = certsInfo.getCurrentCertIndex();
            int totalNumCerts = certsInfo.getNumCertsToEnroll();

            CMS.debug("TPSEnrollProcessor.generateCertificate: Progress values: certsStartProgress: "
                    + certsStartProgress + " certsEndProgress: " + certsEndProgress +
                    " currentCertIndex: " + currentCertIndex + " totalNumCerts: " + totalNumCerts);

            int progressBlock = 0;
            if (totalNumCerts != 0) {
                progressBlock = (certsEndProgress - certsStartProgress) / totalNumCerts;

                CMS.debug("TPSEnrollProcessor.generateCertificate: progressBlock: " + progressBlock);
            } else {//TODO need to make this more accurate
                CMS.debug("TPSEnrollProcessor.generateCertificate: totalNumCerts =0, progressBlock left at 0");
            }

            int startCertProgValue = certsStartProgress + currentCertIndex * progressBlock;

            int endCertProgValue = startCertProgValue + progressBlock;

            CMS.debug("TPSEnrollProcessor.generateCertificate: startCertProgValue: " + startCertProgValue
                    + " endCertProgValue: " + endCertProgValue);

            cEnrollInfo.setStartProgressValue(startCertProgValue);
            cEnrollInfo.setEndProgressValue(endCertProgValue);

        } catch (EBaseException e) {

            throw new TPSException(
                    "TPSEnrollProcessor.generateCertificate: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        enrollOneCertificate(certsInfo, cEnrollInfo, aInfo, channel, mode);

    }

    /* Core method handles the following modes:
     * Regular enrollment
     * Recovery enrollment
     * Renewal enrollment
     */
    private void enrollOneCertificate(EnrolledCertsInfo certsInfo, CertEnrollInfo cEnrollInfo, AppletInfo aInfo,
            SecureChannel channel, TPSEngine.ENROLL_MODES mode)
            throws TPSException, IOException {

        String auditInfo = null;
        CMS.debug("TPSEnrollProcessor.enrollOneCertificate: entering ... mode: " + mode);

        if (certsInfo == null || aInfo == null || cEnrollInfo == null || channel == null) {
            throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: Bad Input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        CMS.debug("TPSEnrollProcessor.enrollOneCertificate: currentCertIndex = " + certsInfo.getCurrentCertIndex());

        statusUpdate(cEnrollInfo.getStartProgressValue(), "PROGRESS_KEY_GENERATION");
        boolean serverSideKeyGen = checkForServerSideKeyGen(cEnrollInfo);
        boolean objectOverwrite = checkForObjectOverwrite(cEnrollInfo);

        PKCS11Obj pkcs11obj = certsInfo.getPKCS11Obj();

        int keyAlg = cEnrollInfo.getAlgorithm();

        boolean isECC = getTPSEngine().isAlgorithmECC(keyAlg);

        if (objectOverwrite) {
            CMS.debug("TPSEnrollProcessor.enrollOneCertificate: We are configured to overwrite existing cert objects.");

        } else {

            boolean certIdExists = pkcs11obj.doesCertIdExist(cEnrollInfo.getCertId());

            //Bomb out if cert exists, we ca't overwrite

            if (certIdExists) {
                auditInfo = "cert id exists on token; Overwrite of certificates not allowed";
                auditEnrollment(userid, "enrollment", aInfo, "failure", channel.getKeyInfoData().toHexStringPlain(),
                        null, null /*caConnID*/, auditInfo);
                throw new TPSException(
                        "TPSEnrollProcessor.enrollOneCertificate: " + auditInfo,
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

        }

        TPSBuffer public_key_blob = null;
        KRAServerSideKeyGenResponse ssKeyGenResponse = null;
        KRARecoverKeyResponse keyResp = null;
        RSAPublicKey parsedPubKey = null;
        PK11PubKey parsedPK11PubKey = null;
        byte[] parsedPubKey_ba = null;

        boolean isRecovery = false;
        boolean isRenewal = false;

        if (mode == ENROLL_MODES.MODE_RECOVERY) {
            isRecovery = true;

            CMS.debug("TPSEnrollProcessor.enrollOneCertificate: detecting recovery mode!");
            if (isRecovery && !serverSideKeyGen) {
                auditInfo = "Attempting illegal recovery when archival is not enabled";
                auditRecovery(userid, aInfo, "failure",
                        channel.getKeyInfoData().toHexStringPlain(),
                        null, null,
                        null, auditInfo);
                throw new TPSException(
                        "TPSEnrollProcessor.enrollOneCertificate: " + auditInfo,
                        TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
            }
        }

        if (mode == ENROLL_MODES.MODE_RENEWAL) {
            isRenewal = true;
            CMS.debug("TPSEnrollProcessor.enrollOneCertificate: detecting renewal mode!");
        }

        if (serverSideKeyGen || isRecovery) {
            //Handle server side keyGen/recovery
            // The main difference is where the key and cert data is obtained.
            // In recovery the cert and key are recovered.
            // In server side key gen, cert is enrolled and key is generated and recovered.

            CMS.debug(
                    "TPSEnrollProcessor.enrollOneCertificate: either generate private key on the server, or preform recovery or perform renewal.");
            boolean archive = checkForServerKeyArchival(cEnrollInfo);
            String kraConnId = getDRMConnectorID();

            String publicKeyStr = null;
            //Do this for JUST server side keygen
            if (isRecovery == false) {
                ssKeyGenResponse = getTPSEngine()
                        .serverSideKeyGen(cEnrollInfo.getKeySize(),
                                aInfo.getCUIDhexStringPlain(), userid, kraConnId, channel.getDRMWrappedDesKey(),
                                archive, isECC);

                publicKeyStr = ssKeyGenResponse.getPublicKey();
                //CMS.debug("TPSEnrollProcessor.enrollOneCertificate: public key string from server: " + publicKeyStr);
                CMS.debug("TPSEnrollProcessor.enrollOneCertificate: got public key string from server ");
                public_key_blob = new TPSBuffer(Utils.base64decode(publicKeyStr));

            } else {
                //Here we have a recovery, get the key data from the CertInfo object

                CMS.debug("TPSEnrollProcessor.enrollOneCertificate: Attempt to get key data in recovery mode!");
                keyResp = cEnrollInfo.getRecoveredKeyData();

                publicKeyStr = keyResp.getPublicKey();
                public_key_blob = new TPSBuffer(Utils.base64decode(publicKeyStr));
            }

            try {
                parsedPK11PubKey = PK11RSAPublicKey.fromSPKI(public_key_blob.toBytesArray());
                parsedPubKey_ba = parsedPK11PubKey.getEncoded();

                if (isRecovery == true) {
                    // reset to accurate keysize
                    RSAPublicKey rsaKey = new RSAPublicKey(parsedPubKey_ba);
                    cEnrollInfo.setKeySize(rsaKey.getKeySize());
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate: recovery reset keysize to:"
                            + rsaKey.getKeySize());
                }
            } catch (InvalidKeyFormatException e) {
                auditInfo = "TPSEnrollProcessor.enrollOneCertificate, can't create public key object from server side key generated public key blob! "
                        + e.toString();
                if (!isRecovery) { //servrSideKeygen
                    auditEnrollment(userid, "enrollment", aInfo, "failure",
                            channel.getKeyInfoData().toHexStringPlain(),
                            BigInteger.ZERO, null /*caConnID*/, auditInfo);
                } else {
                    auditRecovery(userid, aInfo, "failure",
                            channel.getKeyInfoData().toHexStringPlain(),
                            null /*serial*/, null /*caConn*/,
                            kraConnId, auditInfo);
                }
                CMS.debug(auditInfo);
                throw new TPSException(auditInfo,
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            } catch (InvalidKeyException e) {
                String msg = "TPSEnrollProcessor.enrollOneCertificate, can't create public key object from server side key generated public key blob! "
                        + e.toString();
                CMS.debug(msg);
                throw new TPSException(msg,
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

        } else if (isRenewal) {

            CMS.debug(
                    "TPSEnrollProcessor: We are in renewal mode, no work to do with the keys, in renewal the keys remain on the token.");

        } else {
            //Handle token side keyGen
            CMS.debug("TPSEnrollProcessor.enrollOneCertificate: about to generate the private key on the token.");

            int algorithm = 0x80;

            if (certsInfo.getKeyCheck() != null) {
                algorithm = 0x81;
            }

            if (isECC) {
                algorithm = keyAlg;
            }

            int pe1 = (cEnrollInfo.getKeyUser() << 4) + cEnrollInfo.getPrivateKeyNumber();
            int pe2 = (cEnrollInfo.getKeyUsage() << 4) + cEnrollInfo.getPublicKeyNumber();

            int size = channel.startEnrollment(pe1, pe2, certsInfo.getWrappedChallenge(), certsInfo.getKeyCheck(),
                    algorithm, cEnrollInfo.getKeySize(), 0x0);

            byte[] iobytes = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
            TPSBuffer iobuf = new TPSBuffer(iobytes);

            public_key_blob = channel.readObject(iobuf, 0, size);

            parsedPubKey = parsePublicKeyBlob(public_key_blob, isECC);

            parsedPubKey_ba = parsedPubKey.getEncoded();
        }

        // enrollment/recovery begins
        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: enrollment begins");
        X509CertImpl x509Cert = null;
        TokenCertStatus certStatus = TokenCertStatus.ACTIVE; // track cert status
        byte[] cert_bytes = null;
        try {

            if (isRecovery == false && isRenewal == false) {
                String caConnID = getCAConnectorID("keyGen", cEnrollInfo.getKeyType());
                CARemoteRequestHandler caRH = new CARemoteRequestHandler(caConnID);
                TPSBuffer encodedParsedPubKey = new TPSBuffer(parsedPubKey_ba);

                CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: userid =" + userid + ", cuid="
                        + aInfo.getCUIDhexString());

                CAEnrollCertResponse caEnrollResp;
                if (session.getExternalRegAttrs() != null &&
                        session.getExternalRegAttrs().getIsDelegation()) {
                    int sanNum = 0;
                    String urlSanExt = null;
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: isDelegation true");
                    /*
                     * build up name/value pairs for pattern mapping
                     */
                    LinkedHashMap<String, String> nv = new LinkedHashMap<String, String>();

                    nv.put("cuid", aInfo.getCUIDhexStringPlain());
                    nv.put("msn", aInfo.getMSNString());
                    nv.put("userid", userid);
                    nv.put("auth.cn", userid);
                    nv.put("profileId", getSelectedTokenType());

                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: fill in nv with authToken name/value pairs");
                    Enumeration<String> n = authToken.getElements();
                    while (n.hasMoreElements()) {
                        String name = n.nextElement();
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate::name =" + name);
                        if (ldapStringAttrs != null && ldapStringAttrs.contains(name)) {
                            String[] vals = authToken.getInStringArray(name);
                            if (vals != null) {
                                CMS.debug("TPSEnrollProcessor.enrollOneCertificate::val =" + vals[0]);
                                nv.put("auth." + name, vals[0]);
                            } else {
                                CMS.debug("TPSEnrollProcessor.enrollOneCertificate::name not found in authToken:"
                                        + name);
                            }
                        }
                    }

                    String subjectdn = "";
                    /*
                     * isDelegate: process subjectdn
                     * e.g.
                     *     op.enroll.delegateISEtoken.keyGen.encryption.dnpattern=
                     *         cn=$auth.firstname$.$auth.lastname$.$auth.edipi$,e=$auth.mail$,o=TMS Org
                     *     becomes:
                     *       CN=Jane.Doe.0123456789,E=jdoe@redhat.com,O=TMS Org
                     */
                    IConfigStore configStore = CMS.getConfigStore();
                    String configName;
                    configName = TPSEngine.OP_ENROLL_PREFIX + "." +
                            getSelectedTokenType() + ".keyGen." +
                            cEnrollInfo.getKeyType() + ".dnpattern";
                    try {
                        String dnpattern = configStore.getString(configName);
                        subjectdn = mapPattern(nv, dnpattern);
                    } catch (EBaseException e) {
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate: isDelegation dnpattern not set");
                    }

                    /*
                     * isDelegate: process SAN_ext
                     * e.g.
                     *     op.enroll.delegateISEtoken.keyGen.encryption.SANpattern=
                     *         $auth.edipi$.abc@redhat.com
                     *     becomes:
                     *       0123456789.abc@redhat.com
                     */
                    configName = TPSEngine.OP_ENROLL_PREFIX + "." +
                            getSelectedTokenType() + ".keyGen." +
                            cEnrollInfo.getKeyType() + ".SANpattern";
                    try {
                        String sanPattern = configStore.getString(configName);
                        String[] sanToks = sanPattern.split(",");
                        for (String sanToken : sanToks) {
                            /*
                             * for every "tok" in pattern,
                             * 1. mapPattern
                             * 2. uriEncode
                             * 3. append
                             * url_san_ext will look like san1&san2&san3...&
                             */
                            CMS.debug("TPSEnrollProcessor.enrollOneCertificate: isDelegation: sanToken:" + sanToken);
                            String sanExt = mapPattern(nv, sanToken);
                            String urlSanExt1 = Util.uriEncode(sanExt);
                            if (urlSanExt == null) { // first one
                                urlSanExt = "req_san_pattern_" +
                                        sanNum + "=" + urlSanExt1;
                            } else {
                                urlSanExt = urlSanExt +
                                        "&req_san_pattern_" + sanNum +
                                        "=" + urlSanExt1;
                            }
                            CMS.debug(
                                    "TPSEnrollProcessor.enrollOneCertificate: isDelegation: urlSanExt1:" + urlSanExt1);

                            sanNum++;
                        }
                    } catch (EBaseException e) {
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate: isDelegation sanPattern not set");
                    }

                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate: isDelegation: Before calling enrolCertificate");
                    caEnrollResp = caRH.enrollCertificate(encodedParsedPubKey, userid,
                            subjectdn, sanNum, urlSanExt,
                            aInfo.getCUIDhexString(), getSelectedTokenType(),
                            cEnrollInfo.getKeyType());
                } else {
                    CMS.debug(
                            "TPSEnrollProcessor.enrollOneCertificate: not isDelegation: Before calling enrolCertificate");
                    caEnrollResp = caRH.enrollCertificate(encodedParsedPubKey, userid,
                            aInfo.getCUIDhexString(), getSelectedTokenType(),
                            cEnrollInfo.getKeyType());
                }

                String retCertB64 = caEnrollResp.getCertB64();
                if (retCertB64 != null)
                    //CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: new cert b64 =" + retCertB64);
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: new cert b64 retrieved from caEnrollResp");
                else {
                    auditInfo = "new cert b64 not found";
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: " + auditInfo);
                    auditEnrollment(userid, "enrollment", aInfo, "failure",
                            channel.getKeyInfoData().toHexStringPlain(),
                            BigInteger.ZERO, caConnID, auditInfo);
                    throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: " + auditInfo,
                            TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
                }

                cert_bytes = Utils.base64decode(retCertB64);

                //TPSBuffer cert_bytes_buf = new TPSBuffer(cert_bytes);
                //CMS.debug("TPSEnrollProcessor.enrollOneCertificate: retCertB64: " + cert_bytes_buf.toHexString());
                CMS.debug("TPSEnrollProcessor.enrollOneCertificate: retCertB64 base64decode done");

                x509Cert = caEnrollResp.getCert();
                if (x509Cert != null) {
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: new cert retrieved");
                } else {
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: new cert not found");
                    throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: new cert not found",
                            TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
                }

                auditEnrollment(userid, "enrollment", aInfo, "success", channel.getKeyInfoData().toHexStringPlain(),
                        x509Cert.getSerialNumber(), caConnID, null);
            } else {
                String caConnID = getCAConnectorID("keyGen", cEnrollInfo.getKeyType());

                //Import the cert data from the CertEnrollObject or from Renewal object

                CMS.debug(
                        "TPSEnrollProcessor.enrollOneCertificate: Attempt to import cert data in recovery mode or renew mode!");

                if (isRecovery) {

                    CARetrieveCertResponse certResp = cEnrollInfo.getRecoveredCertData();

                    if (certResp == null) {
                        throw new TPSException(
                                "TPSEnrollProcessor.enrollOneCertificate: In recovery mode, CARetieveCertResponse object not found!",
                                TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
                    }

                    String retCertB64 = certResp.getCertB64();

                    if (retCertB64 != null) {
                        //CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: recovering: new cert b64 =" + retCertB64);
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: recovering: new cert b64 not null");
                    } else {
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: recovering new cert b64 not found");
                        throw new TPSException(
                                "TPSEnrollProcessor.enrollOneCertificate: recovering: new cert b64 not found",
                                TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
                    }
                    //CMS.debug("TPSEnrollProcessor.enrollOneCertificate: recovering:  retCertB64: " + retCertB64);
                    CMS.debug(
                            "TPSEnrollProcessor.enrollOneCertificate: recovering:  retCertB64 retrieved from certResp");
                    cert_bytes = Utils.base64decode(retCertB64);

                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate: recovering: retCertB64 base64decode done");
                    //TPSBuffer cert_bytes_buf = new TPSBuffer(cert_bytes);
                    //CMS.debug("TPSEnrollProcessor.enrollOneCertificate: recovering: retCertB64: "
                    //        + cert_bytes_buf.toHexString());

                    x509Cert = certResp.getCert();
                    if (x509Cert != null) {
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: recovering new cert retrieved");

                        // recovered cert might have different status
                        certStatus = getRetrievedCertStatus(certResp);
                        auditEnrollment(userid, "retrieval", aInfo, "success",
                                channel.getKeyInfoData().toHexStringPlain(), x509Cert.getSerialNumber(),
                                certResp.getConnID(), null);
                    } else {
                        auditInfo = "recovering new cert not found";
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: " + auditInfo);
                        auditEnrollment(userid, "retrieval", aInfo, "failure",
                                channel.getKeyInfoData().toHexStringPlain(), null /*unavailable*/,
                                certResp.getConnID(), auditInfo);
                        throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: " + auditInfo,
                                TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
                    }

                }

                // If we are here, it has to be one or the other.

                if (isRenewal) {

                    CARenewCertResponse certResp = cEnrollInfo.getRenewedCertData();
                    if (certResp == null) {
                        auditInfo = "In renewal mode, CARemewCertResponse object not found!";
                        auditEnrollment(userid, "renewal", aInfo, "failure",
                                channel.getKeyInfoData().toHexStringPlain(), null, caConnID, auditInfo);
                        throw new TPSException(
                                "TPSEnrollProcessor.enrollOneCertificate: " + auditInfo,
                                TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
                    }

                    String retCertB64 = certResp.getRenewedCertB64();

                    if (retCertB64 != null)
                        //CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: renewing: new cert b64 =" + retCertB64);
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: renewing: new cert b64 retrieved");
                    else {
                        auditInfo = "renewing new cert b64 not found";
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: " + auditInfo);
                        auditEnrollment(userid, "renewal", aInfo, "failure",
                                channel.getKeyInfoData().toHexStringPlain(), null, certResp.getConnID(), auditInfo);
                        throw new TPSException(
                                "TPSEnrollProcessor.enrollOneCertificate: remewomg: new cert b64 not found",
                                TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
                    }

                    cert_bytes = Utils.base64decode(retCertB64);
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate: renewing: retCertB64 base64decode done");
                    //TPSBuffer cert_bytes_buf = new TPSBuffer(cert_bytes);
                    //CMS.debug("TPSEnrollProcessor.enrollOneCertificate: renewing: retCertB64: "
                    //        + cert_bytes_buf.toHexString());

                    x509Cert = certResp.getRenewedCert();

                    if (x509Cert != null) {
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: renewing new cert retrieved");
                        auditEnrollment(userid, "renewal", aInfo, "success",
                                channel.getKeyInfoData().toHexStringPlain(), x509Cert.getSerialNumber(),
                                certResp.getConnID(), null);
                    } else {
                        auditInfo = "renewing new cert not found";
                        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: " + auditInfo);
                        auditEnrollment(userid, "renewal", aInfo, "failure",
                                channel.getKeyInfoData().toHexStringPlain(), null, certResp.getConnID(), auditInfo);
                        throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: " + auditInfo,
                                TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
                    }

                }

            }

            certsInfo.addCertificate(x509Cert);
            certsInfo.addKType(cEnrollInfo.getKeyType());

            //Add origin, special handling for recovery case.
            if (isRecovery == true) {
                CMS.debug("TPSEnrollProcessor.enrollOneCertificate: about to find origiinal cert record");
                TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
                TPSCertRecord origCertRec = tps.getTokendb().tdbGetOrigCertRecord(x509Cert);
                if (origCertRec != null) {
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate: token origin found");
                    certsInfo.addTokenType(origCertRec.getType());
                    certsInfo.addOrigin(origCertRec.getOrigin());
                    certsInfo.addKType(origCertRec.getKeyType());
                } else {
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate: cert origin not found");
                    TokenRecord recordToRecover = cEnrollInfo.getTokenToBeRecovered();
                    //We need to have this token record otherwise bomb out.

                    if (recordToRecover == null) {
                        throw new TPSException(
                                "TPSEnrollProcessor.enrollOneCertificate: TokenRecord of token to be recovered not found.",
                                TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
                    }

                    certsInfo.addOrigin(recordToRecover.getId());
                    certsInfo.addTokenType(recordToRecover.getType());
                }

            } else {
                certsInfo.addOrigin(aInfo.getCUIDhexStringPlain());
                certsInfo.addTokenType(selectedTokenType);
            }

            certsInfo.addCertStatus(certStatus);

            SubjectPublicKeyInfo publicKeyInfo = null;

            String label = null;
            TPSBuffer keyid = null;
            TPSBuffer modulus = null;
            TPSBuffer exponent = null;

            if (!isRenewal) {

                try {
                    if (serverSideKeyGen) {
                        publicKeyInfo = new SubjectPublicKeyInfo(parsedPK11PubKey);
                    } else {
                        publicKeyInfo = new SubjectPublicKeyInfo(parsedPubKey);
                    }
                } catch (InvalidBERException e) {
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: cant get publicKeyInfo object.");
                    throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: can't get publcKeyInfo object.",
                            TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
                }

                //Create label ToDo: Do this the correct way later

                label = buildCertificateLabel(cEnrollInfo, aInfo);
                CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: cert label: " + label);

                keyid = new TPSBuffer(makeKeyIDFromPublicKeyInfo(publicKeyInfo.getEncoded()));

                modulus = null;
                exponent = null;

                if (serverSideKeyGen) {
                    modulus = new TPSBuffer(((PK11RSAPublicKey) parsedPK11PubKey).getModulus().toByteArray());
                    exponent = new TPSBuffer(((PK11RSAPublicKey) parsedPK11PubKey).getPublicExponent().toByteArray());

                } else {
                    modulus = new TPSBuffer(parsedPubKey.getModulus().toByteArray());
                    exponent = new TPSBuffer(parsedPubKey.getPublicExponent().toByteArray());
                }

            }

            //Write cert to the token,do this in all modes

            //   long l1, l2;
            long objid;
            PKCS11Obj pkcs11Obj = certsInfo.getPKCS11Obj();

            String certId = cEnrollInfo.getCertId();

            objid = ObjectSpec.createObjectID(certId);

            //           l1 = (certId.charAt(0) & 0xff) << 24;
            //          l2 = (certId.charAt(1) & 0xff) << 16;
            //         objid = l1 + l2;

            CMS.debug("TPSEnrollProcess.enrollOneCertificate:  cert objid long: " + objid);

            ObjectSpec certObjSpec = ObjectSpec.parseFromTokenData(objid, new TPSBuffer(cert_bytes));
            pkcs11Obj.addObjectSpec(certObjSpec);

            //Do the rest of this stuff only in enrollment or recovery case, in renewal, we need not deal with the keys

            if (isRenewal == false) {

                String certAttrId = cEnrollInfo.getCertAttrId();

                TPSBuffer certAttrsBuffer = channel.createPKCS11CertAttrsBuffer(cEnrollInfo.getKeyTypeEnum(),
                        certAttrId, label, keyid);

                objid = ObjectSpec.createObjectID(certAttrId);

                CMS.debug("TPSEnrollProcess.enrollOneCertificate:  cert attr objid long: " + objid);
                ObjectSpec certAttrObjSpec = ObjectSpec.parseFromTokenData(objid, certAttrsBuffer);
                pkcs11Obj.addObjectSpec(certAttrObjSpec);

                //Add the pri key attrs object

                String priKeyAttrId = cEnrollInfo.getPrivateKeyAttrId();

                objid = ObjectSpec.createObjectID(priKeyAttrId);

                CMS.debug("TPSEnrollProcess.enrollOneCertificate: pri key objid long: " + objid);

                TPSBuffer privKeyAttrsBuffer = channel.createPKCS11PriKeyAttrsBuffer(priKeyAttrId, label, keyid,
                        modulus, cEnrollInfo.getKeyTypePrefix());

                ObjectSpec priKeyObjSpec = ObjectSpec.parseFromTokenData(objid, privKeyAttrsBuffer);
                pkcs11obj.addObjectSpec(priKeyObjSpec);

                // Now add the public key object

                String pubKeyAttrId = cEnrollInfo.getPublicKeyAttrId();

                objid = ObjectSpec.createObjectID(pubKeyAttrId);

                CMS.debug("TPSEnrollProcess.enrollOneCertificate: pub key objid long: " + objid);

                TPSBuffer pubKeyAttrsBuffer = channel.createPKCS11PublicKeyAttrsBuffer(pubKeyAttrId, label, keyid,
                        modulus, exponent, cEnrollInfo.getKeyTypePrefix());
                ObjectSpec pubKeyObjSpec = ObjectSpec.parseFromTokenData(objid, pubKeyAttrsBuffer);
                pkcs11obj.addObjectSpec(pubKeyObjSpec);

            }
        } catch (EBaseException e) {
            CMS.debug("TPSEnrollProcessor.enrollOneCertificate::" + e);
            throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: Exception thrown: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        if (serverSideKeyGen || isRecovery) {
            //Handle injection of private key onto token
            CMS.debug("TPSEnrollProcessor.enrollOneCertificate: About to inject private key");

            if (!isRecovery) {

                // SecureChannel newChannel = setupSecureChannel();
                importPrivateKeyPKCS8(ssKeyGenResponse, cEnrollInfo, channel, isECC);

            } else {
                importPrivateKeyPKCS8(keyResp, cEnrollInfo, channel, isECC);
            }

        }

        CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: enrollment ends");

        statusUpdate(cEnrollInfo.getEndProgressValue(), "PROGRESS_ENROLL_CERT");
        CMS.debug("TPSEnrollProcessor.enrollOneCertificate ends");

    }

    /*
     * getRetrievedCertStatus
     * @returns TokenCertStatus certificate status of the cert retrieved in certResponse
     */
    TokenCertStatus getRetrievedCertStatus(CARetrieveCertResponse certResponse)
            throws TPSException {
        String method = "TPSEnrollProcessor.getRetrievedCertStatus";
        CMS.debug(method + " begins");
        if (certResponse == null) {
            throw new TPSException(
                    "TPSEnrollProcessor.getRetrievedCertStatus: invalid input data! certResponse cannot be null",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        TokenCertStatus ret = TokenCertStatus.ACTIVE;
        if (!certResponse.isCertValid()) {
            CMS.debug(method + ": cert expired");
            ret = TokenCertStatus.EXPIRED;
        }
        //This would overwrite the "EXPIRED" status,
        //but "REVOKED" would be a more serious invalid status
        if (certResponse.isCertRevoked()) {
            String revReason = certResponse.getRevocationReason();
            CMS.debug(method + ": cert revoked; reason=" + revReason);
            if (RevocationReason.fromInt(Integer.parseInt(revReason)) == RevocationReason.CERTIFICATE_HOLD)
                ret = TokenCertStatus.ONHOLD;
            else
                ret = TokenCertStatus.REVOKED;
        }
        return ret;
    }

    private void importPrivateKeyPKCS8(KRARecoverKeyResponse keyResp, CertEnrollInfo cEnrollInfo,
            SecureChannel channel,
            boolean isECC) throws TPSException, IOException {

        if (keyResp == null || cEnrollInfo == null || channel == null) {
            throw new TPSException("TPSEnrollProcessor.importPrivateKeyPKCS8: invalid input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        importPrivateKeyPKCS8(keyResp.getWrappedPrivKey(), keyResp.getIVParam(), cEnrollInfo, channel, isECC);

    }

    private void importPrivateKeyPKCS8(KRAServerSideKeyGenResponse ssKeyGenResponse, CertEnrollInfo cEnrollInfo,
            SecureChannel channel,
            boolean isECC) throws TPSException, IOException {

        if (ssKeyGenResponse == null || cEnrollInfo == null || channel == null) {
            throw new TPSException("TPSEnrollProcessor.importPrivateKeyPKCS8: invalid input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        importPrivateKeyPKCS8(ssKeyGenResponse.getWrappedPrivKey(), ssKeyGenResponse.getIVParam(), cEnrollInfo,
                channel, isECC);

    }

    private void importPrivateKeyPKCS8(String wrappedPrivKeyStr, String ivParams, CertEnrollInfo cEnrollInfo,
            SecureChannel channel,
            boolean isECC) throws TPSException, IOException {

        CMS.debug("TPSEnrollProcessor.importprivateKeyPKCS8 entering..");
        if (wrappedPrivKeyStr == null || ivParams == null || cEnrollInfo == null || channel == null) {
            throw new TPSException("TPSEnrollProcessor.importPrivateKeyPKCS8: invalid input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        byte[] objid = {
                (byte) 0xFF,
                0x00,
                (byte) 0xFF,
                (byte) 0xF3 };

        byte keytype = 0x09; //RSAPKCS8Pair

        // String wrappedPrivKeyStr = ssKeyGenResponse.getWrappedPrivKey();
        int keysize = cEnrollInfo.getKeySize();

        TPSBuffer privKeyBlob = new TPSBuffer();

        privKeyBlob.add((byte) 0x1); // encryption
        privKeyBlob.add(keytype);
        privKeyBlob.add((byte) (keysize / 256));
        privKeyBlob.add((byte) (keysize % 256));

        TPSBuffer privKeyBuff = new TPSBuffer(Util.uriDecodeFromHex(wrappedPrivKeyStr));
        privKeyBlob.add(privKeyBuff);

        //CMS.debug("TPSEnrollProcessor.importprivateKeyPKCS8 privKeyBlob: " + privKeyBlob.toHexString());

        byte[] perms = { 0x40,
                0x00,
                0x40,
                0x00,
                0x40,
                0x00 };

        TPSBuffer objIdBuff = new TPSBuffer(objid);

        channel.createObject(objIdBuff, new TPSBuffer(perms), privKeyBlob.size());

        channel.writeObject(objIdBuff, privKeyBlob);

        TPSBuffer keyCheck = channel.getKeyCheck();

        if (keyCheck == null) {
            keyCheck = new TPSBuffer();
        }

        //CMS.debug("TPSEnrollProcessor.importPrivateKeyPKCS8 : keyCheck: " + keyCheck.toHexString());
        CMS.debug("TPSEnrollProcessor.importPrivateKeyPKCS8 : got keyCheck");

        //String ivParams = ssKeyGenResponse.getIVParam();
        //CMS.debug("TPSEnrollProcessor.importPrivateKeyPKCS8: ivParams: " + ivParams);
        TPSBuffer ivParamsBuff = new TPSBuffer(Util.uriDecodeFromHex(ivParams));

        if (ivParamsBuff.size() == 0) {
            throw new TPSException("TPSEnrollProcessor.importPrivateKeyPKCS8: invalid iv vector!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

        TPSBuffer kekWrappedDesKey = channel.getKekDesKey();

        if (kekWrappedDesKey != null) {
            CMS.debug("TPSEnrollProcessor.importPrivateKeyPKCS8: keyWrappedDesKey: " + kekWrappedDesKey.toHexString());
            CMS.debug("TPSEnrollProcessor.importPrivateKeyPKCS8: got keyWrappedDesKey");
        } else
            CMS.debug("TPSEnrollProcessor.iportPrivateKeyPKC8: null kekWrappedDesKey!");

        byte alg = (byte) 0x80;
        if (kekWrappedDesKey != null && kekWrappedDesKey.size() > 0) {
            alg = (byte) 0x81;
        }

        TPSBuffer data = new TPSBuffer();

        data.add(objIdBuff);
        data.add(alg);
        data.add((byte) kekWrappedDesKey.size());
        data.add(kekWrappedDesKey);
        data.add((byte) keyCheck.size());
        if (keyCheck.size() > 0) {
            data.add(keyCheck);
        }
        data.add((byte) ivParamsBuff.size());
        data.add(ivParamsBuff);
        CMS.debug("TPSEnrollProcessor.importprivateKeyPKCS8: key data outgoing: " + data.toHexString());

        int pe1 = (cEnrollInfo.getKeyUser() << 4) + cEnrollInfo.getPrivateKeyNumber();
        int pe2 = (cEnrollInfo.getKeyUsage() << 4) + cEnrollInfo.getPublicKeyNumber();

        channel.importKeyEnc(pe1, pe2, data);

        CMS.debug("TPSEnrollProcessor.importprivateKeyPKCS8 successful, leaving...");

    }

    private String buildCertificateLabel(CertEnrollInfo cEnrollInfo, AppletInfo ainfo) throws TPSException {

        CMS.debug("TPSEnrollProcessor.buildCertificateLabel");

        if (cEnrollInfo == null) {
            throw new TPSException("TPSErollProcessor.buildCertificateLabel: Invalid input params!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        String label = null;
        String pattern = null;

        String defaultLabel = cEnrollInfo.getKeyType() + " key for $userid$";

        IConfigStore configStore = CMS.getConfigStore();

        String configValue = "op." + currentTokenOperation + "." + selectedTokenType + ".keyGen."
                + cEnrollInfo.getKeyType() + ".label";

        CMS.debug("TPSEnrollProcessor.buildCertificateLabel: label config: " + configValue);

        try {
            pattern = configStore.getString(
                    configValue, defaultLabel);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.buildCertificateLabel: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        Map<String, String> nv = new LinkedHashMap<String, String>();

        nv.put("cuid", ainfo.getCUIDhexString());
        nv.put("msn", ainfo.getMSNString());
        nv.put("userid", userid);
        nv.put("auth.cn", userid);
        nv.put("profileId", getSelectedTokenType());

        label = mapPattern((LinkedHashMap<String, String>) nv, pattern);

        CMS.debug("TPSEnrollProcessor.buildCertificateLabel: returning: " + label);

        return label;
    }

    /**
     * Extracts information from the public key blob and verify proof.
     *
     * Muscle Key Blob Format (RSA Public Key)
     * ---------------------------------------
     *
     * The key generation operation places the newly generated key into
     * the output buffer encoding in the standard Muscle key blob format.
     * For an RSA key the data is as follows:
     *
     * Byte Encoding (0 for plaintext)
     *
     * Byte Key Type (1 for RSA public)
     *
     * Short Key Length (1024 û high byte first)
     *
     * Short Modulus Length
     *
     * Byte[] Modulus
     *
     * Short Exponent Length
     *
     * Byte[] Exponent
     *
     *
     * ECC KeyBlob Format (ECC Public Key)
     * ----------------------------------
     *
     * Byte Encoding (0 for plaintext)
     *
     * Byte Key Type (10 for ECC public)
     *
     * Short Key Length (256, 384, 521 high byte first)
     *
     * Byte[] Key (W)
     *
     *
     * Signature Format (Proof)
     * ---------------------------------------
     *
     * The key generation operation creates a proof-of-location for the
     * newly generated key. This proof is a signature computed with the
     * new private key using the RSA-with-MD5 signature algorithm. The
     * signature is computed over the Muscle Key Blob representation of
     * the new public key and the challenge sent in the key generation
     * request. These two data fields are concatenated together to form
     * the input to the signature, without any other data or length fields.
     *
     * Byte[] Key Blob Data
     *
     * Byte[] Challenge
     *
     *
     * Key Generation Result
     * ---------------------------------------
     *
     * The key generation command puts the key blob and the signature (proof)
     * into the output buffer using the following format:
     *
     * Short Length of the Key Blob
     *
     * Byte[] Key Blob Data
     *
     * Short Length of the Proof
     *
     * Byte[] Proof (Signature) Data
     *
     * @param blob the publickey blob to be parsed
     * @param challenge the challenge generated by TPS
     *
     ******/
    private RSAPublicKey parsePublicKeyBlob(
            TPSBuffer public_key_blob,
            /* TPSBuffer challenge,*/
            boolean isECC)
            throws TPSException {
        RSAPublicKey parsedPubKey = null;

        if (public_key_blob == null /*|| challenge == null*/) {
            throw new TPSException(
                    "TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! Missing public_key_blob or challenge",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        //CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: public key blob from token to parse: "
        //        + public_key_blob.toHexString());
        CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: parsing public key blob from token");

        /*
         * decode blob into structures
         */

        // offset to the beginning of the public key length.  should be 0
        int pkeyb_len_offset = 0;

        /*
         * now, convert lengths
         */
        // 1st, keyblob length
        /*
                byte len0 = public_key_blob.at(pkeyb_len_offset);
                byte len1 = public_key_blob.at(pkeyb_len_offset + 1);
                int pkeyb_len = (len0 << 8) | (len1 & 0xFF);
        */
        int pkeyb_len = public_key_blob.getIntFrom2Bytes(pkeyb_len_offset);
        CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: pkeyb_len = " +
                pkeyb_len + ", isECC: " + isECC);
        // public key blob
        TPSBuffer pkeyb = public_key_blob.substr(pkeyb_len_offset + 2, pkeyb_len);
        if (pkeyb == null) {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: pkeyb null ");
            throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! pkeyb null",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        //CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: pkeyb = "
        //        + pkeyb.toHexString());

        CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: public key pkeyb extracted from blob");
        //  2nd, proof blob length
        int proofb_len_offset = pkeyb_len_offset + 2 + pkeyb_len;
        /*
                len0 = public_key_blob.at(proofb_len_offset);
                len1 = public_key_blob.at(proofb_len_offset + 1);
                int proofb_len = (len0 << 8 | len1 & 0xFF);
        */
        int proofb_len = public_key_blob.getIntFrom2Bytes(proofb_len_offset);
        // proof blob
        TPSBuffer proofb = public_key_blob.substr(proofb_len_offset + 2, proofb_len);
        if (proofb == null) {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: proofb null ");
            throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! proofb null",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        //CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: proofb = "
        //        + proofb.toHexString());
        CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: proof proofb extracted from blob");

        // convert pkeyb to pkey
        // 1 byte encoding, 1 byte key type, 2 bytes key length, then the key
        int pkey_offset = 4;
        /*
                len0 = pkeyb.at(pkey_offset);
                len1 = pkeyb.at(pkey_offset + 1);
        */
        if (!isECC) {
            //            int mod_len = len0 << 8 | len1 & 0xFF;
            int mod_len = pkeyb.getIntFrom2Bytes(pkey_offset);
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: mod_len= " + mod_len);
            /*
                        len0 = pkeyb.at(pkey_offset + 2 + mod_len);
                        len1 = pkeyb.at(pkey_offset + 2 + mod_len + 1);
                        int exp_len = len0 << 8 | len1 & 0xFF;
            */
            int exp_len = pkeyb.getIntFrom2Bytes(pkey_offset + 2 + mod_len);
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: exp_len= " + exp_len);

            TPSBuffer modb = pkeyb.substr(pkey_offset + 2, mod_len);
            if (modb == null) {
                CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: modb null ");
                throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! modb null",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }
            //CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: modb= "
            //        + modb.toHexString());
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: modulus modb extracted from blob");
            TPSBuffer expb = pkeyb.substr(pkey_offset + 2 + mod_len + 2, exp_len);

            if (expb == null) {
                CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: expb null ");
                throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! expb null",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }
            //CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: expb= "
            //        + expb.toHexString());
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob:processing exponent expb extracted from blob");
            BigInt modb_bi = new BigInt(modb.toBytesArray());
            BigInt expb_bi = new BigInt(expb.toBytesArray());
            try {
                RSAPublicKey rsa_pub_key = new RSAPublicKey(modb_bi, expb_bi);
                CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: public key blob converted to RSAPublicKey");
                if (rsa_pub_key != null) {
                    parsedPubKey = rsa_pub_key;
                }
            } catch (InvalidKeyException e) {
                CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob:InvalidKeyException thrown");
                throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Exception thrown: " + e,
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }
        } else {
            // TODO: handle ECC
        }

        // TODO: challenge verification

        // sanity-check parsedPubKey before return
        if (parsedPubKey == null) {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey null");
            throw new TPSException(
                    "TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey null.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        } else {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey not null");
        }
        byte[] parsedPubKey_ba = parsedPubKey.getEncoded();
        if (parsedPubKey_ba == null) {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey_ba null");
            throw new TPSException(
                    "TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey encoding failure.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        } else {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey getEncoded not null");
        }

        return parsedPubKey;
    }

    private boolean checkForServerSideKeyGen(CertEnrollInfo cInfo) throws TPSException {

        if (cInfo == null) {
            throw new TPSException("TPSEnrollProcessor.checkForServerSideKeyGen: invalid cert info.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        IConfigStore configStore = CMS.getConfigStore();
        boolean serverSideKeygen = false;

        try {
            String configValue = cInfo.getKeyTypePrefix() + "." + TPSEngine.CFG_SERVER_KEYGEN_ENABLE;
            CMS.debug("TPSEnrollProcessor.checkForServerSideKeyGen: config: " + configValue);
            serverSideKeygen = configStore.getBoolean(
                    configValue, false);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.checkForServerSideKeyGen: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSProcess.checkForServerSideKeyGen: returning: " + serverSideKeygen);

        return serverSideKeygen;

    }

    private boolean checkForServerKeyArchival(CertEnrollInfo cInfo) throws TPSException {

        if (cInfo == null) {
            throw new TPSException("TPSEnrollProcessor.checkForServerKeyArchival: invalid cert info.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        IConfigStore configStore = CMS.getConfigStore();
        boolean serverKeyArchival = false;

        try {
            String configValue = cInfo.getKeyTypePrefix() + "." + TPSEngine.CFG_SERVER_KEY_ARCHIVAL;
            CMS.debug("TPSEnrollProcessor.checkForServerKeyArchival: config: " + configValue);
            serverKeyArchival = configStore.getBoolean(
                    configValue, false);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.checkForServerKeyArchival: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSProcess.checkForServerKeyArchival: returning: " + serverKeyArchival);

        return serverKeyArchival;

    }

    private boolean checkForObjectOverwrite(CertEnrollInfo cInfo) throws TPSException {

        if (cInfo == null) {
            throw new TPSException("TPSEnrollProcessor.checkForObjectOverwrite: invalid cert info.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        IConfigStore configStore = CMS.getConfigStore();
        boolean objectOverwrite = false;

        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + getSelectedTokenType() + ".keyGen."
                    + cInfo.getKeyType() + "." + TPSEngine.CFG_OVERWRITE;

            CMS.debug("TPSProcess.checkForObjectOverwrite: config: " + configValue);
            objectOverwrite = configStore.getBoolean(
                    configValue, true);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.checkForServerSideKeyGen: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSProcess.checkForObjectOverwrite: returning: " + objectOverwrite);

        return objectOverwrite;

    }

    private String getConfiguredKeyType(int keyTypeIndex) throws TPSException {

        IConfigStore configStore = CMS.getConfigStore();
        String keyType = null;

        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "."
                    + TPSEngine.CFG_KEYGEN_KEYTYPE_VALUE + "." + keyTypeIndex;
            keyType = configStore.getString(
                    configValue, null);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.getConfiguredKeyType: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        //We would really like one of these to exist

        if (keyType == null) {
            throw new TPSException(
                    "TPSEnrollProcessor.getConfiguredKeyType: Internal error finding config value: ",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSProcess.getConfiguredKeyType: returning: " + keyType);

        return keyType;

    }

    private String getDRMConnectorID() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        String id = null;

        String config = "op." + currentTokenOperation + "." + selectedTokenType + "." + TPSEngine.CFG_KEYGEN_ENCRYPTION
                + "." + TPSEngine.CFG_DRM_CONNECTOR;

        CMS.debug("TPSEnrollProcessor.getDRMConnectorID: config value: " + config);
        try {
            id = configStore.getString(config, "kra1");
        } catch (EBaseException e) {
            throw new TPSException("TPSEnrollProcessor.getDRMConnectorID: Internal error finding config value.");

        }

        CMS.debug("TPSEnrollProcessor.getDRMConectorID: returning: " + id);

        return id;
    }

    protected int getNumberCertsToEnroll() throws TPSException {
        String method = "TPSEnrollProcessor.getNumberCertsToEnroll:";
        String logMsg;
        IConfigStore configStore = CMS.getConfigStore();
        int keyTypeNum = 0;
        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "."
                    + TPSEngine.CFG_KEYGEN_KEYTYPE_NUM;
            CMS.debug(method + "getting config value for:" + configValue);
            keyTypeNum = configStore.getInteger(
                    configValue, 0);

        } catch (EBaseException e) {
            logMsg = "Internal error finding config value: " + e;
            throw new TPSException(method + logMsg,
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);

        }

        if (!isExternalReg) {
            if (keyTypeNum == 0) {
                throw new TPSException(
                        method + " invalid number of certificates configured!",
                        TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }
        }
        CMS.debug(method + " returning: " + keyTypeNum);

        return keyTypeNum;
    }

    protected int getEnrollmentAlg() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        int enrollmentAlg;
        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "."
                    + TPSEngine.CFG_KEYGEN_ENCRYPTION + "." + TPSEngine.CFG_ALG;

            CMS.debug("TPSProcess.getEnrollmentAlg: configValue: " + configValue);

            enrollmentAlg = configStore.getInteger(
                    configValue, 2);

        } catch (EBaseException e) {
            throw new TPSException("TPSEnrollProcessor.getEnrollmentAlg: Internal error finding config value: "
                    + e,
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);

        }

        CMS.debug("TPSProcess.getEnrollmentAlg: returning: " + enrollmentAlg);

        return enrollmentAlg;
    }

    protected String getRecoveryKeyTypeValue(String reason, int index) throws TPSException {

        if (reason == null || index < 0) {
            throw new TPSException("TPSEnrollProcessor.getRecoveryKeyTypeValue: invalide input data!",
                    TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
        }

        IConfigStore configStore = CMS.getConfigStore();
        String keyTypeValue;
        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "." + TPSEngine.CFG_KEYGEN
                    + "."
                    + TPSEngine.RECOVERY_OP + "." + reason + "." + TPSEngine.CFG_KEYTYPE_VALUE + "." + index;
            ;

            CMS.debug("TPSProcess.getRecoveryKeyTypeValue: configValue: " + configValue);

            keyTypeValue = configStore.getString(
                    configValue, null);

        } catch (EBaseException e) {
            throw new TPSException("TPSEnrollProcessor.getRecoveryKeyTypeValue: Internal error finding config value: "
                    + e,
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);

        }

        if (keyTypeValue == null) {
            throw new TPSException("TPSEnrollProcessor.getRecoveryKeyTypeValue: Invalid keyTypeValue found! ",
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }

        CMS.debug("TPSProcess.getRecoveryKeyTypeValue: returning: " + keyTypeValue);

        return keyTypeValue;
    }

    protected String getRecoveryScheme(String reason, String keyTypeValue) throws TPSException {

        if (reason == null || keyTypeValue == null) {
            throw new TPSException("TPSEnrollProcessor.getRecoveryScheme: invalid input data!",
                    TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
        }

        IConfigStore configStore = CMS.getConfigStore();
        String scheme = null;
        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "." + TPSEngine.CFG_KEYGEN
                    + "." + keyTypeValue + "."
                    + TPSEngine.RECOVERY_OP + "." + reason + "." + TPSEngine.CFG_SCHEME;
            ;

            CMS.debug("TPSProcess.getRecoveryScheme: configValue: " + configValue);

            scheme = configStore.getString(
                    configValue, null);

        } catch (EBaseException e) {
            throw new TPSException("TPSEnrollProcessor.getRecoveryScheme: Internal error finding config value: "
                    + e,
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);

        }

        if (scheme == null) {
            throw new TPSException("TPSEnrollProcessor.getRecoverScheme: Invalid scheme found! ",
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }

        CMS.debug("TPSProcess.getRecoveryScheme: returning: " + scheme);

        return scheme;
    }

    protected int getNumberCertsForRecovery(String reason) throws TPSException {
        if (reason == null) {
            throw new TPSException("TPSEnrollProcessor.getNumberCertsForRecovery: invlalid input data!",
                    TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
        }

        IConfigStore configStore = CMS.getConfigStore();
        int keyTypeNum = 0;
        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "." + TPSEngine.CFG_KEYGEN
                    + "." + TPSEngine.RECOVERY_OP
                    + "." + reason + "." + TPSEngine.CFG_KEYTYPE_NUM;

            CMS.debug("TPSEnrollProcessor.getNumberCertsForRecovery: configValue: " + configValue);
            keyTypeNum = configStore.getInteger(
                    configValue, 0);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.getNumberCertsForRecovery: Internal error finding config value: "
                            + e,
                    TPSStatus.STATUS_ERROR_RECOVERY_FAILED);

        }

        if (keyTypeNum == 0) {
            throw new TPSException(
                    "TPSEnrollProcessor.getNumberCertsForRecovery: invalid number of certificates configured!",
                    TPSStatus.STATUS_ERROR_RECOVERY_FAILED);
        }
        CMS.debug("TPSProcess.getNumberCertsForRecovery: returning: " + keyTypeNum);

        return keyTypeNum;
    }

    private TPSBuffer makeKeyIDFromPublicKeyInfo(byte[] publicKeyInfo) throws TPSException {

        final String alg = "SHA1";

        if (publicKeyInfo == null) {
            throw new TPSException("TPSEnrollProcessor.makeKeyIDFromPublicKeyInfo: invalid input data",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        TPSBuffer keyID = null;

        byte[] mozillaDigestOut;

        java.security.MessageDigest mozillaDigest;
        try {
            mozillaDigest = java.security.MessageDigest.getInstance(alg);
        } catch (NoSuchAlgorithmException e) {
            throw new TPSException("TPSEnrollProcessor.makeKeyIDFromPublicKeyInfo: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        mozillaDigestOut = mozillaDigest.digest(publicKeyInfo);

        if (mozillaDigestOut.length == mozillaDigest.getDigestLength()) {
            //System.out.println(mozillaDigest.getAlgorithm() + " " +
            //        " digest output size is " + mozillaDigestOut.length);
        } else {
            throw new TPSException("ERROR: digest output size is " +
                    mozillaDigestOut.length + ", should be " +
                    mozillaDigest.getDigestLength(), TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        keyID = new TPSBuffer(mozillaDigestOut);

        CMS.debug("TPSEnrollProcessor.makeKeyIDFromPublicKeyInfo: " + keyID.toHexString());

        return keyID;
    }

    public BigInteger serialNoToBigInt(String serialS) {
        if (serialS == null)
            return new BigInteger("0", 16);

        CMS.debug("TPSEnrollProcessor.seralNoToBigInt: serial # =" + serialS);
        String serialhex = serialS.substring(2); // strip off the "0x"
        BigInteger serialBI = new BigInteger(serialhex, 16);

        return serialBI;
    }

    /*
     * op can be "retrieval", "renewal", or "enrollment" (default)
     */
    private void auditEnrollment(String subjectID, String op,
            AppletInfo aInfo,
            String status,
            String keyVersion,
            BigInteger serial,
            String caConnId,
            String info) {

        // when serial is 0, means no serial, as in case of failure
        String serialNum = "";
        if (serial != null && serial.compareTo(BigInteger.ZERO) > 0)
            serialNum = serial.toString();

        String auditType = "";
        switch (op) {
        case "retrieval":
            auditType = AuditEvent.TOKEN_CERT_RETRIEVAL;
            break;
        case "renewal":
            auditType = AuditEvent.TOKEN_CERT_RENEWAL;
            break;
        default:
            auditType = AuditEvent.TOKEN_CERT_ENROLLMENT;
        }

        String auditMessage = CMS.getLogMessage(
                auditType,
                (session != null) ? session.getIpAddress() : null,
                subjectID,
                aInfo.getCUIDhexStringPlain(),
                status,
                getSelectedTokenType(),
                keyVersion,
                serialNum,
                caConnId,
                info);
        audit(auditMessage);
    }

    private void auditRecovery(String subjectID, AppletInfo aInfo,
            String status,
            String keyVersion,
            BigInteger serial,
            String caConnId,
            String kraConnId,
            String info) {

        String serialNum = "";
        if (serial.compareTo(BigInteger.ZERO) > 0)
            serialNum = serial.toString();

        String auditMessage = CMS.getLogMessage(
                AuditEvent.TOKEN_KEY_RECOVERY,
                (session != null) ? session.getIpAddress() : null,
                subjectID,
                aInfo.getCUIDhexStringPlain(),
                status,
                getSelectedTokenType(),
                keyVersion,
                serialNum,
                caConnId,
                kraConnId,
                info);
        audit(auditMessage);
    }

    private boolean checkUserAlreadyHasActiveToken(String userid) {

        String method = "TPSEnrollProcessor.checkUserAlreadyHasActiveToken: ";
        boolean result = false;

        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        try {
            tps.tdb.tdbHasActiveToken(userid);
            result = true;

        } catch (Exception e) {
            result = false;
        }

        CMS.debug(method + " user: " + userid + " has a token already: " + result);

        return result;
    }

    private boolean checkUserAlreadyHasOtherActiveToken(String userid, String cuid) {
        boolean result = false;
        String method = "TPSEnrollProcessor.checkUserAlreadyHasOtherActiveToken: ";

        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        try {
            tps.tdb.tdbHasOtherActiveToken(userid, cuid);
            result = true;

        } catch (Exception e) {
            result = false;
        }

        CMS.debug(method + " user: " + userid + " has an active token already: not cuid:  " + cuid + " : " + result);

        return result;
    }

    private boolean checkAllowMultiActiveTokensUser(boolean isExternalReg) {
        boolean allow = true;

        String method = "TPSEnrollProcessor.checkAllowMultiActiveTokensUser: ";
        IConfigStore configStore = CMS.getConfigStore();

        String scheme = null;

        if (isExternalReg == true) {
            scheme = TPSEngine.CFG_EXTERNAL_REG;
        } else {
            scheme = TPSEngine.CFG_NON_EXTERNAL_REG;
        }

        String allowMultiConfig = TPSEngine.CFG_TOKENDB + "." + scheme + "."
                + TPSEngine.CFG_ALLOW_MULTI_TOKENS_USER;

        CMS.debug(method + " trying config: " + allowMultiConfig);

        try {
            allow = configStore.getBoolean(allowMultiConfig, false);
        } catch (EBaseException e) {
            allow = false;
        }

        CMS.debug(method + "returning allow: " + allow);

        return allow;
    }

    public static void main(String[] args) {
    }

}
