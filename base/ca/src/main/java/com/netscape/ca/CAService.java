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
package com.netscape.ca;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.dogtagpki.ct.CTEngine;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICAService;
import org.dogtagpki.server.ca.ICRLIssuingPoint;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.extensions.CertInfo;
import org.mozilla.jss.netscape.security.util.BigInt;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSerialNumber;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.LdapV3DNStrConverter;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.SerialNumber;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X500NameAttrMap;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.SecurityDataArchivalRequestEvent;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.connector.HttpConnector;
import com.netscape.cmscore.connector.LocalConnector;
import com.netscape.cmscore.connector.RemoteAuthority;
import com.netscape.cmscore.crmf.CRMFParser;
import com.netscape.cmscore.crmf.PKIArchiveOptionsContainer;
import com.netscape.cmscore.dbs.CRLRepository;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertRecordList;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Request Service for CertificateAuthority.
 */
public class CAService implements ICAService, IService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAService.class);
    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public static final String CRMF_REQUEST = "CRMFRequest";
    public static final String CHALLENGE_PHRASE = "challengePhrase";
    public static final String SERIALNO_ARRAY = "serialNoArray";

    // CCA->CLA connector
    protected static IConnector mCLAConnector = null;

    private CertificateAuthority mCA = null;
    private Hashtable<String, IServant> mServants = new Hashtable<String, IServant>();
    private IConnector mKRAConnector = null;
    private IConfigStore mConfig = null;
    private boolean mArchivalRequired = true;

    public CAService(CertificateAuthority ca) {
        mCA = ca;

        // init services.
        mServants.put(
                IRequest.ENROLLMENT_REQUEST,
                new serviceIssue(this));
        mServants.put(
                IRequest.RENEWAL_REQUEST,
                new serviceRenewal(this));
        mServants.put(
                IRequest.REVOCATION_REQUEST,
                new serviceRevoke(this));
        mServants.put(
                IRequest.CMCREVOKE_REQUEST,
                new serviceRevoke(this));
        mServants.put(
                IRequest.REVOCATION_CHECK_CHALLENGE_REQUEST,
                new serviceCheckChallenge(this));
        mServants.put(
                IRequest.GETCERTS_FOR_CHALLENGE_REQUEST,
                new getCertsForChallenge(this));
        mServants.put(
                IRequest.UNREVOCATION_REQUEST,
                new serviceUnrevoke(this));
        mServants.put(
                IRequest.GETCACHAIN_REQUEST,
                new serviceGetCAChain(this));
        mServants.put(
                IRequest.GETCRL_REQUEST,
                new serviceGetCRL(this));
        mServants.put(
                IRequest.GETREVOCATIONINFO_REQUEST,
                new serviceGetRevocationInfo(this));
        mServants.put(
                IRequest.GETCERTS_REQUEST,
                new serviceGetCertificates(this));
        mServants.put(
                IRequest.CLA_CERT4CRL_REQUEST,
                new serviceCert4Crl(this));
        mServants.put(
                IRequest.CLA_UNCERT4CRL_REQUEST,
                new serviceUnCert4Crl(this));
        mServants.put(
                IRequest.GETCERT_STATUS_REQUEST,
                new getCertStatus(this));
    }

    public void init(IConfigStore config) throws EBaseException {
        mConfig = config;

        try {
            // MOVED TO com.netscape.certsrv.apps.CMS
            //			java.security.Security.addProvider(new org.mozilla.jss.netscape.security.provider.CMS());
            //			java.security.Provider pr = java.security.Security.getProvider("CMS");
            //			if (pr != null) {
            //				;
            //			}
            //			else
            //				logger.debug("Something is wrong in CMS install !");
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");

            logger.debug("CertificateFactory Type : " + cf.getType());
            logger.debug("CertificateFactory Provider : " + cf.getProvider().getInfo());
        } catch (java.security.cert.CertificateException e) {
            logger.warn("Something is happen in install CMS provider !" + e.toString());
        }
    }

    public void startup() throws EBaseException {
        IConfigStore kraConfig = mConfig.getSubStore("KRA");

        if (kraConfig != null) {
            mArchivalRequired = kraConfig.getBoolean(
                    "archivalRequired", true);
            mKRAConnector = getConnector(kraConfig);
            if (mKRAConnector != null) {
                logger.info("Started KRA Connector");
                mKRAConnector.start();
            }
        }

        // clone ca to CLA (clone master) connector
        IConfigStore claConfig = mConfig.getSubStore("CLA");

        if (claConfig != null) {
            mCLAConnector = getConnector(claConfig);
            if (mCLAConnector != null) {
                logger.debug(CMS.getLogMessage("CMSCORE_CA_START_CONNECTOR"));
                logger.info("Started CLA Connector in CCA");
                mCLAConnector.start();
            }
        }
    }

    protected CertificateAuthority getCA() {
        return mCA;
    }

    public IConnector getKRAConnector() {
        return mKRAConnector;
    }

    public void setKRAConnector(IConnector c) {
        mKRAConnector = c;
    }

    public IConnector getConnector(IConfigStore config)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        EngineConfig cs = engine.getConfig();

        IConnector connector = null;

        if (config == null || config.size() <= 0) {
            return null;
        }
        boolean enable = config.getBoolean("enable", true);
        // provide a way to register a 3rd connector into RA
        String extConnector = config.getString("class", null);

        if (extConnector != null) {
            try {
                connector = (IConnector) Class.forName(extConnector).getDeclaredConstructor().newInstance();
                // connector.start() will be called later on
                return connector;
            } catch (Exception e) {
                // ignore external class if error
                logger.warn(CMS.getLogMessage("CMSCORE_CA_LOAD_CONNECTOR", extConnector, e.toString()), e);
            }
        }

        if (!enable)
            return null;
        boolean local = config.getBoolean("local");
        IAuthority authority = null;

        if (local) {
            String id = config.getString("id");

            authority = (IAuthority) engine.getSubsystem(id);
            if (authority == null) {
                String msg = "local authority " + id + " not found.";

                logger.error(CMS.getLogMessage("CMSCORE_CA_AUTHORITY_NOT_FOUND", id));
                throw new EBaseException(msg);
            }
            connector = new LocalConnector(mCA, authority);
            // logger.info("local Connector to "+id+" inited");
        } else {
            String host = config.getString("host");
            int port = config.getInteger("port");
            String uri = config.getString("uri");

            // Use client cert specified in KRA connector
            String nickname = config.getString("nickName", null);
            if (nickname == null) {
                // Use subsystem cert as client cert
                nickname = cs.getString("ca.subsystem.nickname");

                String tokenname = cs.getString("ca.subsystem.tokenname", "");
                if (!CryptoUtil.isInternalToken(tokenname)) nickname = tokenname + ":" + nickname;
            }

            int resendInterval = config.getInteger("resendInterval", -1);
            // Inserted by beomsuk
            int timeout = config.getInteger("timeout", 0);
            // Insert end
            // Changed by beomsuk
            //RemoteAuthority remauthority =
            //	new RemoteAuthority(host, port, uri);
            RemoteAuthority remauthority =
                    new RemoteAuthority(host, port, uri, timeout);

            // Changed by beomsuk
            //connector =
            //	new HttpConnector(mCA, nickname, remauthority, resendInterval);

            String clientCiphers = config.getString("clientCiphers", null);
            if (timeout == 0)
                connector = new HttpConnector(mCA, nickname, clientCiphers, remauthority, resendInterval,
                        config);
            else
                connector =
                        new HttpConnector(mCA, nickname, clientCiphers, remauthority, resendInterval,
                                config, timeout);
            // Change end

            // logger.info("remote authority " + host+":"+port+" "+uri+" inited");
        }
        return connector;
    }

    public boolean isProfileRequest(IRequest request) {
        String profileId = request.getExtDataInString(IRequest.PROFILE_ID);

        if (profileId == null || profileId.equals(""))
            return false;
        else
            return true;
    }

    /**
     * After population of defaults, and constraint validation,
     * the profile request is processed here.
     */
    public void serviceProfileRequest(IRequest request)
            throws EBaseException {
        logger.debug("CAService: serviceProfileRequest requestId=" +
                request.getRequestId().toString());

        String profileId = request.getExtDataInString(IRequest.PROFILE_ID);

        if (profileId == null || profileId.equals("")) {
            throw new EBaseException("profileId not found");
        }

        CAEngine engine = CAEngine.getInstance();
        ProfileSubsystem ps = engine.getProfileSubsystem();
        Profile profile = null;

        try {
            profile = ps.getProfile(profileId);
        } catch (EProfileException e) {
        }
        if (profile == null) {
            throw new EProfileException("Profile not found " + profileId);
        }

        // assumed rejected
        request.setExtData("dbStatus", "NOT_UPDATED");

        //	profile.populate(request);
        profile.validate(request);
        profile.execute(request);

        // This function is called only from ConnectorServlet

        // serialize to request queue
    }

    /**
     * method interface for IService
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST used whenever a user private key archive
     * request is made. This is an option in a cert enrollment request detected by an RA or a CA, so, if selected, it
     * should be logged immediately following the certificate request.
     * </ul>
     *
     * @param request a certificate enrollment request from an RA or CA
     * @return true or false
     */
    public boolean serviceRequest(IRequest request) {
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID();
        RequestId requestId = request.getRequestId();

        boolean completed = false;

        // short cut profile-based request
        if (isProfileRequest(request)) {
            try {
                logger.debug("CAService: x0 requestStatus="
                        + request.getRequestStatus().toString() + " instance=" + request);
                serviceProfileRequest(request);
                request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
                logger.debug("CAService: x1 requestStatus=" + request.getRequestStatus().toString());

                return true;
            } catch (EBaseException e) {
                logger.debug("CAService: x2 requestStatus=" + request.getRequestStatus().toString());
                // need to put error into the request
                logger.debug("CAService: serviceRequest " + e.toString());
                request.setExtData(IRequest.RESULT, IRequest.RES_ERROR);
                request.setExtData(IRequest.ERROR, e.toString());

                // TODO(alee) New audit message needed here

                return false;
            }
        }

        String type = request.getRequestType();
        IServant servant = mServants.get(type);

        if (servant == null) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_INVALID_REQUEST_TYPE", type));
            request.setExtData(IRequest.RESULT, IRequest.RES_ERROR);
            request.setExtData(IRequest.ERROR,
                    new ECAException(CMS.getUserMessage("CMS_CA_UNRECOGNIZED_REQUEST_TYPE", type)));

            return true;
        }

        // NOTE to alee: The request must include the realm by this point.

        try {
            // send request to KRA first
            if (type.equals(IRequest.ENROLLMENT_REQUEST) &&
                    isPKIArchiveOptionPresent(request) && mKRAConnector != null) {

                logger.debug("CAService: Sending enrollment request to KRA");

                signedAuditLogger.log(SecurityDataArchivalRequestEvent.createSuccessEvent(
                        auditSubjectID,
                        auditRequesterID,
                        requestId,
                        null));

                boolean sendStatus = mKRAConnector.send(request);

                if (mArchivalRequired == true) {
                    if (sendStatus == false) {
                        String message = CMS.getUserMessage("CMS_CA_SEND_KRA_REQUEST");
                        request.setExtData(IRequest.RESULT,
                                IRequest.RES_ERROR);
                        request.setExtData(IRequest.ERROR, new ECAException(message));

                        signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                                auditSubjectID,
                                auditRequesterID,
                                requestId,
                                null,
                                message));

                        return true;
                    } else {
                        if (request.getExtDataInString(IRequest.ERROR) != null) {
                            request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
                            request.deleteExtData(IRequest.ERROR);
                        }
                    }

                    String message = request.getExtDataInString(IRequest.ERROR);
                    if (message != null) {

                        signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                                auditSubjectID,
                                auditRequesterID,
                                requestId,
                                null,
                                message));

                        return true;
                    }
                }
            } else {
                logger.debug("*** NOT Send to KRA type=" + type + " ENROLLMENT=" + IRequest.ENROLLMENT_REQUEST);
            }

            completed = servant.service(request);
            request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
        } catch (EBaseException e) {
            request.setExtData(IRequest.RESULT, IRequest.RES_ERROR);
            request.setExtData(IRequest.ERROR, e);

            if (!(type.equals(IRequest.REVOCATION_REQUEST) ||
                    type.equals(IRequest.UNREVOCATION_REQUEST) || type.equals(IRequest.CMCREVOKE_REQUEST))) {

                signedAuditLogger.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                        auditSubjectID,
                        auditRequesterID,
                        requestId,
                        null,
                        e));
            }

            return true;
        }

        // XXX in case of key archival this may not always be the case.
        logger.debug("serviceRequest completed = " + completed);

        if (!(type.equals(IRequest.REVOCATION_REQUEST) ||
                type.equals(IRequest.UNREVOCATION_REQUEST) || type.equals(IRequest.CMCREVOKE_REQUEST))) {

            signedAuditLogger.log(SecurityDataArchivalRequestEvent.createSuccessEvent(
                    auditSubjectID,
                    auditRequesterID,
                    requestId,
                    null));
        }

        return completed;
    }

    /**
     * Checks if PKIArchiveOption present in the request.
     */
    private boolean isPKIArchiveOptionPresent(IRequest request) {
        String crmfBlob = request.getExtDataInString(
                IRequest.HTTP_PARAMS, CRMF_REQUEST);

        if (crmfBlob == null) {
            logger.debug("CRMF not found");
        } else {
            try {
                PKIArchiveOptionsContainer opts[] = CRMFParser.getPKIArchiveOptions(crmfBlob);

                if (opts != null) {
                    return true;
                }
            } catch (IOException e) {
            }
            return false;
        }
        return false;
    }

    ///
    /// CA related routines.
    ///

    /**
     * issue cert for enrollment.
     */
    public X509CertImpl issueX509Cert(
            AuthorityID aid, X509CertInfo certi,
            String profileId, String rid)
            throws EBaseException {
        logger.debug("issueX509Cert");
        X509CertImpl certImpl = issueX509Cert(aid, "", certi, false, null);

        logger.debug("storeX509Cert " + certImpl.getSerialNumber());
        storeX509Cert(profileId, rid, certImpl);
        logger.debug("done storeX509Cert");
        return certImpl;
    }

    X509CertImpl issueX509Cert(String rid, X509CertInfo certi)
            throws EBaseException {
        return issueX509Cert(rid, certi, false, null);
    }

    /**
     * issue cert for enrollment.
     */
    void storeX509Cert(String profileId, String rid, X509CertImpl cert)
            throws EBaseException {
        storeX509Cert(rid, cert, false, null, null, null, profileId);
    }

    /**
     * issue cert for enrollment.
     */
    void storeX509Cert(String rid, X509CertImpl cert, String crmfReqId)
            throws EBaseException {
        storeX509Cert(rid, cert, false, null, crmfReqId, null, null);
    }

    void storeX509Cert(String rid, X509CertImpl cert, String crmfReqId,
            String challengePassword) throws EBaseException {
        storeX509Cert(rid, cert, false, null, crmfReqId, challengePassword, null);
    }

    /**
     * issue cert for enrollment and renewal.
     * renewal is expected to have original cert serial no. in cert info
     * field.
     */
    X509CertImpl issueX509Cert(
            String rid, X509CertInfo certi,
            boolean renewal, BigInteger oldSerialNo
            ) throws EBaseException {
        return issueX509Cert(null, rid, certi, renewal, oldSerialNo);
    }

    private X509CertImpl issueX509Cert(
            AuthorityID aid, String rid, X509CertInfo certi,
            boolean renewal, BigInteger oldSerialNo
            ) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new CANotFoundException("No such CA: " + aid);

        String algname = null;
        X509CertImpl cert = null;

        // NOTE:  In this implementation, the "oldSerialNo"
        //        parameter is NOT used!

        boolean doUTF8 = mConfig.getBoolean("dnUTF8Encoding", false);

        logger.debug("dnUTF8Encoding " + doUTF8);

        CertificateExtensions exts = null;
        try {
            // check required fields in certinfo.
            if (certi.get(X509CertInfo.SUBJECT) == null ||
                    certi.get(X509CertInfo.KEY) == null) {

                logger.error(CMS.getLogMessage("CMSCORE_CA_MISSING_ATTR"));
                // XXX how do you reject a request in the service object ?
                throw new ECAException(
                        CMS.getUserMessage("CMS_CA_MISSING_REQD_FIELDS_IN_CERTISSUE"));
            }

            // set default cert version. If policies added a extensions
            // the version would already be set to version 3.
            if (certi.get(X509CertInfo.VERSION) == null) {
                certi.set(X509CertInfo.VERSION, engine.getDefaultCertVersion());
            }

            // set default validity if not set.
            // validity would normally be set by policies or by
            // agent or by authentication module.
            CertificateValidity validity = (CertificateValidity)
                    certi.get(X509CertInfo.VALIDITY);
            Date begin = null, end = null;

            if (validity != null) {
                begin = (Date)
                        validity.get(CertificateValidity.NOT_BEFORE);
                end = (Date)
                        validity.get(CertificateValidity.NOT_AFTER);
            }
            if (validity == null ||
                    (begin.getTime() == 0 && end.getTime() == 0)) {
                logger.debug("setting default validity");

                begin = new Date();
                end = new Date(begin.getTime() + engine.getDefaultCertValidity());
                certi.set(CertificateValidity.NAME,
                        new CertificateValidity(begin, end));
            }

            /*
             * For non-CA certs, check if validity exceeds CA time.
             * If so, set to CA's not after  if default validity
             * exceeds ca's not after.
             */

            // First find out if it is a CA cert
            boolean is_ca = false;
            BasicConstraintsExtension bc_ext = null;

            try {
                exts = (CertificateExtensions)
                        certi.get(X509CertInfo.EXTENSIONS);
                if (exts != null) {
                    Enumeration<Extension> e = exts.getAttributes();

                    while (e.hasMoreElements()) {
                        org.mozilla.jss.netscape.security.x509.Extension ext = e.nextElement();

                        if (ext.getExtensionId().toString().equals(PKIXExtensions.BasicConstraints_Id.toString())) {
                            bc_ext = (BasicConstraintsExtension) ext;
                        }
                    }

                    if (bc_ext != null) {
                        Boolean isCA = (Boolean) bc_ext.get(BasicConstraintsExtension.IS_CA);
                        is_ca = isCA.booleanValue();
                    }
                } // exts != null
            } catch (Exception e) {
                logger.warn("EnrollDefault: getExtension " + e.toString());
            }

            Date caNotAfter =
                    ca.getSigningUnit().getCertImpl().getNotAfter();

            if (begin.after(caNotAfter)) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_PAST_VALIDITY"));
                throw new ECAException(CMS.getUserMessage("CMS_CA_CERT_BEGIN_AFTER_CA_VALIDITY"));
            }

            if (end.after(caNotAfter)) {
                logger.debug("CAService: issueX509Cert: notAfter past CA's NOT_AFTER");
                if (!is_ca) {
                    if (!engine.getEnablePastCATime()) {
                        end = caNotAfter;
                        certi.set(CertificateValidity.NAME,
                                new CertificateValidity(begin, caNotAfter));
                        logger.debug("CAService: issueX509Cert: ca.enablePastCATime != true...resetting to match CA's notAfter");
                    } else {
                        logger.debug("CAService: issueX509Cert: ca.enablePastCATime = true...not resetting");
                    }
                } else { //is_ca
                    logger.debug("CAService: issueX509Cert: request issuance of a ca signing cert");
                    if (!engine.getEnablePastCATime_caCert()) {
                        end = caNotAfter;
                        certi.set(CertificateValidity.NAME,
                                new CertificateValidity(begin, caNotAfter));
                        logger.debug("CAService: issueX509Cert: ca.enablePastCATime_caCert != true...resetting to match CA's notAfter");
                    } else {
                        logger.debug("CAService: issueX509Cert: ca.enablePastCATime_caCert = true...not resetting");
                    }
                }

                logger.info(CMS.getLogMessage("CMSCORE_CA_PAST_NOT_AFTER"));
            }

            // check algorithm in certinfo.
            AlgorithmId algid = null;
            CertificateAlgorithmId algor = (CertificateAlgorithmId)
                    certi.get(X509CertInfo.ALGORITHM_ID);

            if (algor == null || algor.toString().equals(CertInfo.SERIALIZE_ALGOR.toString())) {
                algname = ca.getSigningUnit().getDefaultAlgorithm();
                algid = AlgorithmId.get(algname);
                certi.set(X509CertInfo.ALGORITHM_ID,
                        new CertificateAlgorithmId(algid));
            } else {
                algid = (AlgorithmId)
                        algor.get(CertificateAlgorithmId.ALGORITHM);
                algname = algid.getName();
            }

        } catch (CertificateException e) {
            String message = CMS.getLogMessage("CMSCORE_CA_BAD_FIELD", e.toString());
            logger.error(message, e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_ERROR_GETTING_FIELDS_IN_ISSUE"));

        } catch (IOException e) {
            String message = CMS.getLogMessage("CMSCORE_CA_BAD_FIELD", e.toString());
            logger.error(message, e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_ERROR_GETTING_FIELDS_IN_ISSUE"));

        } catch (NoSuchAlgorithmException e) {
            String message = CMS.getLogMessage("CMSCORE_CA_SIGNING_ALG_NOT_SUPPORTED", algname);
            logger.error(message, e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_ALGOR_NOT_SUPPORTED", algname));
        }

        // get old cert serial number if renewal
        if (renewal) {
            try {
                CertificateSerialNumber serialno = (CertificateSerialNumber)
                        certi.get(X509CertInfo.SERIAL_NUMBER);

                if (serialno == null) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_NULL_SERIAL_NUMBER"));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }
                SerialNumber serialnum = (SerialNumber)
                        serialno.get(CertificateSerialNumber.NUMBER);

                if (serialnum == null) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_NULL_SERIAL_NUMBER"));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }
            } catch (CertificateException e) {
                // not possible
                logger.error(CMS.getLogMessage("CMSCORE_CA_NO_ORG_SERIAL", e.getMessage()));
                throw new ECAException(
                        CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
            } catch (IOException e) {
                // not possible.
                logger.error(CMS.getLogMessage("CMSCORE_CA_NO_ORG_SERIAL", e.getMessage()));
                throw new ECAException(
                        CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
            }
        }

        // set issuer, serial number
        try {
            BigInteger serialNo = cr.getNextSerialNumber();
            logger.info("CAService: Signing cert 0x" + serialNo.toString(16));

            certi.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNo));

        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_NO_NEXT_SERIAL", e.toString()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_NOSERIALNO", rid), e);

        } catch (CertificateException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SET_SERIAL", e.toString()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SET_SERIALNO_FAILED", rid), e);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SET_SERIAL", e.toString()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SET_SERIALNO_FAILED", rid), e);
        }

        try {
            if (ca.getIssuerObj() != null) {
                // this ensures the isserDN has the same encoding as the
                // subjectDN of the CA signing cert
                logger.debug("CAService: issueX509Cert: setting issuerDN using exact CA signing cert subjectDN encoding");
                certi.set(X509CertInfo.ISSUER,
                        ca.getIssuerObj());
            } else {
                logger.debug("CAService: issueX509Cert: ca.getIssuerObj() is null, creating new CertificateIssuerName");
                certi.set(X509CertInfo.ISSUER,
                        new CertificateIssuerName(ca.getX500Name()));
            }
        } catch (CertificateException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SET_ISSUER", e.toString()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_SET_ISSUER_FAILED", rid), e);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SET_ISSUER", e.toString()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_SET_ISSUER_FAILED", rid), e);
        }

        byte[] utf8_encodingOrder = { DerValue.tag_UTF8String };

        if (doUTF8 == true) {
            try {

                logger.debug("doUTF8 true, updating subject.");

                String subject = certi.get(X509CertInfo.SUBJECT).toString();

                certi.set(X509CertInfo.SUBJECT, new CertificateSubjectName(
                        new X500Name(subject,
                                new LdapV3DNStrConverter(X500NameAttrMap.getDirDefault(), true), utf8_encodingOrder)));

            } catch (CertificateException e) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_SET_SUBJECT", e.toString()), e);
                throw new ECAException(CMS.getUserMessage("CMS_CA_SET_ISSUER_FAILED", rid), e);
            } catch (IOException e) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_SET_SUBJECT", e.toString()), e);
                throw new ECAException(CMS.getUserMessage("CMS_CA_SET_ISSUER_FAILED", rid), e);
            }
        }

        /*
         * handle possible Certificate Transparency processing
         */
        CTEngine ctEngine = new CTEngine();
        ctEngine.process(certi, mCA, aid, algname);

        logger.debug("CAService: issueX509Cert: About to ca.sign cert.");
        cert = ca.sign(certi, algname);
        return cert;
    }

    void storeX509Cert(String rid, X509CertImpl cert,
            boolean renewal, BigInteger oldSerialNo)
            throws EBaseException {
        storeX509Cert(rid, cert, renewal, oldSerialNo, null, null, null);
    }

    void storeX509Cert(String rid, X509CertImpl cert,
            boolean renewal, BigInteger oldSerialNo, String crmfReqId,
            String challengePassword, String profileId) throws EBaseException {

        logger.info("CAService: Storing cert 0x" + cert.getSerialNumber().toString(16));

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        // now store in repository.
        // if renewal, set the old serial number in the new cert,
        // set the new serial number in the old cert.

        try {
            BigInteger newSerialNo = cert.getSerialNumber();
            MetaInfo metaInfo = new MetaInfo();

            if (profileId != null) {
                metaInfo.set("profileId", profileId);
            }

            if (rid != null) {
                metaInfo.set(CertRecord.META_REQUEST_ID, rid);
            }

            if (challengePassword != null && !challengePassword.equals("")) {
                metaInfo.set("challengePhrase", challengePassword);
            }

            if (crmfReqId != null) {
                //System.out.println("Adding crmf reqid "+crmfReqId);
                metaInfo.set(CertRecord.META_CRMF_REQID, crmfReqId);
            }

            if (renewal) {
                metaInfo.set(CertRecord.META_OLD_CERT, oldSerialNo.toString());
            }

            cr.addCertificateRecord(new CertRecord(newSerialNo, cert, metaInfo));

            if (renewal) {

                logger.info("CAService: Updating old cert 0x" + oldSerialNo.toString(16));

                /*
                 mCA.getCertificateRepository().markCertificateAsRenewed(
                 BigIntegerMapper.BigIntegerToDB(oldSerialNo));
                 mCA.mCertRepot.markCertificateAsRenewed(oldSerialNo);
                 */
                MetaInfo oldMeta = null;
                CertRecord oldCertRec = cr.readCertificateRecord(oldSerialNo);

                if (oldCertRec == null) {
                    String message = CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                            "Cannot read cert record for " + oldSerialNo);
                    Exception e = new EBaseException(message);
                    logger.warn(message, e);
                }

                if (oldCertRec != null) {
                    oldMeta = oldCertRec.getMetaInfo();
                }

                if (oldMeta == null) {
                    logger.debug("No meta info! for " + oldSerialNo);
                    oldMeta = new MetaInfo();

                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Old meta info");
                        Enumeration<String> n = oldMeta.getElements();

                        while (n.hasMoreElements()) {
                            String name = n.nextElement();

                            logger.debug("name " + name + " value " +
                                    oldMeta.get(name));
                        }
                    }
                }

                oldMeta.set(CertRecord.META_RENEWED_CERT, newSerialNo.toString());

                ModificationSet modSet = new ModificationSet();

                modSet.add(CertRecord.ATTR_AUTO_RENEW,
                        Modification.MOD_REPLACE,
                        CertRecord.AUTO_RENEWAL_DONE);

                modSet.add(CertRecord.ATTR_META_INFO, Modification.MOD_REPLACE, oldMeta);

                cr.modifyCertificateRecord(oldSerialNo, modSet);

                logger.info(CMS.getLogMessage("CMSCORE_CA_MARK_SERIAL", oldSerialNo.toString(16), newSerialNo.toString(16)));

                if (logger.isDebugEnabled()) {
                    CertRecord check = cr.readCertificateRecord(oldSerialNo);
                    MetaInfo meta = check.getMetaInfo();

                    Enumeration<String> n = oldMeta.getElements();

                    while (n.hasMoreElements()) {
                        String name = n.nextElement();
                    }
                }
            }

        } catch (EBaseException e) {
            String message = CMS.getLogMessage("CMSCORE_CA_NO_STORE_SERIAL", cert.getSerialNumber().toString(16));
            logger.error(message, e);
            throw e;
        }
    }

    /**
     * revoke cert, check fields in crlentry, etc.
     */
    public void revokeCert(RevokedCertImpl crlentry)
            throws EBaseException {
        revokeCert(crlentry, null);
    }

    public void revokeCert(RevokedCertImpl crlentry, String requestId)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        final String method = "CAService.revokeCert";
        BigInteger serialno = crlentry.getSerialNumber();
        Date revdate = crlentry.getRevocationDate();
        CRLExtensions crlentryexts = crlentry.getExtensions();
        String msg = "";

        logger.debug(method + ": begins: serial:" + serialno.toString());

        // Get the revocation reason
        Enumeration<Extension> enum1 = crlentryexts.getElements();
        RevocationReason revReason = null;
        while (enum1.hasMoreElements()) {
            Extension ext = enum1.nextElement();
            if (ext instanceof CRLReasonExtension) {
                revReason = ((CRLReasonExtension) ext).getReason();
                break;
            }
        }
        if (revReason == null) {
            logger.error(method + ":" + CMS.getLogMessage("CMSCORE_CA_MISSING_REV_REASON", serialno.toString(16)));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_MISSING_REV_REASON",
                            "0x" + serialno.toString(16)));
        }

        logger.debug(method + ": revocaton request revocation reason: " + revReason.toString());
        CertRecord certRec = cr.readCertificateRecord(serialno);

        if (certRec == null) {
            logger.error(method + ": " + CMS.getLogMessage("CMSCORE_CA_CERT_NOT_FOUND", serialno.toString(16)));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                            "0x" + serialno.toString(16)));
        }

        // allow revoking certs that are on hold.
        String certStatus = certRec.getStatus();

        RevocationReason recRevReason = null;
        if (certStatus.equals(CertRecord.STATUS_REVOKED)) {
            try {
                recRevReason = certRec.getRevReason();
            } catch (Exception e) {
                throw new EBaseException(e);
            }
            if (recRevReason == null) {
                msg = "existing revoked cert missing revocation reason";
                logger.error(method + ": " + msg);
                throw new EBaseException(msg);
            }
            logger.debug(method + ": already revoked cert with existing revocation reason:" + recRevReason.toString());
        }

        // for cert already revoked, also check whether revocation reason is changed from SUPERSEDED to KEY_COMPROMISE
        if (((certStatus.equals(CertRecord.STATUS_REVOKED) &&
                !certRec.isCertOnHold()) &&
                ((recRevReason != RevocationReason.SUPERSEDED) ||
                        revReason != RevocationReason.KEY_COMPROMISE))
                ||
                certStatus.equals(CertRecord.STATUS_REVOKED_EXPIRED)) {
            logger.debug(method + ": cert already revoked:" +
                    serialno.toString());
            throw new ECAException(CMS.getUserMessage("CMS_CA_CERT_ALREADY_REVOKED",
                    "0x" + Long.toHexString(serialno.longValue())));
        }

        try {
            // if cert has already revoked, update the revocation info only
            logger.debug(method + ": about to call markAsRevoked");
            if (certStatus.equals(CertRecord.STATUS_REVOKED)) {
                cr.markAsRevoked(serialno,
                        new RevocationInfo(revdate, crlentryexts),
                        true /*isAlreadyRevoked*/);

                logger.debug(method + ": Already-revoked cert marked revoked");

                logger.info(CMS.getLogMessage("CMSCORE_CA_CERT_REVO_INFO_UPDATE",
                                recRevReason.toString(),
                                revReason.toString(),
                                serialno.toString(16)));
            } else {
                cr.markAsRevoked(serialno,
                        new RevocationInfo(revdate, crlentryexts));
            }

            logger.info(CMS.getLogMessage("CMSCORE_CA_CERT_REVOKED",
                    serialno.toString(16)));

            // inform all CRLIssuingPoints about revoked certificate

            for (ICRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
                if (ip != null) {
                    boolean b = true;

                    if (ip.isCACertsOnly()) {
                        X509CertImpl cert = certRec.getCertificate();

                        if (cert != null)
                            b = cert.getBasicConstraintsIsCA();
                    }
                    if (ip.isProfileCertsOnly()) {
                        MetaInfo metaInfo = certRec.getMetaInfo();
                        if (metaInfo != null) {
                            String profileId = (String) metaInfo.get("profileId");
                            if (profileId != null) {
                                b = ip.checkCurrentProfile(profileId);
                            }
                        }
                    }
                    if (b)
                        ip.addRevokedCert(serialno, crlentry, requestId);
                }
            }
        } catch (EBaseException e) {
            String message = CMS.getLogMessage("CMSCORE_CA_ERROR_REVOCATION", serialno.toString(), e.toString());
            logger.error(method + ":" + message, e);
            throw e;
        }
        return;
    }

    /**
     * unrevoke cert, check serial number, etc.
     */
    void unrevokeCert(BigInteger serialNo)
            throws EBaseException {
        unrevokeCert(serialNo, null);
    }

    void unrevokeCert(BigInteger serialNo, String requestId)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        CertRecord certRec = cr.readCertificateRecord(serialNo);

        if (certRec == null) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_NOT_FOUND", serialNo.toString(16)));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                            "0x" + serialNo.toString(16)));
        }
        RevocationInfo revInfo = (RevocationInfo) certRec.getRevocationInfo();
        CRLExtensions exts = null;
        CRLReasonExtension reasonext = null;

        if (revInfo == null) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_ON_HOLD", serialNo.toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_IS_NOT_ON_HOLD",
                    serialNo.toString()));
        }
        exts = revInfo.getCRLEntryExtensions();
        if (exts != null) {
            try {
                reasonext = (CRLReasonExtension)
                        exts.get(CRLReasonExtension.NAME);
            } catch (X509ExtensionException e) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_ON_HOLD", serialNo.toString()), e);
                throw new ECAException(CMS.getUserMessage("CMS_CA_IS_NOT_ON_HOLD",
                        serialNo.toString()), e);
            }
        } else {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_ON_HOLD", serialNo.toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_IS_NOT_ON_HOLD",
                    serialNo.toString()));
        }
        // allow unrevoking certs that are on hold.
        if ((certRec.getStatus().equals(CertRecord.STATUS_REVOKED) ||
                certRec.getStatus().equals(CertRecord.STATUS_REVOKED_EXPIRED)) &&
                reasonext != null &&
                reasonext.getReason() == RevocationReason.CERTIFICATE_HOLD) {
            try {
                cr.unmarkRevoked(serialNo, revInfo, certRec.getRevokedOn(), certRec.getRevokedBy());

                logger.info(CMS.getLogMessage("CMSCORE_CA_CERT_UNREVOKED", serialNo.toString(16)));

                // inform all CRLIssuingPoints about unrevoked certificate

                for (ICRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
                    if (ip != null) {
                        boolean b = true;

                        if (ip.isCACertsOnly()) {
                            X509CertImpl cert = certRec.getCertificate();

                            if (cert != null)
                                b = cert.getBasicConstraintsIsCA();
                        }
                        if (ip.isProfileCertsOnly()) {
                            MetaInfo metaInfo = certRec.getMetaInfo();
                            if (metaInfo != null) {
                                String profileId = (String) metaInfo.get("profileId");
                                if (profileId != null) {
                                    b = ip.checkCurrentProfile(profileId);
                                }
                            }
                        }
                        if (b)
                            ip.addUnrevokedCert(serialNo, requestId);
                    }
                }
            } catch (EBaseException e) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_ERROR_UNREVOKE", serialNo.toString(16)), e);
                throw e;
            }
        } else {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_ON_HOLD", serialNo.toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_IS_NOT_ON_HOLD",
                    "0x" + serialNo.toString(16)));
        }

        return;
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

    /**
     * Signed Audit Log Requester ID
     *
     * This method is called to obtain the "RequesterID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message RequesterID
     */
    private String auditRequesterID() {

        String requesterID = null;

        // Initialize requesterID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            requesterID = (String)
                    auditContext.get(SessionContext.REQUESTER_ID);

            if (requesterID != null) {
                requesterID = requesterID.trim();
            } else {
                requesterID = ILogger.UNIDENTIFIED;
            }
        } else {
            requesterID = ILogger.UNIDENTIFIED;
        }

        return requesterID;
    }
}

///
/// servant classes
///

interface IServant {
    public boolean service(IRequest request) throws EBaseException;
}

class serviceIssue implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(serviceIssue.class);

    private CAService mService;

    public serviceIssue(CAService service) {
        mService = service;
    }

    public boolean service(IRequest request)
            throws EBaseException {
        // XXX This is ugly. should associate attributes with
        // request types, not policy.
        // XXX how do we know what to look for in request ?

        if (request.getExtDataInCertInfoArray(IRequest.CERT_INFO) != null)
            return serviceX509(request);
        else
            return false; // Don't know what it is ?????
    }

    public boolean serviceX509(IRequest request)
            throws EBaseException {
        // XXX This is ugly. should associate attributes with
        // request types, not policy.
        // XXX how do we know what to look for in request ?
        X509CertInfo certinfos[] =
                request.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (certinfos == null || certinfos[0] == null) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_REQUEST_NOT_FOUND", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_ISSUEREQ"));
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        String challengePassword =
                request.getExtDataInString(CAService.CHALLENGE_PHRASE);

        X509CertImpl[] certs = new X509CertImpl[certinfos.length];
        String rid = request.getRequestId().toString();
        int i;

        for (i = 0; i < certinfos.length; i++) {
            try {
                certs[i] = mService.issueX509Cert(rid, certinfos[i]);
            } catch (EBaseException e) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_ISSUE_ERROR", Integer.toString(i), rid, e.toString()), e);
                throw e;
            }
        }
        String crmfReqId = request.getExtDataInString(IRequest.CRMF_REQID);
        EBaseException ex = null;

        for (i = 0; i < certs.length; i++) {
            try {
                mService.storeX509Cert(rid, certs[i], crmfReqId, challengePassword);
            } catch (EBaseException e) {
                String message = CMS.getLogMessage("CMSCORE_CA_STORE_ERROR", Integer.toString(i), rid, e.toString());
                logger.warn(message, e);
                ex = e; // save to throw later.
                break;
            }
        }
        if (ex != null) {
            for (int j = 0; j < i; j++) {
                // delete the stored cert records from the database.
                // we issue all or nothing.
                BigInteger serialNo =
                        ((X509Certificate) certs[i]).getSerialNumber();

                try {
                    cr.deleteCertificateRecord(serialNo);
                } catch (EBaseException e) {
                    logger.warn(CMS.getLogMessage("CMSCORE_CA_DELETE_CERT_ERROR", serialNo.toString(), e.toString()), e);
                }
            }
            throw ex;
        }

        request.setExtData(IRequest.ISSUED_CERTS, certs);

        return true;
    }
}

class serviceRenewal implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(serviceRenewal.class);

    private CAService mService;

    public serviceRenewal(CAService service) {
        mService = service;
    }

    public boolean service(IRequest request)
            throws EBaseException {
        // XXX if one fails should all fail ? - can't backtrack.
        X509CertInfo certinfos[] =
                request.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (certinfos == null || certinfos[0] == null) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_REQUEST_NOT_FOUND", request.getRequestId().toString()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        X509CertImpl issuedCerts[] = new X509CertImpl[certinfos.length];

        for (int j = 0; j < issuedCerts.length; j++)
            issuedCerts[j] = null;
        String svcerrors[] = new String[certinfos.length];

        for (int k = 0; k < svcerrors.length; k++)
            svcerrors[k] = null;
        String rid = request.getRequestId().toString();

        for (int i = 0; i < certinfos.length; i++) {
            try {
                // get old serial number.
                SerialNumber serialnum = null;

                try {
                    CertificateSerialNumber serialno = (CertificateSerialNumber)
                            certinfos[i].get(X509CertInfo.SERIAL_NUMBER);

                    if (serialno == null) {
                        logger.error(CMS.getLogMessage("CMSCORE_CA_NULL_SERIAL_NUMBER"));
                        throw new ECAException(
                                CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                    }
                    serialnum = (SerialNumber)
                            serialno.get(CertificateSerialNumber.NUMBER);

                } catch (IOException e) {
                    String message = CMS.getLogMessage("CMSCORE_CA_ERROR_GET_CERT", e.toString());
                    logger.error(message, e);
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));

                } catch (CertificateException e) {
                    String message = CMS.getLogMessage("CMSCORE_CA_ERROR_GET_CERT", e.toString());
                    logger.error(message, e);
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }

                if (serialnum == null) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_ERROR_GET_CERT", ""));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }
                BigInt serialnumBigInt = serialnum.getNumber();
                BigInteger oldSerialNo = serialnumBigInt.toBigInteger();

                // get cert record
                CertRecord certRecord = cr.readCertificateRecord(oldSerialNo);

                if (certRecord == null) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_NOT_FROM_CA", oldSerialNo.toString()));
                    svcerrors[i] = new ECAException(
                            CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                                    oldSerialNo.toString())).toString();
                    continue;
                }

                // check if cert has been revoked.
                String certStatus = certRecord.getStatus();

                if (certStatus.equals(CertRecord.STATUS_REVOKED) ||
                        certStatus.equals(CertRecord.STATUS_REVOKED_EXPIRED)) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_RENEW_REVOKED", oldSerialNo.toString()));
                    svcerrors[i] = new ECAException(
                            CMS.getUserMessage("CMS_CA_CANNOT_RENEW_REVOKED_CERT",
                                    "0x" + oldSerialNo.toString(16))).toString();
                    continue;
                }

                // check if cert has already been renewed.
                MetaInfo metaInfo = certRecord.getMetaInfo();

                if (metaInfo != null) {
                    String renewed = (String) metaInfo.get(CertRecord.META_RENEWED_CERT);

                    if (renewed != null) {
                        BigInteger serial = new BigInteger(renewed);
                        X509CertImpl cert = cr.getX509Certificate(serial);

                        if (cert == null) {
                            // something wrong
                            logger.error(CMS.getLogMessage("CMSCORE_CA_MISSING_RENEWED", serial.toString()));
                            svcerrors[i] = new ECAException(
                                    CMS.getUserMessage("CMS_CA_ERROR_GETTING_RENEWED_CERT",
                                            oldSerialNo.toString(), serial.toString())).toString();
                            continue;
                        }
                        // get cert record
                        CertRecord cRecord = cr.readCertificateRecord(serial);

                        if (cRecord == null) {
                            logger.error(CMS.getLogMessage("CMSCORE_CA_NOT_FROM_CA", serial.toString()));
                            svcerrors[i] = new ECAException(
                                    CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                                            serial.toString())).toString();
                            continue;
                        }
                        // Check renewed certificate already REVOKED or EXPIRED
                        String status = cRecord.getStatus();

                        if (status.equals(CertRecord.STATUS_REVOKED) ||
                                status.equals(CertRecord.STATUS_REVOKED_EXPIRED)) {
                            logger.debug("It is already revoked or Expired !!!");
                        } // it is still new ... So just return this certificate to user
                        else {
                            logger.debug("It is still new !!!");
                            issuedCerts[i] = cert;
                            continue;
                        }
                    }
                }

                // issue the cert.
                issuedCerts[i] =
                        mService.issueX509Cert(rid, certinfos[i], true, oldSerialNo);
                mService.storeX509Cert(rid, issuedCerts[i], true, oldSerialNo);
            } catch (ECAException e) {
                svcerrors[i] = e.toString();
                logger.warn(CMS.getLogMessage("CMSCORE_CA_CANNOT_RENEW", Integer.toString(i), request
                        .getRequestId().toString()), e);
            }
        }

        // always set issued certs regardless of error.
        request.setExtData(IRequest.ISSUED_CERTS, issuedCerts);

        // set and throw error if any.
        int l;

        for (l = svcerrors.length - 1; l >= 0 && svcerrors[l] == null; l--)
            ;
        if (l >= 0) {
            request.setExtData(IRequest.SVCERRORS, svcerrors);
            logger.error(CMS.getLogMessage("CMSCORE_CA_NO_RENEW", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_RENEW_FAILED"));
        }
        return true;
    }
}

class getCertsForChallenge implements IServant {

    public getCertsForChallenge(CAService service) {
    }

    public boolean service(IRequest request)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        BigInteger[] serialNoArray =
                request.getExtDataInBigIntegerArray(CAService.SERIALNO_ARRAY);
        if (serialNoArray == null) {
            throw new ECAException(CMS.getLogMessage("CMS_CA_MISSING_SERIAL_NUMBER"));
        }
        X509CertImpl[] certs = new X509CertImpl[serialNoArray.length];

        for (int i = 0; i < serialNoArray.length; i++) {
            certs[i] = cr.getX509Certificate(serialNoArray[i]);
        }
        request.setExtData(IRequest.OLD_CERTS, certs);
        return true;
    }
}

class getCertStatus implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(getCertStatus.class);

    private ICertificateAuthority mCA;
    private CAService mService;

    public getCertStatus(CAService service) {
        mService = service;
        mCA = mService.getCA();
    }

    public boolean service(IRequest request) throws EBaseException {
        BigInteger serialno = request.getExtDataInBigInteger("serialNumber");
        String issuerDN = request.getExtDataInString("issuerDN");

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certDB = engine.getCertificateRepository();

        String status = null;

        if (serialno != null) {
            CertRecord record = null;

            try {
                record = certDB.readCertificateRecord(serialno);
            } catch (EBaseException ee) {
                logger.warn(ee.toString());
            }

            if (record != null) {
                status = record.getStatus();
                if (status.equals("VALID")) {
                    X509CertImpl cacert = mCA.getCACert();
                    Principal p = cacert.getSubjectDN();

                    if (!p.toString().equals(issuerDN)) {
                        status = "INVALIDCERTROOT";
                    }
                }
            }
        }

        request.setExtData(IRequest.CERT_STATUS, status);
        return true;
    }
}

class serviceCheckChallenge implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(serviceCheckChallenge.class);

    private MessageDigest mSHADigest = null;

    public serviceCheckChallenge(CAService service) {
        try {
            mSHADigest = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            logger.warn(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
        }
    }

    public boolean service(IRequest request)
            throws EBaseException {
        // note: some request attributes used below are set in
        // authentication/ChallengePhraseAuthentication.java :(
        BigInteger serialno = request.getExtDataInBigInteger("serialNumber");
        String pwd = request.getExtDataInString(
                CAService.CHALLENGE_PHRASE);

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certDB = engine.getCertificateRepository();

        BigInteger[] bigIntArray = null;

        if (serialno != null) {
            CertRecord record = null;

            try {
                record = certDB.readCertificateRecord(serialno);
            } catch (EBaseException ee) {
                logger.warn(ee.toString());
            }
            if (record != null) {
                String status = record.getStatus();

                if (status.equals("VALID")) {
                    boolean samepwd = compareChallengePassword(record, pwd);

                    if (samepwd) {
                        bigIntArray = new BigInteger[1];
                        bigIntArray[0] = record.getSerialNumber();
                    }
                } else {
                    bigIntArray = new BigInteger[0];
                }
            } else
                bigIntArray = new BigInteger[0];
        } else {
            String subjectName = request.getExtDataInString("subjectName");

            if (subjectName != null) {
                String filter = "(&(x509cert.subject=" + subjectName + ")(certStatus=VALID))";
                CertRecordList list = certDB.findCertRecordsInList(filter, null, 10);
                int size = list.getSize();
                Enumeration<CertRecord> en = list.getCertRecords(0, size - 1);

                if (!en.hasMoreElements()) {
                    bigIntArray = new BigInteger[0];
                } else {
                    Vector<BigInteger> idv = new Vector<BigInteger>();

                    while (en.hasMoreElements()) {
                        CertRecord record = en.nextElement();
                        boolean samepwd = compareChallengePassword(record, pwd);

                        if (samepwd) {
                            BigInteger id = record.getSerialNumber();

                            idv.addElement(id);
                        }
                    }
                    bigIntArray = new BigInteger[idv.size()];
                    idv.copyInto(bigIntArray);
                }
            }
        }

        if (bigIntArray == null)
            bigIntArray = new BigInteger[0];

        request.setExtData(CAService.SERIALNO_ARRAY, bigIntArray);
        return true;
    }

    private boolean compareChallengePassword(CertRecord record, String pwd)
            throws EBaseException {
        MetaInfo metaInfo = (MetaInfo) record.get(CertRecord.ATTR_META_INFO);

        if (metaInfo == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "metaInfo"));
        }

        String hashpwd = hashPassword(pwd);

        // got metaInfo
        String challengeString =
                (String) metaInfo.get(CertRecord.META_CHALLENGE_PHRASE);

        if (!challengeString.equals(hashpwd)) {
            return false;
        } else
            return true;
    }

    private String hashPassword(String pwd) {
        String salt = "lala123";
        byte[] pwdDigest = mSHADigest.digest((salt + pwd).getBytes());
        String b64E = Utils.base64encode(pwdDigest, true);

        return "{SHA}" + b64E;
    }
}

class serviceRevoke implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(serviceRevoke.class);

    private CAService mService;

    public serviceRevoke(CAService service) {
        mService = service;
    }

    public boolean service(IRequest request)
            throws EBaseException {
        boolean sendStatus = true;
        // XXX Need to think passing as array.
        // XXX every implemented according to servlet.
        RevokedCertImpl crlentries[] =
                request.getExtDataInRevokedCertArray(IRequest.CERT_INFO);

        if (crlentries == null ||
                crlentries.length == 0 ||
                crlentries[0] == null) {
            // XXX should this be an error ?
            logger.error(CMS.getLogMessage("CMSCORE_CA_CRL_NOT_FOUND", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_REVREQ"));
        }

        RevokedCertImpl revokedCerts[] =
                new RevokedCertImpl[crlentries.length];
        String svcerrors[] = null;

        for (int i = 0; i < crlentries.length; i++) {
            try {
                mService.revokeCert(crlentries[i], request.getRequestId().toString());
                revokedCerts[i] = crlentries[i];
            } catch (ECAException e) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_CANNOT_REVOKE", Integer.toString(i), request
                        .getRequestId().toString(), e.toString()), e);
                revokedCerts[i] = null;
                if (svcerrors == null) {
                    svcerrors = new String[revokedCerts.length];
                }
                svcerrors[i] = e.toString();
            }
        }

        // #605941 - request.get(IRequest.CERT_INFO) store exact same thing
        // request.set(IRequest.REVOKED_CERTS, revokedCerts);

        // if clone ca, send revoked cert records to CLA
        if (CAService.mCLAConnector != null) {
            logger.debug(CMS.getLogMessage("CMSCORE_CA_CLONE_READ_REVOKED"));
            BigInteger revokedCertIds[] =
                    new BigInteger[revokedCerts.length];

            for (int i = 0; i < revokedCerts.length; i++) {
                revokedCertIds[i] = revokedCerts[i].getSerialNumber();
            }
            request.deleteExtData(IRequest.CERT_INFO);
            request.deleteExtData(IRequest.OLD_CERTS);
            request.setExtData(IRequest.REVOKED_CERT_RECORDS, revokedCertIds);

            logger.debug(CMS.getLogMessage("CMSCORE_CA_CLONE_READ_REVOKED_CONNECTOR"));

            request.setRequestType(IRequest.CLA_CERT4CRL_REQUEST);
            sendStatus = CAService.mCLAConnector.send(request);
            if (sendStatus == false) {
                request.setExtData(IRequest.RESULT,
                        IRequest.RES_ERROR);
                request.setExtData(IRequest.ERROR,
                        new ECAException(CMS.getUserMessage("CMS_CA_SEND_CLA_REQUEST")));
                return sendStatus;
            } else {
                if (request.getExtDataInString(IRequest.ERROR) != null) {
                    request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
                    request.deleteExtData(IRequest.ERROR);
                }
            }
            if (request.getExtDataInString(IRequest.ERROR) != null) {
                return sendStatus;
            }
        }

        if (svcerrors != null) {
            request.setExtData(IRequest.SVCERRORS, svcerrors);
            throw new ECAException(CMS.getUserMessage("CMS_CA_REVOKE_FAILED"));
        }

        logger.debug("serviceRevoke sendStatus=" + sendStatus);

        return sendStatus;
    }
}

class serviceUnrevoke implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(serviceUnrevoke.class);

    private CAService mService;

    public serviceUnrevoke(CAService service) {
        mService = service;
    }

    public boolean service(IRequest request)
            throws EBaseException {
        boolean sendStatus = true;
        BigInteger oldSerialNo[] =
                request.getExtDataInBigIntegerArray(IRequest.OLD_SERIALS);

        if (oldSerialNo == null || oldSerialNo.length < 1) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_UNREVOKE_MISSING_SERIAL"));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_MISSING_SERIAL_NUMBER"));
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        String svcerrors[] = null;
        boolean needOldCerts = false;
        X509CertImpl oldCerts[] = request.getExtDataInCertArray(IRequest.OLD_CERTS);

        if (oldCerts == null || oldCerts.length < 1) {
            needOldCerts = true;
            oldCerts = new X509CertImpl[oldSerialNo.length];
        }

        for (int i = 0; i < oldSerialNo.length; i++) {
            try {
                if (oldSerialNo[i].compareTo(new BigInteger("0")) < 0) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_UNREVOKE_MISSING_SERIAL"));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_SERIAL_NUMBER"));
                }
                if (needOldCerts) {
                    CertRecord certRec = cr.readCertificateRecord(oldSerialNo[i]);

                    oldCerts[i] = certRec.getCertificate();
                }
                mService.unrevokeCert(oldSerialNo[i], request.getRequestId().toString());
            } catch (ECAException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_UNREVOKE_FAILED", oldSerialNo[i].toString(),
                        request.getRequestId().toString()), e);
                if (svcerrors == null) {
                    svcerrors = new String[oldSerialNo.length];
                }
                svcerrors[i] = e.toString();
            }
        }

        // if clone ca, send unrevoked cert serials to CLA
        if (CAService.mCLAConnector != null) {
            request.setRequestType(IRequest.CLA_UNCERT4CRL_REQUEST);
            sendStatus = CAService.mCLAConnector.send(request);
            if (sendStatus == false) {
                request.setExtData(IRequest.RESULT,
                        IRequest.RES_ERROR);
                request.setExtData(IRequest.ERROR,
                        new ECAException(CMS.getUserMessage("CMS_CA_SEND_CLA_REQUEST")));
                return sendStatus;
            } else {
                if (request.getExtDataInString(IRequest.ERROR) != null) {
                    request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
                    request.deleteExtData(IRequest.ERROR);
                }
            }

        }

        if (needOldCerts) {
            request.setExtData(IRequest.OLD_CERTS, oldCerts);
        }

        if (svcerrors != null) {
            request.setExtData(IRequest.SVCERRORS, svcerrors);
            throw new ECAException(CMS.getUserMessage("CMS_CA_UNREVOKE_FAILED"));
        }

        return sendStatus;
    }
}

class serviceGetCAChain implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(serviceGetCAChain.class);

    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceGetCAChain(CAService service) {
        mService = service;
        mCA = mService.getCA();
    }

    public boolean service(IRequest request) throws EBaseException {
        CertificateChain certChain = mCA.getCACertChain();
        ByteArrayOutputStream certChainOut = new ByteArrayOutputStream();
        try {
            certChain.encode(certChainOut);
        } catch (IOException e) {
            logger.error(e.toString(), e);
            throw new EBaseException(e.toString(), e);
        }
        request.setExtData(IRequest.CACERTCHAIN, certChainOut.toByteArray());
        return true;
    }
}

class serviceGetCRL implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(serviceGetCRL.class);

    public serviceGetCRL(CAService service) {
    }

    public boolean service(IRequest request)
            throws EBaseException {
        try {
            CAEngine engine = CAEngine.getInstance();
            CRLRepository crlRepository = engine.getCRLRepository();

            ICRLIssuingPointRecord crlRec = crlRepository.readCRLIssuingPointRecord(ICertificateAuthority.PROP_MASTER_CRL);
            X509CRLImpl crl = new X509CRLImpl(crlRec.getCRL());

            request.setExtData(IRequest.CRL, crl.getEncoded());

        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_GETCRL_FIND_CRL"), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CRL_ISSUEPT_NOT_FOUND", e.toString()), e);

        } catch (CRLException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_GETCRL_INST_CRL", ICertificateAuthority.PROP_MASTER_CRL), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CRL_ISSUEPT_NOGOOD", ICertificateAuthority.PROP_MASTER_CRL), e);

        } catch (X509ExtensionException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_GETCRL_NO_ISSUING_REC"), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CRL_ISSUEPT_EXT_NOGOOD",
                            ICertificateAuthority.PROP_MASTER_CRL), e);
        }
        return true;
    }
}

class serviceGetRevocationInfo implements IServant {

    public serviceGetRevocationInfo(CAService service) {
    }

    public boolean service(IRequest request)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certDB = engine.getCertificateRepository();

        Enumeration<String> enum1 = request.getExtDataKeys();

        while (enum1.hasMoreElements()) {
            String name = enum1.nextElement();
            RevocationInfo info = null;
            if (name.equals(IRequest.ISSUED_CERTS)) {
                X509CertImpl certsToCheck[] =
                        request.getExtDataInCertArray(IRequest.ISSUED_CERTS);
                if (certsToCheck != null) {
                    info = certDB.isCertificateRevoked(certsToCheck[0]);
                }
                if (info != null) {
                    RevokedCertImpl revokedCerts[] = new RevokedCertImpl[1];
                    RevokedCertImpl revokedCert = new RevokedCertImpl(
                            certsToCheck[0].getSerialNumber(),
                            info.getRevocationDate(),
                            info.getCRLEntryExtensions());

                    revokedCerts[0] = revokedCert;
                    request.setExtData(IRequest.REVOKED_CERTS, revokedCerts);
                }
            }
        }
        return true;
    }
}

class serviceGetCertificates implements IServant {

    public serviceGetCertificates(CAService service) {
    }

    public boolean service(IRequest request)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certDB = engine.getCertificateRepository();

        Enumeration<String> enum1 = request.getExtDataKeys();

        while (enum1.hasMoreElements()) {
            String name = enum1.nextElement();

            if (name.equals(IRequest.CERT_FILTER)) {
                String filter = request.getExtDataInString(IRequest.CERT_FILTER);
                X509CertImpl[] certs = certDB.getX509Certificates(filter);

                if (certs != null) {
                    request.setExtData(IRequest.OLD_CERTS, certs);
                }
            }
        }
        return true;
    }
}

class serviceCert4Crl implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(serviceCert4Crl.class);

    public serviceCert4Crl(CAService service) {
    }

    public boolean service(IRequest request)
            throws EBaseException {
        // XXX Need to think passing as array.
        // XXX every implemented according to servlet.
        BigInteger revokedCertIds[] = request.getExtDataInBigIntegerArray(
                IRequest.REVOKED_CERT_RECORDS);
        if (revokedCertIds == null ||
                revokedCertIds.length == 0) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT4CRL_NO_ENTRY", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_CLAREQ"));
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        CertRecord revokedCertRecs[] = new CertRecord[revokedCertIds.length];
        for (int i = 0; i < revokedCertIds.length; i++) {
            revokedCertRecs[i] = cr.readCertificateRecord(revokedCertIds[i]);
        }

        if (revokedCertRecs == null ||
                revokedCertRecs.length == 0 ||
                revokedCertRecs[0] == null) {
            // XXX should this be an error ?
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT4CRL_NO_ENTRY", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_CLAREQ"));
        }

        CertRecord recordedCerts[] =
                new CertRecord[revokedCertRecs.length];
        String svcerrors[] = null;

        for (int i = 0; i < revokedCertRecs.length; i++) {
            try {
                // for CLA, record it into cert repost
                cr.addRevokedCertRecord(revokedCertRecs[i]);
                //				mService.revokeCert(crlentries[i]);
                recordedCerts[i] = revokedCertRecs[i];

                // inform all CRLIssuingPoints about revoked certificate

                for (ICRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
                    // form RevokedCertImpl
                    RevokedCertImpl rci =
                            new RevokedCertImpl(revokedCertRecs[i].getSerialNumber(),
                                    revokedCertRecs[i].getRevokedOn());

                    if (ip != null) {
                        ip.addRevokedCert(revokedCertRecs[i].getSerialNumber(), rci);
                    }
                }

            } catch (ECAException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_CERT4CRL_NO_REC", Integer.toString(i),
                        request.getRequestId().toString(), e.toString()), e);
                recordedCerts[i] = null;
                if (svcerrors == null) {
                    svcerrors = new String[recordedCerts.length];
                }
                svcerrors[i] = e.toString();
            }
        }
        //need to record which gets recorded and which failed...cfu
        //		request.set(IRequest.REVOKED_CERTS, revokedCerts);
        if (svcerrors != null) {
            request.setExtData(IRequest.SVCERRORS, svcerrors);
            throw new ECAException(CMS.getUserMessage("CMS_CA_CERT4CRL_FAILED"));
        }

        return true;
    }
}

class serviceUnCert4Crl implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(serviceUnCert4Crl.class);

    public serviceUnCert4Crl(CAService service) {
    }

    public boolean service(IRequest request)
            throws EBaseException {
        BigInteger oldSerialNo[] =
                request.getExtDataInBigIntegerArray(IRequest.OLD_SERIALS);

        if (oldSerialNo == null || oldSerialNo.length < 1) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_UNREVOKE_MISSING_SERIAL"));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_MISSING_SERIAL_NUMBER"));
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        String svcerrors[] = null;

        for (int i = 0; i < oldSerialNo.length; i++) {
            try {
                cr.deleteCertificateRecord(oldSerialNo[i]);

                // inform all CRLIssuingPoints about unrevoked certificate

                for (ICRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
                    if (ip != null) {
                        ip.addUnrevokedCert(oldSerialNo[i]);
                    }
                }
            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_DELETE_CERT_ERROR", oldSerialNo[i].toString(), e.toString()), e);
                if (svcerrors == null) {
                    svcerrors = new String[oldSerialNo.length];
                }
                svcerrors[i] = e.toString();
            }

        }

        if (svcerrors != null) {
            request.setExtData(IRequest.SVCERRORS, svcerrors);
            throw new ECAException(CMS.getUserMessage("CMS_CA_UNCERT4CRL_FAILED"));
        }

        return true;
    }
}
