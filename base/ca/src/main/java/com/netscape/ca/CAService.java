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

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import org.dogtagpki.ct.CTEngine;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.extensions.CertInfo;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
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
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.connector.Connector;
import com.netscape.certsrv.connector.ConnectorConfig;
import com.netscape.certsrv.connector.ConnectorsConfig;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.SecurityDataArchivalRequestEvent;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.connector.HttpConnector;
import com.netscape.cmscore.connector.LocalConnector;
import com.netscape.cmscore.connector.RemoteAuthority;
import com.netscape.cmscore.crmf.CRMFParser;
import com.netscape.cmscore.crmf.PKIArchiveOptionsContainer;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Request Service for CertificateAuthority.
 */
public class CAService implements IService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAService.class);

    public static final String CRMF_REQUEST = "CRMFRequest";
    public static final String CHALLENGE_PHRASE = "challengePhrase";
    public static final String SERIALNO_ARRAY = "serialNoArray";

    // CCA->CLA connector
    protected static Connector mCLAConnector = null;

    private Hashtable<String, IServant> mServants = new Hashtable<>();
    private Connector mKRAConnector = null;
    private ConnectorsConfig connectorsConfig;
    private boolean mArchivalRequired = true;

    public CAService() {

        // init services.
        mServants.put(
                Request.ENROLLMENT_REQUEST,
                new ServiceIssue(this));
        mServants.put(
                Request.RENEWAL_REQUEST,
                new ServiceRenewal(this));
        mServants.put(
                Request.REVOCATION_REQUEST,
                new ServiceRevoke(this));
        mServants.put(
                Request.CMCREVOKE_REQUEST,
                new ServiceRevoke(this));
        mServants.put(
                Request.REVOCATION_CHECK_CHALLENGE_REQUEST,
                new ServiceCheckChallenge(this));
        mServants.put(
                Request.GETCERTS_FOR_CHALLENGE_REQUEST,
                new GetCertsForChallenge(this));
        mServants.put(
                Request.UNREVOCATION_REQUEST,
                new ServiceUnrevoke(this));
        mServants.put(
                Request.GETCACHAIN_REQUEST,
                new ServiceGetCAChain());
        mServants.put(
                Request.GETCRL_REQUEST,
                new ServiceGetCRL(this));
        mServants.put(
                Request.GETREVOCATIONINFO_REQUEST,
                new ServiceGetRevocationInfo(this));
        mServants.put(
                Request.GETCERTS_REQUEST,
                new ServiceGetCertificates(this));
        mServants.put(
                Request.CLA_CERT4CRL_REQUEST,
                new ServiceCert4Crl(this));
        mServants.put(
                Request.CLA_UNCERT4CRL_REQUEST,
                new ServiceUnCert4Crl(this));
        mServants.put(
                Request.GETCERT_STATUS_REQUEST,
                new GetCertStatus());
    }

    public void init(ConnectorsConfig connectorsConfig) throws EBaseException {
        this.connectorsConfig = connectorsConfig;

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
        ConnectorConfig kraConfig = connectorsConfig.getConnectorConfig("KRA");

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
        ConnectorConfig claConfig = connectorsConfig.getConnectorConfig("CLA");

        if (claConfig != null) {
            mCLAConnector = getConnector(claConfig);
            if (mCLAConnector != null) {
                logger.debug(CMS.getLogMessage("CMSCORE_CA_START_CONNECTOR"));
                logger.info("Started CLA Connector in CCA");
                mCLAConnector.start();
            }
        }
    }

    /**
     * Returns KRA-CA connector.
     *
     * @return KRA-CA connector
     */
    public Connector getKRAConnector() {
        return mKRAConnector;
    }

    public void setKRAConnector(Connector c) {
        mKRAConnector = c;
    }

    public Connector getConnector(ConnectorConfig config) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        Connector connector = null;

        if (config == null || config.size() <= 0) {
            return null;
        }
        boolean enable = config.getEnable();
        // provide a way to register a 3rd connector into RA
        String extConnector = config.getClassName();

        if (extConnector != null) {
            try {
                connector = (Connector) Class.forName(extConnector).getDeclaredConstructor().newInstance();
                connector.setCMSEngine(engine);
                connector.init();
                // connector.start() will be called later on
                return connector;

            } catch (Exception e) {
                // ignore external class if error
                logger.warn(CMS.getLogMessage("CMSCORE_CA_LOAD_CONNECTOR", extConnector, e.toString()), e);
            }
        }

        if (!enable)
            return null;
        boolean local = config.getLocal();
        IAuthority authority = null;

        if (local) {
            String id = config.getID();

            authority = (IAuthority) engine.getSubsystem(id);
            if (authority == null) {
                String msg = "local authority " + id + " not found.";

                logger.error(CMS.getLogMessage("CMSCORE_CA_AUTHORITY_NOT_FOUND", id));
                throw new EBaseException(msg);
            }
            connector = new LocalConnector(authority);
            connector.setCMSEngine(engine);
            connector.init();
            // logger.info("local Connector to "+id+" inited");

        } else {
            String host = config.getHost();
            int port = config.getPort();
            String uri = config.getURI();

            // Use client cert specified in KRA connector
            String nickname = config.getNickname();
            if (nickname == null) {
                // Use subsystem cert as client cert
                nickname = cs.getString("ca.subsystem.nickname");

                String tokenname = cs.getString("ca.subsystem.tokenname", "");
                if (!CryptoUtil.isInternalToken(tokenname)) nickname = tokenname + ":" + nickname;
            }

            int resendInterval = config.getResendInterval();
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

            String clientCiphers = config.getClientCiphers();
            if (timeout == 0) {
                connector = new HttpConnector(nickname, clientCiphers, remauthority, resendInterval,
                        config);
            } else {
                connector =
                        new HttpConnector(nickname, clientCiphers, remauthority, resendInterval,
                                config, timeout);
            }

            connector.setCMSEngine(engine);
            connector.init();
            // Change end

            // logger.info("remote authority " + host+":"+port+" "+uri+" inited");
        }
        return connector;
    }

    public boolean isProfileRequest(Request request) {
        String profileId = request.getExtDataInString(Request.PROFILE_ID);
        return !(profileId == null || profileId.equals(""));
    }

    /**
     * Services profile request.
     *
     * @param request profile enrollment request information
     * @exception EBaseException failed to service profile enrollment request
     */
    public void serviceProfileRequest(Request request)
            throws EBaseException {
        logger.debug("CAService: serviceProfileRequest requestId=" +
                request.getRequestId().toString());

        String profileId = request.getExtDataInString(Request.PROFILE_ID);

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
    @Override
    public boolean serviceRequest(Request request) {

        CAEngine engine = CAEngine.getInstance();

        Auditor auditor = engine.getAuditor();
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
                request.setExtData(Request.RESULT, Request.RES_SUCCESS);
                logger.debug("CAService: x1 requestStatus=" + request.getRequestStatus().toString());

                return true;
            } catch (EBaseException e) {
                logger.debug("CAService: x2 requestStatus=" + request.getRequestStatus().toString());
                // need to put error into the request
                logger.debug("CAService: serviceRequest " + e.toString());
                request.setExtData(Request.RESULT, Request.RES_ERROR);
                request.setExtData(Request.ERROR, e.toString());

                // TODO(alee) New audit message needed here

                return false;
            }
        }

        String type = request.getRequestType();
        IServant servant = mServants.get(type);

        if (servant == null) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_INVALID_REQUEST_TYPE", type));
            request.setExtData(Request.RESULT, Request.RES_ERROR);
            request.setExtData(Request.ERROR,
                    new ECAException(CMS.getUserMessage("CMS_CA_UNRECOGNIZED_REQUEST_TYPE", type)));

            return true;
        }

        // NOTE to alee: The request must include the realm by this point.

        try {
            // send request to KRA first
            if (type.equals(Request.ENROLLMENT_REQUEST) &&
                    isPKIArchiveOptionPresent(request) && mKRAConnector != null) {

                logger.debug("CAService: Sending enrollment request to KRA");

                auditor.log(SecurityDataArchivalRequestEvent.createSuccessEvent(
                        auditSubjectID,
                        auditRequesterID,
                        requestId,
                        null));

                boolean sendStatus = mKRAConnector.send(request);

                if (mArchivalRequired) {
                    if (!sendStatus) {
                        String message = CMS.getUserMessage("CMS_CA_SEND_KRA_REQUEST");
                        request.setExtData(Request.RESULT,
                                Request.RES_ERROR);
                        request.setExtData(Request.ERROR, new ECAException(message));

                        auditor.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                                auditSubjectID,
                                auditRequesterID,
                                requestId,
                                null,
                                message));

                        return true;
                    }
                    if (request.getExtDataInString(Request.ERROR) != null) {
                        request.setExtData(Request.RESULT, Request.RES_SUCCESS);
                        request.deleteExtData(Request.ERROR);
                    }

                    String message = request.getExtDataInString(Request.ERROR);
                    if (message != null) {

                        auditor.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                                auditSubjectID,
                                auditRequesterID,
                                requestId,
                                null,
                                message));

                        return true;
                    }
                }
            } else {
                logger.debug("*** NOT Send to KRA type=" + type + " ENROLLMENT=" + Request.ENROLLMENT_REQUEST);
            }

            completed = servant.service(request);
            request.setExtData(Request.RESULT, Request.RES_SUCCESS);
        } catch (EBaseException e) {
            request.setExtData(Request.RESULT, Request.RES_ERROR);
            request.setExtData(Request.ERROR, e);

            if (!(type.equals(Request.REVOCATION_REQUEST) ||
                    type.equals(Request.UNREVOCATION_REQUEST) || type.equals(Request.CMCREVOKE_REQUEST))) {

                auditor.log(SecurityDataArchivalRequestEvent.createFailureEvent(
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

        if (!(type.equals(Request.REVOCATION_REQUEST) ||
                type.equals(Request.UNREVOCATION_REQUEST) || type.equals(Request.CMCREVOKE_REQUEST))) {

            auditor.log(SecurityDataArchivalRequestEvent.createSuccessEvent(
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
    private boolean isPKIArchiveOptionPresent(Request request) {
        String crmfBlob = request.getExtDataInString(
                Request.HTTP_PARAMS, CRMF_REQUEST);

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
     * Issues certificate base on enrollment information,
     * creates certificate record, and stores all necessary data.
     *
     * @param aid CA ID
     * @param certi information obtain from revocation request
     * @param profileId Name of profile used
     * @param rid Request ID
     * @exception EBaseException failed to issue certificate or create certificate record
     */
    public X509CertImpl issueX509Cert(
            AuthorityID aid, X509CertInfo certi,
            String profileId, String rid)
            throws EBaseException {
        logger.debug("issueX509Cert");
        X509CertImpl certImpl = issueX509Cert(aid, rid, certi, false, null);

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

        CertificateAuthority hostCA = engine.getCA();
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new CANotFoundException("No such CA: " + aid);

        String algname = null;
        X509CertImpl cert = null;

        // NOTE:  In this implementation, the "oldSerialNo"
        //        parameter is NOT used!

        boolean doUTF8 = connectorsConfig.getBoolean("dnUTF8Encoding", false);

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
            CertificateValidity validity = (CertificateValidity) certi.get(X509CertInfo.VALIDITY);
            Date begin = null, end = null;

            if (validity != null) {
                logger.info("CAService: Using provided cert validity");
                begin = (Date) validity.get(CertificateValidity.NOT_BEFORE);
                end = (Date) validity.get(CertificateValidity.NOT_AFTER);
            }

            if (validity == null || begin.getTime() == 0 && end.getTime() == 0) {
                logger.info("CAService: Using default cert validity");
                begin = new Date();
                end = new Date(begin.getTime() + engine.getDefaultCertValidity());
                certi.set(CertificateValidity.NAME, new CertificateValidity(begin, end));
            }

            logger.info("CAService: - not before: " + begin);
            logger.info("CAService: - not after: " + end);

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

        if (doUTF8) {
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
        ctEngine.process(certi, hostCA, aid, algname);

        logger.debug("CAService: issueX509Cert: About to ca.sign cert.");
        cert = engine.sign(ca, certi, algname);
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
     * Marks certificate record as revoked by adding revocation information.
     * Updates CRL cache.
     *
     * @param crlentry revocation information obtained from revocation request
     * @exception EBaseException failed to mark certificate record as revoked
     */
    public void revokeCert(RevokedCertImpl crlentry)
            throws EBaseException {
        revokeCert(crlentry, null);
    }

    /**
     * Marks certificate record as revoked by adding revocation information.
     * Updates CRL cache.
     *
     * @param crlentry revocation information obtained from revocation request
     * @param requestId revocation request id
     * @exception EBaseException failed to mark certificate record as revoked
     */
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

            for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
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
        RevocationInfo revInfo = certRec.getRevocationInfo();
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

                for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
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
