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
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.apache.commons.net.ntp.TimeStamp;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICAService;
import org.dogtagpki.server.ca.ICRLIssuingPoint;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.extensions.CertInfo;
import org.mozilla.jss.netscape.security.util.BigInt;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
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
import com.netscape.certsrv.authority.ICertAuthority;
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
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertRecordList;
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
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.connector.HttpConnector;
import com.netscape.cmscore.connector.LocalConnector;
import com.netscape.cmscore.connector.RemoteAuthority;
import com.netscape.cmscore.crmf.CRMFParser;
import com.netscape.cmscore.crmf.PKIArchiveOptionsContainer;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.http.HttpClient;
import com.netscape.cmsutil.http.HttpRequest;
import com.netscape.cmsutil.http.HttpResponse;

/**
 * Request Service for CertificateAuthority.
 */
public class CAService implements ICAService, IService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAService.class);
    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public static final String CRMF_REQUEST = "CRMFRequest";
    public static final String CHALLENGE_PHRASE = "challengePhrase";
    public static final String SERIALNO_ARRAY = "serialNoArray";

    public static final String GoogleTestTube_Pub = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw8i8S7qiGEs9NXv0ZJFh6uuOmR2Q7dPprzk9XNNGkUXjzqx2SDvRfiwKYwBljfWujozHESVPQyydGaHhkaSz/g==";

    // CCA->CLA connector
    protected static IConnector mCLAConnector = null;

    private ICertificateAuthority mCA = null;
    private Hashtable<String, IServant> mServants = new Hashtable<String, IServant>();
    private IConnector mKRAConnector = null;
    private IConfigStore mConfig = null;
    private boolean mArchivalRequired = true;
    private Hashtable<String, ICRLIssuingPoint> mCRLIssuingPoints = new Hashtable<String, ICRLIssuingPoint>();

    public CAService(ICertificateAuthority ca) {
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

    protected ICertificateAuthority getCA() {
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

        CMSEngine engine = CMS.getCMSEngine();
        IConnector connector = null;

        if (config == null || config.size() <= 0) {
            return null;
        }
        boolean enable = config.getBoolean("enable", true);
        // provide a way to register a 3rd connector into RA
        String extConnector = config.getString("class", null);

        if (extConnector != null) {
            try {
                connector = (IConnector)
                        Class.forName(extConnector).newInstance();
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
            connector = new LocalConnector((ICertAuthority) mCA, authority);
            // logger.info("local Connector to "+id+" inited");
        } else {
            String host = config.getString("host");
            int port = config.getInteger("port");
            String uri = config.getString("uri");
            String nickname = config.getString("nickName", null);
            int resendInterval = config.getInteger("resendInterval", -1);
            // Inserted by beomsuk
            int timeout = config.getInteger("timeout", 0);
            // Insert end
            // Changed by beomsuk
            //RemoteAuthority remauthority =
            //	new RemoteAuthority(host, port, uri);
            RemoteAuthority remauthority =
                    new RemoteAuthority(host, port, uri, timeout);

            // Change end
            if (nickname == null)
                nickname = mCA.getNickname();
            // Changed by beomsuk
            //connector =
            //	new HttpConnector(mCA, nickname, remauthority, resendInterval);

            String clientCiphers = config.getString("clientCiphers", null);
            if (timeout == 0)
                connector = new HttpConnector((IAuthority) mCA, nickname, clientCiphers, remauthority, resendInterval,
                        config);
            else
                connector =
                        new HttpConnector((IAuthority) mCA, nickname, clientCiphers, remauthority, resendInterval,
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

        CAEngine engine = (CAEngine) CMS.getCMSEngine();
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
     * register CRL Issuing Point
     */
    public void addCRLIssuingPoint(String id, ICRLIssuingPoint crlIssuingPoint) {
        mCRLIssuingPoints.put(id, crlIssuingPoint);
    }

    /**
     * get CRL Issuing Point
     */
    public Hashtable<String, ICRLIssuingPoint> getCRLIssuingPoints() {
        return mCRLIssuingPoints;
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
        ICertificateAuthority ca = mCA.getCA(aid);
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
                certi.set(X509CertInfo.VERSION, ca.getDefaultCertVersion());
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
                end = new Date(begin.getTime() + ca.getDefaultValidity());
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
                if (!is_ca) {
                    if (!ca.isEnablePastCATime()) {
                        end = caNotAfter;
                        certi.set(CertificateValidity.NAME,
                                new CertificateValidity(begin, caNotAfter));
                        logger.debug("CAService: issueX509Cert: cert past CA's NOT_AFTER...ca.enablePastCATime != true...resetting");
                    } else {
                        logger.debug("CAService: issueX509Cert: cert past CA's NOT_AFTER...ca.enablePastCATime = true...not resetting");
                    }
                } else {
                    logger.debug("CAService: issueX509Cert: CA cert issuance past CA's NOT_AFTER.");
                } //!is_ca

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
            BigInteger serialNo =
                    mCA.getCertificateRepository().getNextSerialNumber();

            certi.set(X509CertInfo.SERIAL_NUMBER,
                    new CertificateSerialNumber(serialNo));
            logger.info(CMS.getLogMessage("CMSCORE_CA_SIGN_SERIAL", serialNo.toString(16)));

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

        /**
         * (Certificate Transparency)
         *
         * Check to see if certInfo contains Certificate Transparency poison
         * extension (from profile containig certTransparencyExtDefaultImpl);
         * if it does then reach out to the CT log servers to obtain
         * signed certificate timestamp (SCT) for inclusion in the SCT extension
         * in the cert to be issued.
         */
        String method = "CAService: issueX509Cert - CT:";
        try {
            exts = (CertificateExtensions)
                    certi.get(X509CertInfo.EXTENSIONS);
            logger.debug(method + " about to check CT poison");
            Extension ctPoison = (Extension) exts.get("1.3.6.1.4.1.11129.2.4.3");
            if ( ctPoison == null) {
                logger.debug(method + " ctPoison not found");
            } else {
                logger.debug(method + " ctPoison found");
                logger.debug(method + " About to ca.sign CT pre-cert.");
                cert = ca.sign(certi, algname);

                // compose JSON request
                String ct_json_request = composeJSONrequest(cert);

                // submit to CT log(s)
                // TODO: retrieve certTrans config and submit to designated CT logs
                // This prototype code currently only handles one single hardcoded CT log
                String respS;

                { // loop through all CTs
                    String ct_host = "ct.googleapis.com";
                    int ct_port = 80;
                    String ct_uri = "http://ct.googleapis.com/testtube/ct/v1/add-pre-chain";

                    respS = certTransSendReq(
                            ct_host, ct_port, ct_uri, ct_json_request);

                    // verify the sct: TODO - not working, need to fix
                    verifySCT(CTResponse.fromJSON(respS), cert.getTBSCertificate());
                } // todo: should collect a list of CTResonses once out of loop

                /**
                 * Now onto turning the precert into a real cert
                 */
                // remove the poison extension
                exts.delete("1.3.6.1.4.1.11129.2.4.3");
                certi.delete(X509CertInfo.EXTENSIONS);
                certi.set(X509CertInfo.EXTENSIONS, exts);

                // create SCT extension
                // TODO : handle multiple SCTs; should pass in list of CTResponses
                Extension sctExt = createSCTextension(CTResponse.fromJSON(respS));

                // add the SCT extension
                exts.set(sctExt.getExtensionId().toString(), sctExt);
                //check
                Extension p = (Extension) exts.get("1.3.6.1.4.1.11129.2.4.2");
                certi.delete(X509CertInfo.EXTENSIONS);
                certi.set(X509CertInfo.EXTENSIONS, exts);

                try { //double-check if it's there
                    exts = (CertificateExtensions)
                            certi.get(X509CertInfo.EXTENSIONS);
                    logger.debug(method + " about to check sct ext");
                    Extension check = (Extension) exts.get("1.3.6.1.4.1.11129.2.4.2");
                    if ( check == null)
                        logger.debug(method + " check not found");
                    else
                        logger.debug(method + " SCT ext found added successfully");
                } catch (Exception e) {
                    logger.debug(method + " check sct failed:" + e.toString());
                }
            }
        } catch (Exception e) {
            logger.debug(method + " ctPoison check failure:" + e.toString());
        }

        logger.debug(method + "About to ca.sign cert.");
        cert = ca.sign(certi, algname);
        return cert;
    }

    /**
     * (Certificate Transparency)
     *
     * timeStampHexStringToByteArray
     */
    public static byte[] timeStampHexStringToByteArray(String timeStampString) {
        String method = "timeStampHexStringToByteArray: ";
        int len = timeStampString.length();
        logger.debug(method + "len =" + len);
        byte[] data = new byte[(len-1) / 2];
        for (int i = 0; i < len; i += 2) {
            if (i == 8 ) {
                i--; // skip the '.' and at i+=2 it will move to next digit
                continue;
            }
            data[i / 2] = (byte) ((Character.digit(timeStampString.charAt(i), 16) << 4)
                             + Character.digit(timeStampString.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * (Certificate Transparency)
     *
       https://tools.ietf.org/html/rfc6962
       ...
          a certificate authority MAY submit a Precertificate to
          more than one log, and all obtained SCTs can be directly embedded in
          the final certificate, by encoding the SignedCertificateTimestampList
          structure as an ASN.1 OCTET STRING and inserting the resulting data
          in the TBSCertificate as an X.509v3 certificate extension (OID
          1.3.6.1.4.1.11129.2.4.2).  Upon receiving the certificate, clients
          can reconstruct the original TBSCertificate to verify the SCT
          signature.
       ...

       SCT response:

       struct {
           Version sct_version;
           LogID id;
           uint64 timestamp;
           CtExtensions extensions;
           digitally-signed struct {
               Version sct_version;
               SignatureType signature_type = certificate_timestamp;
               uint64 timestamp;
               LogEntryType entry_type;
               select(entry_type) {
                   case x509_entry: ASN.1Cert;
                   case precert_entry: PreCert;
               } signed_entry;
              CtExtensions extensions;
           };
       } SignedCertificateTimestamp;

       TODO: support multiple CTs: list of CTResponse as input param
    */
    Extension createSCTextension(CTResponse response) {

        String method = "CAService.createSCTextension:";
        boolean ct_sct_critical = false;
        ObjectIdentifier ct_sct_oid = new ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2");

        /*
              TLS encoding:
               [ total len : 2 bytes ]
                   [ sct1 len : 2 bytes ]
                   [ sct1 ]
                   [ sct2 len : 2 bytes ]
                   [ sct2 ]
                   ...
                   [ sctx ...]
        */
        try {
            int tls_len = 0;

            ByteArrayOutputStream sct_ostream = new ByteArrayOutputStream();
            { // loop through each ctResponse
                byte ct_version[] = new byte[] {0}; // sct_version
                byte ct_id[] = CryptoUtil.base64Decode(response.getId()); // id
                logger.debug(method + " ct_id: " + bytesToHex(ct_id));

                long timestamp_l = response.getTimestamp();
                TimeStamp timestamp_t = new TimeStamp(timestamp_l);
                String timestamp_s = timestamp_t.toString();
                logger.debug(method + " ct_timestamp: " + timestamp_s);
                // timestamp
                byte ct_timestamp[] = timeStampHexStringToByteArray(timestamp_s);

                byte ct_ext[] = new byte[] {0, 0}; // CT extension
                // signature
                byte ct_signature[] = CryptoUtil.base64Decode(response.getSignature());
                logger.debug(method + " ct_signature: " + bytesToHex(ct_signature));

                int sct_len = ct_version.length + ct_id.length +
                        ct_timestamp.length + 2 /* ext */ + ct_signature.length;
                ByteBuffer sct_len_bytes = ByteBuffer.allocate(4);
                //sct_len_bytes.order(ByteOrder.BIG_ENDIAN);
                sct_len_bytes.putInt(sct_len);

                logger.debug(method + " sct_len = "+ sct_len);
                byte sct_len_ba[] = sct_len_bytes.array();
                // stuff into 2 byte len
                byte sct_len_b2[] = {sct_len_ba[2], sct_len_ba[3]};
                tls_len += (2 + sct_len); // add 2 bytes for sct len ltself

                sct_ostream.write(sct_len_b2);
                sct_ostream.write(ct_version);
                sct_ostream.write(ct_id);
                sct_ostream.write(ct_timestamp);
                sct_ostream.write(ct_ext);
                sct_ostream.write(ct_signature);

                /* test double the SCT to act as though there were two
                sct_ostream.write(sct_len_b2);
                sct_ostream.write(ct_version);
                sct_ostream.write(ct_id);
                sct_ostream.write(ct_timestamp);
                sct_ostream.write(ct_ext);
                sct_ostream.write(ct_signature);
                */
            }

            // collection of sct bytes that comes after tls_len bytes
            byte[] sct_bytes = sct_ostream.toByteArray();
            ByteBuffer tls_len_bytes = ByteBuffer.allocate(4);
            //tls_len_bytes.order(ByteOrder.BIG_ENDIAN);
            //tls_len_bytes.putInt((sct_len + 2) * 2); //cfu test: double it
            tls_len_bytes.putInt(tls_len);
            byte tls_len_ba[] = tls_len_bytes.array();
            // stuff into 2 byte len
            byte tls_len_b2[] = {tls_len_ba[2], tls_len_ba[3]};

            ByteArrayOutputStream tls_sct_ostream = new ByteArrayOutputStream();
            tls_sct_ostream.write(tls_len_b2);
            tls_sct_ostream.write(sct_bytes);
            byte[] tls_sct_bytes = tls_sct_ostream.toByteArray();

            Extension ct_sct_ext = new Extension();
            try (DerOutputStream out = new DerOutputStream()) {
                out.putOctetString(tls_sct_bytes);
                ct_sct_ext.setExtensionId(ct_sct_oid);
                ct_sct_ext.setCritical(false);
                ct_sct_ext.setExtensionValue(out.toByteArray());
                logger.debug(method + " ct_sct_ext id = " +
                    ct_sct_ext.getExtensionId().toString());
                logger.debug(method + " CT extension constructed");
            } catch (IOException e) {
                logger.debug(method + " test 3 " + e.toString());
                return null;
            } catch (Exception e) {
                logger.debug(method + " test4 " + e.toString());
                return null;
            }

            return ct_sct_ext;
        } catch (Exception ex) {
            logger.debug(method + " test 5" + ex.toString());
            return null;
        }
    }

    /** cfu == This is not yet working ==
     * (Certificate Transparency)

           digitally-signed struct {
               Version sct_version;
               SignatureType signature_type = certificate_timestamp; == 0 for ct
               uint64 timestamp;
               LogEntryType entry_type; ===> 1 for precert
               select(entry_type) { ==> 32 bit sha256 hash of issuer pub key + DER of precert
                   case x509_entry: ASN.1Cert;
                   case precert_entry: PreCert;
               } signed_entry;
              CtExtensions extensions;
           };

         struct {
           opaque issuer_key_hash[32];
           TBSCertificate tbs_certificate;
         } PreCert;
    */
    void verifySCT(CTResponse response, byte[] cert)
            throws Exception {

        String method = "CAService:verifySCT: ";
        logger.debug(method + "begins");

        long timestamp_l = response.getTimestamp();
        TimeStamp timestamp_t = new TimeStamp(timestamp_l);
        String timestamp_s = timestamp_t.toString();
        logger.debug(method + " ct_timestamp: " + timestamp_s);
        // timestamp
        byte timestamp[] = timeStampHexStringToByteArray(timestamp_s);
        byte ct_signature[] = CryptoUtil.base64Decode(response.getSignature());
        byte[] signature = Arrays.copyOfRange(ct_signature, 4, ct_signature.length+1);

        /* compose data */
        byte[] version = new byte[] {0}; // v1(0)
        byte[] signature_type = new byte[] {0}; // certificate_timestamp(0)
        byte[] entry_type = new byte[] {0, 1}; // LogEntryType: precert_entry(1)
        byte google_pub[] = CryptoUtil.base64Decode(GoogleTestTube_Pub);
        PublicKey google_pubKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(google_pub));
        /*
        byte[] key_id = null;
        try {
            MessageDigest SHA256Digest = MessageDigest.getInstance("SHA256");

            key_id = SHA256Digest.digest(google_pubKey.getEncoded());
        } catch (NoSuchAlgorithmException ex) {
            logger.debug(method + " getting hash of CT signer key:" + ex.toString());
        }

        */
        X509CertImpl cacert = mCA.getCACert();
        byte[] issuer_key = cacert.getPublicKey().getEncoded();
        byte[] issuer_key_hash = null;
        try {
            MessageDigest SHA256Digest = MessageDigest.getInstance("SHA256");

            issuer_key_hash = SHA256Digest.digest(issuer_key);
        } catch (NoSuchAlgorithmException ex) {
            logger.debug(method + " getting hash of CA signing key:" + ex.toString());
        }

        byte[] extensions = new byte[] {0, 0};

        // piece them together
        int data_len = version.length + signature_type.length +
                 timestamp.length + entry_type.length +
                 issuer_key_hash.length + cert.length + extensions.length;
        logger.debug(method + " issuer_key_hash.length = "+ issuer_key_hash.length);
        logger.debug(method + " data_len = "+ data_len);
        ByteArrayOutputStream ostream = new ByteArrayOutputStream();
        ostream.write(version);
        ostream.write(signature_type);
        ostream.write(timestamp);
        ostream.write(entry_type);
        ostream.write(issuer_key_hash);
        ostream.write(cert);
        ostream.write(extensions);
        byte[] data = ostream.toByteArray();

        // todo: interpret the alg bytes later; hardcode for now
        Signature signer = Signature.getInstance("SHA256withEC", "Mozilla-JSS");
        signer.initVerify(/*pubKey*/ google_pubKey);
        signer.update(data);

        if (!signer.verify(signature)) {
            logger.debug(method + "failed to verify SCT signature");
            // this method is not yet working;  Let this pass for now
            // throw new Exception("Invalid SCT signature");
        }
        logger.debug("verifySCT ends");

    }

    /**
     * (Certificate Transparency)
     * Given a leaf cert, build chain and format a JSON request
     * @param leaf cert
     * @return JSON request in String
     */
    String composeJSONrequest(X509CertImpl cert) {
        String method = "CAService.composeJSONrequest";

        // JSON request
        String ct_json_request_begin = "{\"chain\":[\"";
        String ct_json_request_end = "\"]}";
        String ct_json_request = ct_json_request_begin;

        // Create chain, leaf first
        ByteArrayOutputStream certOut = new ByteArrayOutputStream();
        CertificateChain caCertChain = mCA.getCACertChain();
        X509Certificate[] cacerts = caCertChain.getChain();

        try {
            // first, leaf cert;
            cert.encode(certOut);
            byte[] certBytes = certOut.toByteArray();
            certOut.reset();
            ct_json_request += Utils.base64encode(certBytes, false);

            // then ca chain;
            // TODO: need to make sure they are in order
            //       I believe they are; should test
            for (int n = 0; n < cacerts.length; n++) {
                ct_json_request += "\",\"";
                X509CertImpl caCertInChain = (X509CertImpl) cacerts[n];
                caCertInChain.encode(certOut);
                certBytes = certOut.toByteArray();
                certOut.reset();
                logger.debug(method + "caCertInChain " + n + " = " +
                        Utils.base64encode(certBytes, false));
                ct_json_request += Utils.base64encode(certBytes, false);
;
            }
            certOut.close();
            ct_json_request += ct_json_request_end;
            logger.debug(method + " ct_json_request:" + ct_json_request);
        } catch (Exception e) {
            logger.debug(method + e.toString());
        }
        return ct_json_request;
    }

    /**
     * (Certificate Transparency)
     * certTransSendReq connects to CT host and send ct request
     */
    private String certTransSendReq(String ct_host, int ct_port, String ct_uri, String ctReq) {
        HttpClient client = new HttpClient();
        HttpRequest req = new HttpRequest();
        HttpResponse resp = null;

        logger.debug("CAService.certTransSendReq begins");
        try {
            client.connect(ct_host, ct_port);
            req.setMethod("POST");
            req.setURI(ct_uri);
            req.setHeader("Content-Type", "application/json");
            req.setContent(ctReq);
            req.setHeader("Content-Length", Integer.toString(ctReq.length()));

            resp = client.send(req);
            logger.debug("version " + resp.getHttpVers());
            logger.debug("status code " + resp.getStatusCode());
            logger.debug("reason " + resp.getReasonPhrase());
            logger.debug("content " + resp.getContent());
            logger.debug("CAService.certTransSendReq ends");
        } catch (Exception e) {
        }

        return (resp.getContent());
    }

    /*
     * (Certificate Transparency)
     */
    public static String bytesToHex(byte[] bytes) {
        final StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


    void storeX509Cert(String rid, X509CertImpl cert,
            boolean renewal, BigInteger oldSerialNo)
            throws EBaseException {
        storeX509Cert(rid, cert, renewal, oldSerialNo, null, null, null);
    }

    void storeX509Cert(String rid, X509CertImpl cert,
            boolean renewal, BigInteger oldSerialNo, String crmfReqId,
            String challengePassword, String profileId) throws EBaseException {
        // now store in repository.
        // if renewal, set the old serial number in the new cert,
        // set the new serial number in the old cert.

        logger.debug("In storeX509Cert");
        try {
            BigInteger newSerialNo = cert.getSerialNumber();
            MetaInfo metaInfo = new MetaInfo();

            if (profileId != null)
                metaInfo.set("profileId", profileId);
            if (rid != null)
                metaInfo.set(CertRecord.META_REQUEST_ID, rid);
            if (challengePassword != null && !challengePassword.equals(""))
                metaInfo.set("challengePhrase", challengePassword);
            if (crmfReqId != null) {
                //System.out.println("Adding crmf reqid "+crmfReqId);
                metaInfo.set(CertRecord.META_CRMF_REQID, crmfReqId);
            }
            if (renewal)
                metaInfo.set(CertRecord.META_OLD_CERT, oldSerialNo.toString());
            mCA.getCertificateRepository().addCertificateRecord(
                    new CertRecord(newSerialNo, cert, metaInfo));

            logger.info(CMS.getLogMessage("CMSCORE_CA_STORE_SERIAL", cert.getSerialNumber().toString(16)));

            if (renewal) {

                /*
                 mCA.getCertificateRepository().markCertificateAsRenewed(
                 BigIntegerMapper.BigIntegerToDB(oldSerialNo));
                 mCA.mCertRepot.markCertificateAsRenewed(oldSerialNo);
                 */
                MetaInfo oldMeta = null;
                CertRecord oldCertRec = (CertRecord)
                        mCA.getCertificateRepository().readCertificateRecord(oldSerialNo);

                if (oldCertRec == null) {
                    String message = CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                            "Cannot read cert record for " + oldSerialNo);
                    Exception e = new EBaseException(message);
                    logger.warn(message, e);
                }

                if (oldCertRec != null)
                    oldMeta = oldCertRec.getMetaInfo();
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
                oldMeta.set(CertRecord.META_RENEWED_CERT,
                        newSerialNo.toString());
                ModificationSet modSet = new ModificationSet();

                modSet.add(CertRecord.ATTR_AUTO_RENEW,
                        Modification.MOD_REPLACE,
                        CertRecord.AUTO_RENEWAL_DONE);
                modSet.add(ICertRecord.ATTR_META_INFO,
                        Modification.MOD_REPLACE, oldMeta);
                mCA.getCertificateRepository().modifyCertificateRecord(oldSerialNo, modSet);

                logger.info(CMS.getLogMessage("CMSCORE_CA_MARK_SERIAL", oldSerialNo.toString(16), newSerialNo.toString(16)));

                if (logger.isDebugEnabled()) {
                    CertRecord check = (CertRecord)
                            mCA.getCertificateRepository().readCertificateRecord(oldSerialNo);
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
        CertRecord certRec = (CertRecord) mCA.getCertificateRepository().readCertificateRecord(serialno);

        if (certRec == null) {
            logger.error(method + ": " + CMS.getLogMessage("CMSCORE_CA_CERT_NOT_FOUND", serialno.toString(16)));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                            "0x" + serialno.toString(16)));
        }

        // allow revoking certs that are on hold.
        String certStatus = certRec.getStatus();

        RevocationReason recRevReason = null;
        if (certStatus.equals(ICertRecord.STATUS_REVOKED)) {
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
        if (((certStatus.equals(ICertRecord.STATUS_REVOKED) &&
                !certRec.isCertOnHold()) &&
                ((recRevReason != RevocationReason.SUPERSEDED) ||
                        revReason != RevocationReason.KEY_COMPROMISE))
                ||
                certStatus.equals(ICertRecord.STATUS_REVOKED_EXPIRED)) {
            logger.debug(method + ": cert already revoked:" +
                    serialno.toString());
            throw new ECAException(CMS.getUserMessage("CMS_CA_CERT_ALREADY_REVOKED",
                    "0x" + Long.toHexString(serialno.longValue())));
        }

        try {
            // if cert has already revoked, update the revocation info only
            logger.debug(method + ": about to call markAsRevoked");
            if (certStatus.equals(ICertRecord.STATUS_REVOKED)) {
                mCA.getCertificateRepository().markAsRevoked(serialno,
                        new RevocationInfo(revdate, crlentryexts),
                        true /*isAlreadyRevoked*/);

                logger.debug(method + ": Already-revoked cert marked revoked");

                logger.info(CMS.getLogMessage("CMSCORE_CA_CERT_REVO_INFO_UPDATE",
                                recRevReason.toString(),
                                revReason.toString(),
                                serialno.toString(16)));
            } else {
                mCA.getCertificateRepository().markAsRevoked(serialno,
                        new RevocationInfo(revdate, crlentryexts));
            }

            logger.info(CMS.getLogMessage("CMSCORE_CA_CERT_REVOKED",
                    serialno.toString(16)));

            // inform all CRLIssuingPoints about revoked certificate
            Enumeration<ICRLIssuingPoint> eIPs = mCRLIssuingPoints.elements();

            while (eIPs.hasMoreElements()) {
                ICRLIssuingPoint ip = eIPs.nextElement();

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
        CertRecord certRec = (CertRecord) mCA.getCertificateRepository().readCertificateRecord(serialNo);

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
        if ((certRec.getStatus().equals(ICertRecord.STATUS_REVOKED) ||
                certRec.getStatus().equals(ICertRecord.STATUS_REVOKED_EXPIRED)) &&
                reasonext != null &&
                reasonext.getReason() == RevocationReason.CERTIFICATE_HOLD) {
            try {
                mCA.getCertificateRepository().unmarkRevoked(serialNo, revInfo,
                        certRec.getRevokedOn(), certRec.getRevokedBy());

                logger.info(CMS.getLogMessage("CMSCORE_CA_CERT_UNREVOKED", serialNo.toString(16)));

                // inform all CRLIssuingPoints about unrevoked certificate
                Enumeration<ICRLIssuingPoint> eIPs = mCRLIssuingPoints.elements();

                while (eIPs.hasMoreElements()) {
                    ICRLIssuingPoint ip = eIPs.nextElement();

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

    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceIssue(CAService service) {
        mService = service;
        mCA = mService.getCA();
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
                    mCA.getCertificateRepository().deleteCertificateRecord(serialNo);
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

    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceRenewal(CAService service) {
        mService = service;
        mCA = mService.getCA();
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
                CertRecord certRecord = (CertRecord)
                        mCA.getCertificateRepository().readCertificateRecord(oldSerialNo);

                if (certRecord == null) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_NOT_FROM_CA", oldSerialNo.toString()));
                    svcerrors[i] = new ECAException(
                            CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                                    oldSerialNo.toString())).toString();
                    continue;
                }

                // check if cert has been revoked.
                String certStatus = certRecord.getStatus();

                if (certStatus.equals(ICertRecord.STATUS_REVOKED) ||
                        certStatus.equals(ICertRecord.STATUS_REVOKED_EXPIRED)) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_RENEW_REVOKED", oldSerialNo.toString()));
                    svcerrors[i] = new ECAException(
                            CMS.getUserMessage("CMS_CA_CANNOT_RENEW_REVOKED_CERT",
                                    "0x" + oldSerialNo.toString(16))).toString();
                    continue;
                }

                // check if cert has already been renewed.
                MetaInfo metaInfo = certRecord.getMetaInfo();

                if (metaInfo != null) {
                    String renewed = (String)
                            metaInfo.get(ICertRecord.META_RENEWED_CERT);

                    if (renewed != null) {
                        BigInteger serial = new BigInteger(renewed);
                        X509CertImpl cert =
                                mCA.getCertificateRepository().getX509Certificate(serial);

                        if (cert == null) {
                            // something wrong
                            logger.error(CMS.getLogMessage("CMSCORE_CA_MISSING_RENEWED", serial.toString()));
                            svcerrors[i] = new ECAException(
                                    CMS.getUserMessage("CMS_CA_ERROR_GETTING_RENEWED_CERT",
                                            oldSerialNo.toString(), serial.toString())).toString();
                            continue;
                        }
                        // get cert record
                        CertRecord cRecord = (CertRecord)
                                mCA.getCertificateRepository().readCertificateRecord(serial);

                        if (cRecord == null) {
                            logger.error(CMS.getLogMessage("CMSCORE_CA_NOT_FROM_CA", serial.toString()));
                            svcerrors[i] = new ECAException(
                                    CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                                            serial.toString())).toString();
                            continue;
                        }
                        // Check renewed certificate already REVOKED or EXPIRED
                        String status = cRecord.getStatus();

                        if (status.equals(ICertRecord.STATUS_REVOKED) ||
                                status.equals(ICertRecord.STATUS_REVOKED_EXPIRED)) {
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
    private ICertificateAuthority mCA;
    private CAService mService;

    public getCertsForChallenge(CAService service) {
        mService = service;
        mCA = mService.getCA();
    }

    public boolean service(IRequest request)
            throws EBaseException {
        BigInteger[] serialNoArray =
                request.getExtDataInBigIntegerArray(CAService.SERIALNO_ARRAY);
        if (serialNoArray == null) {
            throw new ECAException(CMS.getLogMessage("CMS_CA_MISSING_SERIAL_NUMBER"));
        }
        X509CertImpl[] certs = new X509CertImpl[serialNoArray.length];

        for (int i = 0; i < serialNoArray.length; i++) {
            certs[i] = mCA.getCertificateRepository().getX509Certificate(serialNoArray[i]);
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
        CertificateRepository certDB = (CertificateRepository)
                mCA.getCertificateRepository();

        String status = null;

        if (serialno != null) {
            CertRecord record = null;

            try {
                record = (CertRecord) certDB.readCertificateRecord(serialno);
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

    private ICertificateAuthority mCA;
    private CAService mService;
    private MessageDigest mSHADigest = null;

    public serviceCheckChallenge(CAService service) {
        mService = service;
        mCA = mService.getCA();
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
        CertificateRepository certDB = (CertificateRepository) mCA.getCertificateRepository();
        BigInteger[] bigIntArray = null;

        if (serialno != null) {
            CertRecord record = null;

            try {
                record = (CertRecord) certDB.readCertificateRecord(serialno);
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
                ICertRecordList list = certDB.findCertRecordsInList(filter, null, 10);
                int size = list.getSize();
                Enumeration<ICertRecord> en = list.getCertRecords(0, size - 1);

                if (!en.hasMoreElements()) {
                    bigIntArray = new BigInteger[0];
                } else {
                    Vector<BigInteger> idv = new Vector<BigInteger>();

                    while (en.hasMoreElements()) {
                        ICertRecord record = en.nextElement();
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

    private boolean compareChallengePassword(ICertRecord record, String pwd)
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

    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceRevoke(CAService service) {
        mService = service;
        mCA = mService.getCA();
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

    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceUnrevoke(CAService service) {
        mService = service;
        mCA = mService.getCA();
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
                    CertRecord certRec = (CertRecord)
                            mCA.getCertificateRepository().readCertificateRecord(oldSerialNo[i]);

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

    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceGetCRL(CAService service) {
        mService = service;
        mCA = mService.getCA();
    }

    public boolean service(IRequest request)
            throws EBaseException {
        try {
            ICRLIssuingPointRecord crlRec =
                    mCA.getCRLRepository().readCRLIssuingPointRecord(
                            ICertificateAuthority.PROP_MASTER_CRL);
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
    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceGetRevocationInfo(CAService service) {
        mService = service;
        mCA = mService.getCA();
    }

    public boolean service(IRequest request)
            throws EBaseException {
        Enumeration<String> enum1 = request.getExtDataKeys();

        while (enum1.hasMoreElements()) {
            String name = enum1.nextElement();
            RevocationInfo info = null;
            if (name.equals(IRequest.ISSUED_CERTS)) {
                X509CertImpl certsToCheck[] =
                        request.getExtDataInCertArray(IRequest.ISSUED_CERTS);
                if (certsToCheck != null) {
                    CertificateRepository certDB = (CertificateRepository) mCA.getCertificateRepository();
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
    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceGetCertificates(CAService service) {
        mService = service;
        mCA = mService.getCA();
    }

    public boolean service(IRequest request)
            throws EBaseException {
        Enumeration<String> enum1 = request.getExtDataKeys();

        while (enum1.hasMoreElements()) {
            String name = enum1.nextElement();

            if (name.equals(IRequest.CERT_FILTER)) {
                String filter = request.getExtDataInString(IRequest.CERT_FILTER);

                CertificateRepository certDB = (CertificateRepository) mCA.getCertificateRepository();
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

    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceCert4Crl(CAService service) {
        mService = service;
        mCA = mService.getCA();
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

        CertRecord revokedCertRecs[] = new CertRecord[revokedCertIds.length];
        for (int i = 0; i < revokedCertIds.length; i++) {
            revokedCertRecs[i] = (CertRecord)
                    mCA.getCertificateRepository().readCertificateRecord(
                            revokedCertIds[i]);
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
                ((CertificateRepository) mCA.getCertificateRepository()).addRevokedCertRecord(revokedCertRecs[i]);
                //				mService.revokeCert(crlentries[i]);
                recordedCerts[i] = revokedCertRecs[i];
                // inform all CRLIssuingPoints about revoked certificate
                Hashtable<String, ICRLIssuingPoint> hips = mService.getCRLIssuingPoints();
                Enumeration<ICRLIssuingPoint> eIPs = hips.elements();

                while (eIPs.hasMoreElements()) {
                    ICRLIssuingPoint ip = eIPs.nextElement();
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

    private ICertificateAuthority mCA;
    private CAService mService;

    public serviceUnCert4Crl(CAService service) {
        mService = service;
        mCA = mService.getCA();
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

        String svcerrors[] = null;

        for (int i = 0; i < oldSerialNo.length; i++) {
            try {
                mCA.getCertificateRepository().deleteCertificateRecord(oldSerialNo[i]);
                // inform all CRLIssuingPoints about unrevoked certificate
                Hashtable<String, ICRLIssuingPoint> hips = mService.getCRLIssuingPoints();
                Enumeration<ICRLIssuingPoint> eIPs = hips.elements();

                while (eIPs.hasMoreElements()) {
                    ICRLIssuingPoint ip = eIPs.nextElement();

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
