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

import netscape.security.extensions.CertInfo;
import netscape.security.util.BigInt;
import netscape.security.util.DerValue;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateIssuerName;
import netscape.security.x509.CertificateSerialNumber;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.Extension;
import netscape.security.x509.LdapV3DNStrConverter;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.SerialNumber;
import netscape.security.x509.X500Name;
import netscape.security.x509.X500NameAttrMap;
import netscape.security.x509.X509CRLImpl;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.ca.ICAService;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertRecordList;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.cmscore.base.SubsystemRegistry;
import com.netscape.cmscore.connector.HttpConnector;
import com.netscape.cmscore.connector.LocalConnector;
import com.netscape.cmscore.connector.RemoteAuthority;
import com.netscape.cmscore.crmf.CRMFParser;
import com.netscape.cmscore.crmf.PKIArchiveOptionsContainer;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.util.Utils;

/**
 * Request Service for CertificateAuthority.
 */
public class CAService implements ICAService, IService {

    public static final String CRMF_REQUEST = "CRMFRequest";
    public static final String CHALLENGE_PHRASE = "challengePhrase";
    public static final String SERIALNO_ARRAY = "serialNoArray";

    // CCA->CLA connector
    protected static IConnector mCLAConnector = null;

    private ICertificateAuthority mCA = null;
    private Hashtable<String, IServant> mServants = new Hashtable<String, IServant>();
    private IConnector mKRAConnector = null;
    private IConfigStore mConfig = null;
    private boolean mArchivalRequired = true;
    private Hashtable<String, ICRLIssuingPoint> mCRLIssuingPoints = new Hashtable<String, ICRLIssuingPoint>();

    private ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    private final static String LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST =
            "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_4";

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
            //			java.security.Security.addProvider(new netscape.security.provider.CMS());
            //			java.security.Provider pr = java.security.Security.getProvider("CMS");
            //			if (pr != null) {
            //				;
            //			}
            //			else
            //				Debug.trace("Something is wrong in CMS install !");
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");

            Debug.trace("CertificateFactory Type : " + cf.getType());
            Debug.trace("CertificateFactory Provider : " + cf.getProvider().getInfo());
        } catch (java.security.cert.CertificateException e) {
            Debug.trace("Something is happen in install CMS provider !" + e.toString());
        }
    }

    public void startup() throws EBaseException {
        IConfigStore kraConfig = mConfig.getSubStore("KRA");

        if (kraConfig != null) {
            mArchivalRequired = kraConfig.getBoolean(
                    "archivalRequired", true);
            mKRAConnector = getConnector(kraConfig);
            if (mKRAConnector != null) {
                if (Debug.ON) {
                    Debug.trace("Started KRA Connector");
                }
                mKRAConnector.start();
            }
        }

        // clone ca to CLA (clone master) connector
        IConfigStore claConfig = mConfig.getSubStore("CLA");

        if (claConfig != null) {
            mCLAConnector = getConnector(claConfig);
            if (mCLAConnector != null) {
                CMS.debug(CMS.getLogMessage("CMSCORE_CA_START_CONNECTOR"));
                if (Debug.ON) {
                    Debug.trace("Started CLA Connector in CCA");
                }
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
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_LOAD_CONNECTOR", extConnector, e.toString()));
            }
        }

        if (!enable)
            return null;
        boolean local = config.getBoolean("local");
        IAuthority authority = null;

        if (local) {
            String id = config.getString("id");

            authority = (IAuthority) SubsystemRegistry.getInstance().get(id);
            if (authority == null) {
                String msg = "local authority " + id + " not found.";

                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_AUTHORITY_NOT_FOUND", id));
                throw new EBaseException(msg);
            }
            connector = new LocalConnector((ICertAuthority) mCA, authority);
            // log(ILogger.LL_INFO, "local Connector to "+id+" inited");
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

            // log(ILogger.LL_INFO, "remote authority "+
            //	host+":"+port+" "+uri+" inited");
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
        CMS.debug("CAService: serviceProfileRequest requestId=" +
                request.getRequestId().toString());

        String profileId = request.getExtDataInString(IRequest.PROFILE_ID);

        if (profileId == null || profileId.equals("")) {
            throw new EBaseException("profileId not found");
        }

        IProfileSubsystem ps = (IProfileSubsystem)
                CMS.getSubsystem("profile");
        IProfile profile = null;

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
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID();
        String auditArchiveID = ILogger.SIGNED_AUDIT_NON_APPLICABLE;

        boolean completed = false;

        // short cut profile-based request
        if (isProfileRequest(request)) {
            try {
                CMS.debug("CAService: x0 requestStatus="
                        + request.getRequestStatus().toString() + " instance=" + request);
                serviceProfileRequest(request);
                request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
                CMS.debug("CAService: x1 requestStatus=" + request.getRequestStatus().toString());

                return true;
            } catch (EBaseException e) {
                CMS.debug("CAService: x2 requestStatus=" + request.getRequestStatus().toString());
                // need to put error into the request
                CMS.debug("CAService: serviceRequest " + e.toString());
                request.setExtData(IRequest.RESULT, IRequest.RES_ERROR);
                request.setExtData(IRequest.ERROR, e.toString());

                audit(auditMessage);

                return false;
            }
        }

        String type = request.getRequestType();
        IServant servant = mServants.get(type);

        if (servant == null) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_INVALID_REQUEST_TYPE", type));
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

                CMS.debug("CAService: Sending enrollment request to KRA");

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditRequesterID,
                        auditArchiveID);

                audit(auditMessage);

                boolean sendStatus = mKRAConnector.send(request);

                if (mArchivalRequired == true) {
                    if (sendStatus == false) {
                        request.setExtData(IRequest.RESULT,
                                IRequest.RES_ERROR);
                        request.setExtData(IRequest.ERROR,
                                new ECAException(CMS.getUserMessage("CMS_CA_SEND_KRA_REQUEST")));

                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditArchiveID);

                        audit(auditMessage);

                        return true;
                    } else {
                        if (request.getExtDataInString(IRequest.ERROR) != null) {
                            request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
                            request.deleteExtData(IRequest.ERROR);
                        }
                    }
                    if (request.getExtDataInString(IRequest.ERROR) != null) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditArchiveID);

                        audit(auditMessage);

                        return true;
                    }
                }
            } else {
                if (Debug.ON) {
                    Debug.trace("*** NOT Send to KRA type=" + type + " ENROLLMENT=" + IRequest.ENROLLMENT_REQUEST);
                }
            }

            completed = servant.service(request);
            request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
        } catch (EBaseException e) {
            request.setExtData(IRequest.RESULT, IRequest.RES_ERROR);
            request.setExtData(IRequest.ERROR, e);

            // store a message in the signed audit log file
            if (!(type.equals(IRequest.REVOCATION_REQUEST) ||
                    type.equals(IRequest.UNREVOCATION_REQUEST) || type.equals(IRequest.CMCREVOKE_REQUEST))) {
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        auditArchiveID);

                audit(auditMessage);
            }

            return true;
        }

        // XXX in case of key archival this may not always be the case.
        if (Debug.ON)
            Debug.trace("serviceRequest completed = " + completed);

        if (!(type.equals(IRequest.REVOCATION_REQUEST) ||
                type.equals(IRequest.UNREVOCATION_REQUEST) || type.equals(IRequest.CMCREVOKE_REQUEST))) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    auditRequesterID,
                    auditArchiveID);

            audit(auditMessage);
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
            if (Debug.ON) {
                Debug.trace("CRMF not found");
            }
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
        CMS.debug("issueX509Cert");
        X509CertImpl certImpl = issueX509Cert(aid, "", certi, false, null);

        CMS.debug("storeX509Cert " + certImpl.getSerialNumber());
        storeX509Cert(profileId, rid, certImpl);
        CMS.debug("done storeX509Cert");
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

        CMS.debug("dnUTF8Encoding " + doUTF8);

        try {
            // check required fields in certinfo.
            if (certi.get(X509CertInfo.SUBJECT) == null ||
                    certi.get(X509CertInfo.KEY) == null) {

                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_MISSING_ATTR"));
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
                if (Debug.ON) {
                    Debug.trace("setting default validity");
                }

                begin = CMS.getCurrentDate();
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
            CertificateExtensions exts = null;
            BasicConstraintsExtension bc_ext = null;

            try {
                exts = (CertificateExtensions)
                        certi.get(X509CertInfo.EXTENSIONS);
                if (exts != null) {
                    Enumeration<Extension> e = exts.getAttributes();

                    while (e.hasMoreElements()) {
                        netscape.security.x509.Extension ext = e.nextElement();

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
                CMS.debug("EnrollDefault: getExtension " + e.toString());
            }

            Date caNotAfter =
                    ca.getSigningUnit().getCertImpl().getNotAfter();

            if (begin.after(caNotAfter)) {
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_PAST_VALIDITY"));
                throw new ECAException(CMS.getUserMessage("CMS_CA_CERT_BEGIN_AFTER_CA_VALIDITY"));
            }

            if (end.after(caNotAfter)) {
                if (!is_ca) {
                    if (!ca.isEnablePastCATime()) {
                        end = caNotAfter;
                        certi.set(CertificateValidity.NAME,
                                new CertificateValidity(begin, caNotAfter));
                        CMS.debug("CAService: issueX509Cert: cert past CA's NOT_AFTER...ca.enablePastCATime != true...resetting");
                    } else {
                        CMS.debug("CAService: issueX509Cert: cert past CA's NOT_AFTER...ca.enablePastCATime = true...not resetting");
                    }
                } else {
                    CMS.debug("CAService: issueX509Cert: CA cert issuance past CA's NOT_AFTER.");
                } //!is_ca
                mCA.log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_CA_PAST_NOT_AFTER"));
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
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_BAD_FIELD", e.toString()));
            if (Debug.ON) {
                e.printStackTrace();
            }
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_ERROR_GETTING_FIELDS_IN_ISSUE"));
        } catch (IOException e) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_BAD_FIELD", e.toString()));
            if (Debug.ON) {
                e.printStackTrace();
            }
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_ERROR_GETTING_FIELDS_IN_ISSUE"));
        } catch (NoSuchAlgorithmException e) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_SIGNING_ALG_NOT_SUPPORTED", algname));
            if (Debug.ON) {
                e.printStackTrace();
            }
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_ALGOR_NOT_SUPPORTED", algname));
        }

        // get old cert serial number if renewal
        if (renewal) {
            try {
                CertificateSerialNumber serialno = (CertificateSerialNumber)
                        certi.get(X509CertInfo.SERIAL_NUMBER);

                if (serialno == null) {
                    mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_NULL_SERIAL_NUMBER"));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }
                SerialNumber serialnum = (SerialNumber)
                        serialno.get(CertificateSerialNumber.NUMBER);

                if (serialnum == null) {
                    mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_NULL_SERIAL_NUMBER"));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }
            } catch (CertificateException e) {
                // not possible
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_NO_ORG_SERIAL", e.getMessage()));
                throw new ECAException(
                        CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
            } catch (IOException e) {
                // not possible.
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_NO_ORG_SERIAL", e.getMessage()));
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
            mCA.log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_CA_SIGN_SERIAL", serialNo.toString(16)));
        } catch (EBaseException e) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_NO_NEXT_SERIAL", e.toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_NOSERIALNO", rid));
        } catch (CertificateException e) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_SET_SERIAL", e.toString()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SET_SERIALNO_FAILED", rid));
        } catch (IOException e) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_SET_SERIAL", e.toString()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SET_SERIALNO_FAILED", rid));
        }

        try {
            if (ca.getIssuerObj() != null) {
                // this ensures the isserDN has the same encoding as the
                // subjectDN of the CA signing cert
                CMS.debug("CAService: issueX509Cert: setting issuerDN using exact CA signing cert subjectDN encoding");
                certi.set(X509CertInfo.ISSUER,
                        ca.getIssuerObj());
            } else {
                CMS.debug("CAService: issueX509Cert: ca.getIssuerObj() is null, creating new CertificateIssuerName");
                certi.set(X509CertInfo.ISSUER,
                        new CertificateIssuerName(ca.getX500Name()));
            }
        } catch (CertificateException e) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_SET_ISSUER", e.toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_SET_ISSUER_FAILED", rid));
        } catch (IOException e) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_SET_ISSUER", e.toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_SET_ISSUER_FAILED", rid));
        }

        byte[] utf8_encodingOrder = { DerValue.tag_UTF8String };

        if (doUTF8 == true) {
            try {

                CMS.debug("doUTF8 true, updating subject.");

                String subject = certi.get(X509CertInfo.SUBJECT).toString();

                certi.set(X509CertInfo.SUBJECT, new CertificateSubjectName(
                        new X500Name(subject,
                                new LdapV3DNStrConverter(X500NameAttrMap.getDirDefault(), true), utf8_encodingOrder)));

            } catch (CertificateException e) {
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_SET_SUBJECT", e.toString()));
                throw new ECAException(CMS.getUserMessage("CMS_CA_SET_ISSUER_FAILED", rid));
            } catch (IOException e) {
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_SET_SUBJECT", e.toString()));
                throw new ECAException(CMS.getUserMessage("CMS_CA_SET_ISSUER_FAILED", rid));
            }
        }

        CMS.debug("About to ca.sign cert.");
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
        // now store in repository.
        // if renewal, set the old serial number in the new cert,
        // set the new serial number in the old cert.

        CMS.debug("In storeX509Cert");
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

            mCA.log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_CA_STORE_SERIAL", cert.getSerialNumber().toString(16)));
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
                    Exception e =
                            new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                                    "Cannot read cert record for " + oldSerialNo));

                    e.printStackTrace();
                }
                if (oldCertRec != null)
                    oldMeta = oldCertRec.getMetaInfo();
                if (oldMeta == null) {
                    if (Debug.ON) {
                        Debug.trace("No meta info! for " + oldSerialNo);
                    }
                    oldMeta = new MetaInfo();
                } else {
                    if (Debug.ON) {
                        System.out.println("Old meta info");
                        Enumeration<String> n = oldMeta.getElements();

                        while (n.hasMoreElements()) {
                            String name = n.nextElement();

                            System.out.println("name " + name + " value " +
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
                mCA.log(ILogger.LL_INFO,
                        CMS.getLogMessage("CMSCORE_CA_MARK_SERIAL", oldSerialNo.toString(16), newSerialNo.toString(16)));
                if (Debug.ON) {
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
            mCA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_NO_STORE_SERIAL", cert.getSerialNumber().toString(16)));
            if (Debug.ON)
                e.printStackTrace();
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
        BigInteger serialno = crlentry.getSerialNumber();
        Date revdate = crlentry.getRevocationDate();
        CRLExtensions crlentryexts = crlentry.getExtensions();

        CMS.debug("CAService.revokeCert: revokeCert begins");
        CertRecord certRec = (CertRecord) mCA.getCertificateRepository().readCertificateRecord(serialno);

        if (certRec == null) {
            CMS.debug("CAService.revokeCert: cert record not found");
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CERT_NOT_FOUND", serialno.toString(16)));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                            "0x" + serialno.toString(16)));
        }

        // allow revoking certs that are on hold.
        String certStatus = certRec.getStatus();

        if ((certStatus.equals(ICertRecord.STATUS_REVOKED) &&
                !certRec.isCertOnHold()) ||
                certStatus.equals(ICertRecord.STATUS_REVOKED_EXPIRED)) {
            CMS.debug("CAService.revokeCert: cert already revoked:" +
                    serialno.toString());
            throw new ECAException(CMS.getUserMessage("CMS_CA_CERT_ALREADY_REVOKED",
                    "0x" + Long.toHexString(serialno.longValue())));
        }
        try {
            CMS.debug("CAService.revokeCert: about to call markAsRevoked");
            if (certRec.isCertOnHold()) {
                mCA.getCertificateRepository().markAsRevoked(serialno,
                        new RevocationInfo(revdate, crlentryexts), true /*isAlreadyOnHold*/);
            } else {
                mCA.getCertificateRepository().markAsRevoked(serialno,
                        new RevocationInfo(revdate, crlentryexts));
            }
            CMS.debug("CAService.revokeCert: cert revoked");
            mCA.log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_CA_CERT_REVOKED",
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
            CMS.debug("CAService.revokeCert: " + e.toString());
            mCA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_ERROR_REVOCATION", serialno.toString(), e.toString()));
            //e.printStackTrace();
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
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CERT_NOT_FOUND", serialNo.toString(16)));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                            "0x" + serialNo.toString(16)));
        }
        RevocationInfo revInfo = (RevocationInfo) certRec.getRevocationInfo();
        CRLExtensions exts = null;
        CRLReasonExtension reasonext = null;

        if (revInfo == null) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CERT_ON_HOLD", serialNo.toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_IS_NOT_ON_HOLD",
                    serialNo.toString()));
        }
        exts = revInfo.getCRLEntryExtensions();
        if (exts != null) {
            try {
                reasonext = (CRLReasonExtension)
                        exts.get(CRLReasonExtension.NAME);
            } catch (X509ExtensionException e) {
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CERT_ON_HOLD", serialNo.toString()));
                throw new ECAException(CMS.getUserMessage("CMS_CA_IS_NOT_ON_HOLD",
                        serialNo.toString()));
            }
        } else {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CERT_ON_HOLD", serialNo.toString()));
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
                mCA.log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_CA_CERT_UNREVOKED", serialNo.toString(16)));
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
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CERT_ERROR_UNREVOKE", serialNo.toString(16)));
                throw e;
            }
        } else {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CERT_ON_HOLD", serialNo.toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_IS_NOT_ON_HOLD",
                    "0x" + serialNo.toString(16)));
        }

        return;
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
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

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
            mCA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CERT_REQUEST_NOT_FOUND", request.getRequestId().toString()));
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
                mCA.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_CA_ISSUE_ERROR", Integer.toString(i), rid, e.toString()));
                throw e;
            }
        }
        String crmfReqId = request.getExtDataInString(IRequest.CRMF_REQID);
        EBaseException ex = null;

        for (i = 0; i < certs.length; i++) {
            try {
                mService.storeX509Cert(rid, certs[i], crmfReqId, challengePassword);
            } catch (EBaseException e) {
                e.printStackTrace();
                mCA.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_CA_STORE_ERROR", Integer.toString(i), rid, e.toString()));
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
                    mCA.log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_DELETE_CERT_ERROR", serialNo.toString(), e.toString()));
                }
            }
            throw ex;
        }

        request.setExtData(IRequest.ISSUED_CERTS, certs);

        return true;
    }
}

class serviceRenewal implements IServant {
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
            mCA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CERT_REQUEST_NOT_FOUND", request.getRequestId().toString()));
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
                        mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_NULL_SERIAL_NUMBER"));
                        throw new ECAException(
                                CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                    }
                    serialnum = (SerialNumber)
                            serialno.get(CertificateSerialNumber.NUMBER);
                } catch (IOException e) {
                    if (Debug.ON)
                        e.printStackTrace();
                    mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ERROR_GET_CERT", e.toString()));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                } catch (CertificateException e) {
                    if (Debug.ON)
                        e.printStackTrace();
                    mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ERROR_GET_CERT", e.toString()));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }
                if (serialnum == null) {
                    mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ERROR_GET_CERT", ""));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }
                BigInt serialnumBigInt = serialnum.getNumber();
                BigInteger oldSerialNo = serialnumBigInt.toBigInteger();

                // get cert record
                CertRecord certRecord = (CertRecord)
                        mCA.getCertificateRepository().readCertificateRecord(oldSerialNo);

                if (certRecord == null) {
                    mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_NOT_FROM_CA", oldSerialNo.toString()));
                    svcerrors[i] = new ECAException(
                            CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                                    oldSerialNo.toString())).toString();
                    continue;
                }

                // check if cert has been revoked.
                String certStatus = certRecord.getStatus();

                if (certStatus.equals(ICertRecord.STATUS_REVOKED) ||
                        certStatus.equals(ICertRecord.STATUS_REVOKED_EXPIRED)) {
                    mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_RENEW_REVOKED", oldSerialNo.toString()));
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
                            mCA.log(ILogger.LL_FAILURE,
                                    CMS.getLogMessage("CMSCORE_CA_MISSING_RENEWED", serial.toString()));
                            svcerrors[i] = new ECAException(
                                    CMS.getUserMessage("CMS_CA_ERROR_GETTING_RENEWED_CERT",
                                            oldSerialNo.toString(), serial.toString())).toString();
                            continue;
                        }
                        // get cert record
                        CertRecord cRecord = (CertRecord)
                                mCA.getCertificateRepository().readCertificateRecord(serial);

                        if (cRecord == null) {
                            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_NOT_FROM_CA", serial.toString()));
                            svcerrors[i] = new ECAException(
                                    CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                                            serial.toString())).toString();
                            continue;
                        }
                        // Check renewed certificate already REVOKED or EXPIRED
                        String status = cRecord.getStatus();

                        if (status.equals(ICertRecord.STATUS_REVOKED) ||
                                status.equals(ICertRecord.STATUS_REVOKED_EXPIRED)) {
                            Debug.trace("It is already revoked or Expired !!!");
                        } // it is still new ... So just return this certificate to user
                        else {
                            Debug.trace("It is still new !!!");
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
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CANNOT_RENEW", Integer.toString(i), request
                        .getRequestId().toString()));
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
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_NO_RENEW", request.getRequestId().toString()));
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
                Debug.trace(ee.toString());
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
    private ICertificateAuthority mCA;
    private CAService mService;
    private MessageDigest mSHADigest = null;

    public serviceCheckChallenge(CAService service) {
        mService = service;
        mCA = mService.getCA();
        try {
            mSHADigest = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));
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
                Debug.trace(ee.toString());
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
        String b64E = Utils.base64encode(pwdDigest);

        return "{SHA}" + b64E;
    }
}

class serviceRevoke implements IServant {
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
            mCA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CRL_NOT_FOUND", request.getRequestId().toString()));
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
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CANNOT_REVOKE", Integer.toString(i), request
                        .getRequestId().toString(), e.toString()));
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
            CMS.debug(CMS.getLogMessage("CMSCORE_CA_CLONE_READ_REVOKED"));
            BigInteger revokedCertIds[] =
                    new BigInteger[revokedCerts.length];

            for (int i = 0; i < revokedCerts.length; i++) {
                revokedCertIds[i] = revokedCerts[i].getSerialNumber();
            }
            request.deleteExtData(IRequest.CERT_INFO);
            request.deleteExtData(IRequest.OLD_CERTS);
            request.setExtData(IRequest.REVOKED_CERT_RECORDS, revokedCertIds);

            CMS.debug(CMS.getLogMessage("CMSCORE_CA_CLONE_READ_REVOKED_CONNECTOR"));

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

        if (Debug.ON) {
            Debug.trace("serviceRevoke sendStatus=" + sendStatus);
        }

        return sendStatus;
    }
}

class serviceUnrevoke implements IServant {
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
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_UNREVOKE_MISSING_SERIAL"));
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
                    mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_UNREVOKE_MISSING_SERIAL"));
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
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_UNREVOKE_FAILED", oldSerialNo[i].toString(),
                        request.getRequestId().toString()));
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
            mCA.log(ILogger.LL_FAILURE, e.toString());
            throw new EBaseException(e.toString());
        }
        request.setExtData(IRequest.CACERTCHAIN, certChainOut.toByteArray());
        return true;
    }
}

class serviceGetCRL implements IServant {
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
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_GETCRL_FIND_CRL"));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CRL_ISSUEPT_NOT_FOUND", e.toString()));
        } catch (CRLException e) {
            mCA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_GETCRL_INST_CRL", ICertificateAuthority.PROP_MASTER_CRL));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CRL_ISSUEPT_NOGOOD", ICertificateAuthority.PROP_MASTER_CRL));
        } catch (X509ExtensionException e) {
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_GETCRL_NO_ISSUING_REC"));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_CRL_ISSUEPT_EXT_NOGOOD",
                            ICertificateAuthority.PROP_MASTER_CRL));
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
            mCA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CERT4CRL_NO_ENTRY", request.getRequestId().toString()));
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
            mCA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CERT4CRL_NO_ENTRY", request.getRequestId().toString()));
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
                mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CERT4CRL_NO_REC", Integer.toString(i),
                        request.getRequestId().toString(), e.toString()));
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
            mCA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_UNREVOKE_MISSING_SERIAL"));
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
                mCA.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_CA_DELETE_CERT_ERROR", oldSerialNo[i].toString(), e.toString()));
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
