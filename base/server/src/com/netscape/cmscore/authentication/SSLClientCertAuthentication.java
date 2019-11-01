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
package com.netscape.cmscore.authentication;

// ldap java sdk

// cert server imports.
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509Certificate;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.IAuthManager;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.EAuthUserError;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.authentication.AuthManagerConfig;
import com.netscape.cms.authentication.AuthenticationConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * SSL client based authentication.
 * <P>
 *
 * @author chrisho
 * @version $Revision$, $Date$
 */
public class SSLClientCertAuthentication implements IAuthManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SSLClientCertAuthentication.class);

    /* required credential to authenticate, client certificate */
    public static final String CRED_CERT = IAuthManager.CRED_SSL_CLIENT_CERT;
    public static final String SERIALNUMBER = "serialNumber";
    public static final String ISSUERDN = "issuerDN";
    protected static String[] mRequiredCreds = { CRED_CERT };

    private ICertificateAuthority mCA = null;
    private ICertificateRepository mCertDB = null;
    private String mName = null;
    private String mImplName = null;
    private AuthenticationConfig authenticationConfig;
    private AuthManagerConfig mConfig;

    /* Holds configuration parameters accepted by this implementation.
     * This list is passed to the configuration console so configuration
     * for instances of this implementation can be configured through the
     * console.
     */
    protected static String[] mConfigParams =
            new String[] {};

    /**
     * Default constructor, initialization must follow.
     */
    public SSLClientCertAuthentication() {
        super();
    }

    public AuthenticationConfig getAuthenticationConfig() {
        return authenticationConfig;
    }

    public void setAuthenticationConfig(AuthenticationConfig authenticationConfig) {
        this.authenticationConfig = authenticationConfig;
    }

    public void init(String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        logger.info(CMS.getLogMessage("INIT_DONE", name));
    }

    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {

        AuthToken authToken = new AuthToken(this);

        logger.debug("SSLCertAuth: Retrieving client certificates");
        X509Certificate[] x509Certs =
                (X509Certificate[]) authCred.get(CRED_CERT);

        if (x509Certs == null) {
            logger.error("SSLCertAuth: No client certificate found");
            logger.error(CMS.getLogMessage("CMSCORE_AUTH_MISSING_CERT"));
            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_CERT));
        }
        logger.debug("SSLCertAuth: Got client certificate");

        CMSEngine engine = CMS.getCMSEngine();
        mCA = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);

        if (mCA != null) {
            mCertDB = mCA.getCertificateRepository();
        }

        X509CertImpl clientCert = (X509CertImpl) x509Certs[0];

        BigInteger serialNum = null;

        try {
            serialNum = clientCert.getSerialNumber();
            //serialNum = new BigInteger(s.substring(2), 16);
        } catch (NumberFormatException e) {
            throw new EAuthUserError(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_ATTRIBUTE_VALUE",
                    "Invalid serial number."));
        }

        String clientCertIssuerDN = clientCert.getIssuerDN().toString();

        if (mCertDB != null) { /* is CA */
            ICertRecord record = null;

            try {
                record = mCertDB.readCertificateRecord(serialNum);
            } catch (EBaseException ee) {
                logger.warn("SSLClientCertAuthentication: " + ee.getMessage(), ee);
            }
            if (record != null) {
                String status = record.getStatus();

                if (status.equals("VALID")) {

                    X509CertImpl cacert = mCA.getCACert();
                    Principal p = cacert.getSubjectDN();

                    if (!p.toString().equals(clientCertIssuerDN)) {
                        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ISSUER_NAME"));
                    }
                } else {
                    throw new EBaseException(
                            CMS.getUserMessage("CMS_BASE_INVALID_CERT_STATUS", status));
                }
            } else {
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
            }
        } else {

            /*
             * ra, build a request and send through the connection for
             * authentication
             */
            IRequestQueue queue = getReqQueue();

            if (queue != null) {
                IRequest getCertStatusReq = null;

                getCertStatusReq =
                        queue.newRequest(IRequest.GETCERT_STATUS_REQUEST);
                // pass just serial number instead of whole cert
                if (serialNum != null) {
                    getCertStatusReq.setExtData(SERIALNUMBER, serialNum);
                    getCertStatusReq.setExtData(ISSUERDN, clientCertIssuerDN);
                }
                queue.processRequest(getCertStatusReq);
                // check request status...
                RequestStatus status = getCertStatusReq.getRequestStatus();

                if (status == RequestStatus.COMPLETE) {
                    String certStatus =
                            getCertStatusReq.getExtDataInString(IRequest.CERT_STATUS);

                    if (certStatus == null) {
                        String[] params = { "null status" };

                        throw new EBaseException(
                                CMS.getUserMessage("CMS_BASE_INVALID_CERT_STATUS", params));
                    } else if (certStatus.equals("INVALIDCERTROOT")) {
                        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ISSUER_NAME"));
                    } else if (!certStatus.equals("VALID")) {
                        String[] params = { status.toString() };

                        throw new EBaseException(
                                CMS.getUserMessage("CMS_BASE_INVALID_CERT_STATUS", params));
                    }
                } else {
                    logger.error(CMS.getLogMessage("CMSCORE_AUTH_INCOMPLETE_REQUEST"));
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_REQUEST_IN_BAD_STATE"));
                }
            } else {
                logger.error(CMS.getLogMessage("CMSCORE_AUTH_FAILED_GET_QUEUE"));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_GET_QUEUE_FAILED"));
            }
        } // else, ra

        authToken.set(AuthToken.TOKEN_CERT, clientCert);

        return authToken;
    }

    /**
     * prepare this authentication manager for shutdown.
     */
    public void shutdown() {
    }

    /**
     * Returns a list of configuration parameter names.
     * The list is passed to the configuration console so instances of
     * this implementation can be configured through the console.
     *
     * @return String array of configuration parameter names.
     */
    public String[] getConfigParams() {
        return (mConfigParams);
    }

    /**
     * Returns array of required credentials for this authentication manager.
     *
     * @return Array of required credentials.
     */
    public String[] getRequiredCreds() {
        return mRequiredCreds;
    }

    private IRequestQueue getReqQueue() {

        CMSEngine engine = CMS.getCMSEngine();
        IRequestQueue queue = null;

        try {
            IRegistrationAuthority ra = (IRegistrationAuthority) engine.getSubsystem(IRegistrationAuthority.ID);

            if (ra != null) {
                queue = ra.getRequestQueue();
            }
        } catch (Exception e) {
            logger.warn("Unable to get access to the request queue: " + e.getMessage(), e);
        }

        return queue;
    }

    /**
     * Gets the configuration substore used by this authentication manager
     *
     * @return configuration store
     */
    public AuthManagerConfig getConfigStore() {
        return mConfig;
    }

    /**
     * gets the name of this authentication manager instance
     */
    public String getName() {
        return mName;
    }

    /**
     * gets the plugin name of this authentication manager.
     */
    public String getImplName() {
        return mImplName;
    }
}
