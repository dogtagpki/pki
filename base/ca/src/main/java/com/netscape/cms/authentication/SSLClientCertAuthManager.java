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
package com.netscape.cms.authentication;

// ldap java sdk

// cert server imports.
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EAuthUserError;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

/**
 * SSL client based authentication manager for RenewalServlet and RevocationServlet.
 *
 * @author chrisho
 */
public class SSLClientCertAuthManager extends AuthManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SSLClientCertAuthManager.class);

    /* required credential to authenticate, client certificate */
    public static final String CRED_CERT = AuthManager.CRED_SSL_CLIENT_CERT;
    public static final String SERIALNUMBER = "serialNumber";
    public static final String ISSUERDN = "issuerDN";
    protected static String[] mRequiredCreds = { CRED_CERT };

    private CertificateRepository mCertDB;

    /**
     * Default constructor, initialization must follow.
     */
    public SSLClientCertAuthManager() {
        super();
    }

    @Override
    public void init(
            AuthenticationConfig authenticationConfig,
            String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        this.authenticationConfig = authenticationConfig;
        mName = name;
        mImplName = implName;
        mConfig = config;
    }

    @Override
    public void init(ConfigStore config) throws EProfileException {
    }

    @Override
    public AuthToken authenticate(AuthCredentials authCred)
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

        CAEngine caEngine = (CAEngine) engine;
        mCertDB = caEngine.getCertificateRepository();

        X509CertImpl clientCert = (X509CertImpl) x509Certs[0];

        BigInteger serialNum = null;

        try {
            serialNum = clientCert.getSerialNumber();
            //serialNum = new BigInteger(s.substring(2), 16);
        } catch (NumberFormatException e) {
            throw new EAuthUserError(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_ATTRIBUTE_VALUE",
                    "Invalid serial number."));
        }

        String clientCertIssuerDN = clientCert.getIssuerName().toString();

        CertRecord record = null;

        try {
            record = mCertDB.readCertificateRecord(serialNum);
        } catch (EBaseException ee) {
            logger.warn("SSLClientCertAuthentication: " + ee.getMessage(), ee);
        }

        if (record != null) {
            String status = record.getStatus();

            if (status.equals("VALID")) {

                CertificateAuthority ca = caEngine.getCA();
                X509CertImpl cacert = ca.getCACert();
                Principal p = cacert.getSubjectName();

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

        authToken.set(AuthToken.TOKEN_CERT, clientCert);

        return authToken;
    }

    @Override
    public void populate(AuthToken token, Request request) throws EProfileException {
    }

    /**
     * prepare this authentication manager for shutdown.
     */
    @Override
    public void shutdown() {
    }

    /**
     * Returns array of required credentials for this authentication manager.
     *
     * @return Array of required credentials.
     */
    @Override
    public String[] getRequiredCreds() {
        return mRequiredCreds;
    }

    @Override
    public String getText(Locale locale) {
        return null;
    }

    @Override
    public Enumeration<String> getValueNames() {
        return null;
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public boolean isValueWriteable(String name) {
        return false;
    }

    @Override
    public boolean isSSLClientRequired() {
        return false;
    }
}
