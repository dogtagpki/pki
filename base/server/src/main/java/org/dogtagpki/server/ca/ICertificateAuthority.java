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
package org.dogtagpki.server.ca;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.cmscore.dbs.CertificateRepository;

/**
 * An interface represents a Certificate Authority that is
 * responsible for certificate specific operations.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface ICertificateAuthority extends ISubsystem {


    public static final String ID = "ca";

    public static final String PROP_REGISTRATION = "Registration";
    public static final String PROP_POLICY = "Policy";
    public static final String PROP_GATEWAY = "gateway";
    public static final String PROP_CLASS = "class";
    public static final String PROP_TYPE = "type";
    public static final String PROP_IMPL = "impl";
    public static final String PROP_PLUGIN = "plugin";
    public static final String PROP_INSTANCE = "instance";
    public static final String PROP_LISTENER_SUBSTORE = "listener";
    public final static String PROP_LDAP_PUBLISH_SUBSTORE = "ldappublish";
    public final static String PROP_ENABLE_PUBLISH = "enablePublish";
    public final static String PROP_ENABLE_LDAP_PUBLISH = "enableLdapPublish";

    public final static String PROP_X509CERT_VERSION = "X509CertVersion";
    public final static String PROP_ENABLE_PAST_CATIME = "enablePastCATime";
    public final static String PROP_ENABLE_PAST_CATIME_CACERT = "enablePastCATime_caCert";
    public final static String PROP_DEF_VALIDITY = "DefaultIssueValidity";
    public final static String PROP_FAST_SIGNING = "fastSigning";
    public static final String PROP_ENABLE_ADMIN_ENROLL =
            "enableAdminEnroll";

    // make this public so agent gateway can access for now.
    public final static String PROP_CRL_PAGE_SIZE = "pageSize";
    public final static String PROP_MASTER_CRL = "MasterCRL";
    public final static String PROP_CRLEXT_SUBSTORE = "extension";
    public final static String PROP_ISSUING_CLASS =
            "com.netscape.cmscore.ca.CRLIssuingPoint";
    public final static String PROP_EXPIREDCERTS_CLASS =
            "com.netscape.cmscore.ca.CRLWithExpiredCerts";

    public final static String PROP_NOTIFY_SUBSTORE = "notification";
    public final static String PROP_CERT_ISSUED_SUBSTORE = "certIssued";
    public final static String PROP_CERT_REVOKED_SUBSTORE = "certRevoked";
    public final static String PROP_REQ_IN_Q_SUBSTORE = "requestInQ";
    public final static String PROP_PUB_QUEUE_SUBSTORE = "publishingQueue";

    public final static String PROP_ISSUER_NAME = "name";
    public final static String PROP_CA_NAMES = "CAs";

    public final static String PROP_ENABLE_OCSP = "ocsp";
    public final static String PROP_ID = "id";

    /**
     * Retrieves the certificate repository where all the locally
     * issued certificates are kept.
     *
     * @return CA's certificate repository
     */
    public CertificateRepository getCertificateRepository();

    public Map<Object, Long> getNonces(HttpServletRequest request, String name);

    /**
     * Retrieves the CA certificate chain.
     *
     * @return the CA certificate chain
     */
    public CertificateChain getCACertChain();

    /**
     * Retrieves the CA certificate.
     *
     * @return the CA certificate
     */
    public org.mozilla.jss.crypto.X509Certificate getCaX509Cert();

    /**
     * Retrieves the CA certificate.
     *
     * @return the CA certificate
     */
    public X509CertImpl getCACert() throws EBaseException;

    /**
     * Is this a clone CA?
     *
     * @return true if this is a clone CA
     */
    public boolean isClone();

    /**
     * Logs a message to this certificate authority.
     *
     * @param level logging level
     * @param msg logged message
     */
    public void log(int level, String msg);

    /**
     * get Issuance Protection Private Key
     */
    public org.mozilla.jss.crypto.PrivateKey getIssuanceProtPrivKey();
}
