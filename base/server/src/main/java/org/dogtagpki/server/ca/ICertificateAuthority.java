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

import java.util.Enumeration;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.dogtagpki.legacy.policy.IPolicyProcessor;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestNotifier;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.security.SigningUnit;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.ReplicaIDRepository;

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

    public final static String PROP_CRL_SUBSTORE = "crl";
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

    public final static String PROP_SIGNING_SUBSTORE = "signing";
    public final static String PROP_ENABLE_OCSP = "ocsp";
    public final static String PROP_OCSP_SIGNING_SUBSTORE = "ocsp_signing";
    public final static String PROP_CRL_SIGNING_SUBSTORE = "crl_signing";
    public final static String PROP_ID = "id";

    /**
     * Retrieves the certificate repository where all the locally
     * issued certificates are kept.
     *
     * @return CA's certificate repository
     */
    public CertificateRepository getCertificateRepository();

    /**
     * Retrieves the policy processor of this certificate authority.
     * @return CA's policy processor
     */
    public IPolicyProcessor getPolicyProcessor();

    public boolean noncesEnabled();

    public Map<Object, Long> getNonces(HttpServletRequest request, String name);

    /**
     * Retrieves the next available serial number.
     *
     * @return next available serial number
     */
    public String getStartSerial();

    /**
     * Sets the next available serial number.
     *
     * @param serial next available serial number
     * @exception EBaseException failed to set next available serial number
     */
    public void setStartSerial(String serial) throws EBaseException;

    /**
     * Retrieves the last serial number that can be used for
     * certificate issuance in this certificate authority.
     *
     * @return the last serial number
     */
    public String getMaxSerial();

    /**
     * Sets the last serial number that can be used for
     * certificate issuance in this certificate authority.
     *
     * @param serial the last serial number
     * @exception EBaseException failed to set the last serial number
     */
    public void setMaxSerial(String serial) throws EBaseException;

    /**
     * Retrieves the default signature algorithm of this certificate authority.
     *
     * @return the default signature algorithm of this CA
     */
    public SignatureAlgorithm getDefaultSignatureAlgorithm();

    /**
     * Retrieves the default signing algorithm of this certificate authority.
     *
     * @return the default signing algorithm of this CA
     */
    public String getDefaultAlgorithm();

    /**
     * Sets the default signing algorithm of this certificate authority.
     *
     * @param algorithm new default signing algorithm
     * @exception EBaseException failed to set the default signing algorithm
     */
    public void setDefaultAlgorithm(String algorithm) throws EBaseException;

    /**
     * Retrieves the supported signing algorithms of this certificate authority.
     *
     * @return the supported signing algorithms of this CA
     */
    public String[] getCASigningAlgorithms();

    /**
     * Retrieves the default validity period.
     *
     * @return the default validity length in days
     */
    public long getDefaultValidity();

    /**
     * Adds CRL issuing point with the given identifier and description.
     *
     * @param crlSubStore sub-store with all CRL issuing points
     * @param id CRL issuing point id
     * @param description CRL issuing point description
     * @return true if CRL issuing point was successfully added
     */
    public boolean addCRLIssuingPoint(IConfigStore crlSubStore, String id,
                                      boolean enable, String description);

    /**
     * Deletes CRL issuing point with the given identifier.
     *
     * @param crlSubStore sub-store with all CRL issuing points
     * @param id CRL issuing point id
     */
    public void deleteCRLIssuingPoint(IConfigStore crlSubStore, String id);

    /**
     * Retrieves the Replica ID repository.
     *
     * @return CA's Replica ID repository
     */
    public ReplicaIDRepository getReplicaRepository();

    /**
     * Retrieves all request listeners.
     *
     * @return name enumeration of all request listeners
     */
    public Enumeration<String> getRequestListenerNames();

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
     * Updates the CRL immediately for MasterCRL issuing point if it exists.
     *
     * @exception EBaseException failed to create or publish CRL
     */
    public void updateCRLNow() throws EBaseException;

    /**
     * Publishes the CRL immediately for MasterCRL issuing point if it exists.
     *
     * @exception EBaseException failed to publish CRL
     */
    public void publishCRLNow() throws EBaseException;

    /**
     * Retrieves the signing unit that manages the CA signing key for
     * signing certificates.
     *
     * @return the CA signing unit for certificates
     */
    public SigningUnit getSigningUnit();

    /**
     * Retrieves the signing unit that manages the CA signing key for
     * signing CRL.
     *
     * @return the CA signing unit for CRLs
     */
    public SigningUnit getCRLSigningUnit();

    /**
     * Retrieves the signing unit that manages the CA signing key for
     * signing OCSP response.
     *
     * @return the CA signing unit for OCSP responses
     */
    public SigningUnit getOCSPSigningUnit();

    /**
     * Sets the maximium path length in the basic constraint extension.
     *
     * @param num the maximium path length
     */
    public void setBasicConstraintMaxLen(int num);

    /**
     * Is this a clone CA?
     *
     * @return true if this is a clone CA
     */
    public boolean isClone();

    /**
     * Retrieves the request listener by name.
     *
     * @param name request listener name
     * @return the request listener
     */
    public IRequestListener getRequestListener(String name);

    /**
     * get request notifier
     */
    public IRequestNotifier getRequestNotifier();

    /**
     * Registers a request listener.
     *
     * @param listener request listener to be registered
     */
    public void registerRequestListener(IRequestListener listener);

    /**
     * Registers a request listener.
     *
     * @param name under request listener is going to be registered
     * @param listener request listener to be registered
     */
    public void registerRequestListener(String name, IRequestListener listener);

    /**
     * Retrieves the issuer name of this certificate authority.
     *
     * @return the issuer name of this certificate authority
     */
    public X500Name getX500Name();

    /**
     * Retrieves the issuer name of this certificate authority issuing point.
     *
     * @return the issuer name of this certificate authority issuing point
     */
    public X500Name getCRLX500Name();

    /**
     * Signs the given CRL with the specific algorithm.
     *
     * @param crl CRL to be signed
     * @param algname algorithm used for signing
     * @return signed CRL
     * @exception EBaseException failed to sign CRL
     */
    public X509CRLImpl sign(X509CRLImpl crl, String algname)
            throws EBaseException;

    /**
     * Logs a message to this certificate authority.
     *
     * @param level logging level
     * @param msg logged message
     */
    public void log(int level, String msg);

    /**
     * Returns the nickname for the CA signing certificate.
     *
     * @return the nickname for the CA signing certificate
     */
    public String getNickname();

    /**
     * Signs a X.509 certificate template.
     *
     * @param certInfo X.509 certificate template
     * @param algname algorithm used for signing
     * @return signed certificate
     * @exception EBaseException failed to sign certificate
     */
    public X509CertImpl sign(X509CertInfo certInfo, String algname)
            throws EBaseException;

    /**
     * Retrieves the CA service object that is responsible for
     * processing requests.
     *
     * @return CA service object
     */
    public IService getCAService();

    /**
     * Returns the in-memory count of the processed OCSP requests.
     *
     * @return number of processed OCSP requests in memory
     */
    public long getNumOCSPRequest();

    /**
     * Returns the in-memory time (in mini-second) of
     * the processed time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPRequestTotalTime();

    /**
     * Returns the in-memory time (in mini-second) of
     * the signing time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalSignTime();

    /**
     * Returns the total data signed
     * for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalData();

    public CertificateIssuerName getIssuerObj();
    public CertificateSubjectName getSubjectObj();

    /**
     * Return whether this CA is the host authority (not a
     * lightweight authority).
     */
    public boolean isHostAuthority();

    /**
     * Get the AuthorityID of this CA.
     */
    public AuthorityID getAuthorityID();

    /**
     * Get the AuthorityID of this CA's parent CA, if available.
     */
    public AuthorityID getAuthorityParentID();

    /**
     * Return whether CA is enabled.
     */
    public boolean getAuthorityEnabled();

    /**
     * Return whether CA is ready to perform signing operations.
     */
    public boolean isReady();

    /**
     * Throw an exception if CA is not ready to perform signing operations.
     */
    public void ensureReady() throws ECAException;

    /**
     * Return CA description.  May be null.
     */
    public String getAuthorityDescription();

    /**
     * Renew certificate of CA.
     */
    public void renewAuthority(HttpServletRequest httpReq) throws Exception;

    /**
     * Delete this lightweight CA.
     */
    public void deleteAuthority(HttpServletRequest httpReq)
        throws EBaseException;

    /**
     * get Issuance Protection Public Key
     */
    public java.security.PublicKey getIssuanceProtPubKey();

    /**
     * get Issuance Protection Private Key
     */
    public org.mozilla.jss.crypto.PrivateKey getIssuanceProtPrivKey();

    /**
     * get Issuance Protection Certificate
     */
    public org.mozilla.jss.crypto.X509Certificate getIssuanceProtCert();
}
