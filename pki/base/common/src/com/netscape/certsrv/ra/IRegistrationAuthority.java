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
package com.netscape.certsrv.ra;

import java.util.Enumeration;

import netscape.security.x509.X500Name;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestQueue;

/**
 * An interface represents a Registration Authority that is responsible for
 * certificate enrollment operations.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IRegistrationAuthority extends ISubsystem {
    public static final String ID = "ra";

    public static final String PROP_POLICY = "Policy";
    public static final String PROP_REGISTRATION = "Registration";
    public static final String PROP_GATEWAY = "gateway";
    public static final String PROP_NICKNAME = "certNickname";
    // public final static String PROP_PUBLISH_SUBSTORE = "publish";
    // public final static String PROP_LDAP_PUBLISH_SUBSTORE = "ldappublish";
    public final static String PROP_CONNECTOR = "connector";
    public final static String PROP_NEW_NICKNAME = "newNickname";

    // for the notification listeners
    public final static String PROP_NOTIFY_SUBSTORE = "notification";
    public final static String PROP_CERT_ISSUED_SUBSTORE = "certIssued";
    public final static String PROP_CERT_REVOKED_SUBSTORE = "certRevoked";
    public final static String PROP_REQ_IN_Q_SUBSTORE = "requestInQ";

    /**
     * Retrieves the request queue of this registration authority.
     * 
     * @return RA's request queue
     */
    public IRequestQueue getRequestQueue();

    /**
     * Retrieves the publishing processor of this registration authority.
     * 
     * @return RA's publishing processor
     */
    public IPublisherProcessor getPublisherProcessor();

    /**
     * Retrieves the policy processor of this registration authority.
     * 
     * @return RA's policy processor
     */
    public IPolicyProcessor getPolicyProcessor();

    /**
     * Retrieves the RA certificate.
     * 
     * @return the RA certificate
     */
    public org.mozilla.jss.crypto.X509Certificate getRACert();

    /**
     * Retrieves the request in queue listener.
     * 
     * @return the request in queue listener
     */
    public IRequestListener getRequestInQListener();

    /**
     * Retrieves the request listener for issued certificates.
     * 
     * @return the request listener for issued certificates
     */
    public IRequestListener getCertIssuedListener();

    /**
     * Retrieves the request listener for revoked certificates.
     * 
     * @return the request listener for revoked certificates
     */
    public IRequestListener getCertRevokedListener();

    /**
     * Returns the nickname of the RA certificate.
     * 
     * @return the nickname of the RA certificate
     */
    public String getNickname();

    /**
     * Retrieves the nickname of the RA certificate from configuration store.
     * 
     * @return the nickname of the RA certificate
     * @exception EBaseException failed to get nickname
     */
    public String getNewNickName() throws EBaseException;

    /**
     * Sets the new nickname of the RA certifiate.
     * 
     * @param name new nickname
     */
    public void setNewNickName(String name);

    /**
     * Sets the nickname of the RA certifiate.
     * 
     * @param str nickname
     */
    public void setNickname(String str);

    /**
     * Retrieves the default validity period.
     * 
     * @return the default validity length in days
     */
    public long getDefaultValidity();

    /**
     * Retrieves the issuer name of this registration authority.
     * 
     * @return the issuer name of this registration authority
     */
    public X500Name getX500Name();

    /**
     * Retrieves the RA service object that is responsible for processing
     * requests.
     * 
     * @return RA service object
     */
    public IRAService getRAService();

    /**
     * Retrieves the request listener by name.
     * 
     * @param name request listener name
     * @return the request listener
     */
    public IRequestListener getRequestListener(String name);

    /**
     * Retrieves all request listeners.
     * 
     * @return name enumeration of all request listeners
     */
    public Enumeration getRequestListenerNames();
}
