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
package com.netscape.cmscore.ldapconn;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.dogtagpki.server.PKIClientSocketListener;
import org.mozilla.jss.ssl.SSLClientCertificateSelectionCallback;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedListener;
import org.mozilla.jss.ssl.SSLSocket;

import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.certsrv.logging.event.ClientAccessSessionEstablishEvent;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;

/**
 * Uses HCL ssl socket.
 *
 * @author Lily Hsiao lhsiao@netscape.com
 */
public class PKISocketFactory implements LDAPSSLSocketFactoryExt {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKISocketFactory.class);

    private static SignedAuditLogger signedAuditLogger = SignedAuditLogger.getLogger();
    private boolean secure;
    private String mClientAuthCertNickname;
    private boolean mClientAuth;
    private boolean keepAlive;
    PKIClientSocketListener sockListener = null;

    /*
     * Per Bugzilla 1585722, the parameter "external" was introduced
     * to allow this class to be called by an external application.
     * Areas specifically guarded by "!external" are
     * 1. code reaching out to CS.cfg
     * 2. code writing log messages to server log files
     */
    private static boolean external = false;

    public PKISocketFactory() {
    }

    public PKISocketFactory(boolean secure) {
        this.secure = secure;
    }

    public PKISocketFactory(String certNickname) {
        this.secure = true;
        mClientAuthCertNickname = certNickname;
    }

    public PKISocketFactory(String certNickname, boolean external) {
        this.secure = true;
        PKISocketFactory.external = external;
        mClientAuthCertNickname = certNickname;
        init();
    }

    public void init() {
        init (null);
    }
    public void init(PKISocketConfig config) {
        try {
            if (!external) {
                if (config == null) {
                    CMSEngine engine = CMS.getCMSEngine();
                    config = engine.getConfig().getSocketConfig();
                }
                keepAlive = config.isKeepAlive();
            } else {
                keepAlive = true;
            }
            log("TCP Keep-Alive: " + keepAlive);
            sockListener = new PKIClientSocketListener();

        } catch (Exception e) {
            String message = "Unable to read TCP configuration: " + e;
            log(message, e);
            throw new RuntimeException(message, e);
        }
    }

    public SSLSocket makeSSLSocket(String host, int port) throws UnknownHostException, IOException {
        String method = "ldapconn/PKISocketFactory.makeSSLSocket: ";
        log(method + "begins");

        /*
         * let inherit TLS range and cipher settings
         */

        SSLSocket s;

        if (mClientAuthCertNickname == null) {
            s = new SSLSocket(host, port);

        } else {
            // Let's create a selection callback in the case the client auth
            // No longer manually set the cert name.
            // This two step process, used in the JSS client auth test suite,
            // appears to be needed to get this working.

            Socket js = new Socket(InetAddress.getByName(host), port);
            s = new SSLSocket(js, host,
                    null,
                    new SSLClientCertificateSelectionCB(mClientAuthCertNickname));
        }

        s.setUseClientMode(true);
        s.enableV2CompatibleHello(false);

        s.addSocketListener(sockListener);

        SSLHandshakeCompletedListener listener = null;

        listener = new ClientHandshakeCB(this);
        s.addHandshakeCompletedListener(listener);

        if (mClientAuthCertNickname != null) {
            mClientAuth = true;
            log("LdapJssSSLSocket: set client auth cert nickname " +
                    mClientAuthCertNickname);

            //We have already established the manual cert selection callback
            //Doing it this way will provide some debugging info on the candidate certs
        }
        s.forceHandshake();

        return s;
    }

    public Socket makeSocket(String host, int port) throws LDAPException {
        Socket s = null;

        try {
            if (!secure) {
                s = new Socket(host, port);

            } else {
                s = makeSSLSocket(host, port);
            }

            s.setKeepAlive(keepAlive);

        } catch (Exception e) {
            if (!external) {
                // for auditing
                String localIP = "localhost";
                try {
                    localIP = InetAddress.getLocalHost().getHostAddress();
                } catch (UnknownHostException e2) {
                    // default to "localhost";
                }
                SignedAuditEvent auditEvent;
                auditEvent = ClientAccessSessionEstablishEvent.createFailureEvent(
                        localIP,
                        host,
                        Integer.toString(port),
                        "SYSTEM",
                        "connect:" +e.toString());
                signedAuditLogger.log(auditEvent);
            }

            String message = "Unable to create socket: " + e;
            log(message, e);
            if (s != null) {
                try {
                    s.close();
                } catch (IOException e1) {
                    log("Unable to close socket: " + e1.getMessage(), e1);
                }
            }
            throw new LDAPException(message);
        }

        return s;
    }

    public boolean isClientAuth() {
        return mClientAuth;
    }

    public Object getCipherSuites() {
        return null;
    }

    public void log(int level, String msg) {
    }

    private static void log(String msg) {
        log(msg, null);
    }

    private static void log(String msg, Exception e) {
        if(!external && e != null){
            logger.error(msg, e);
        } else if (!external) {
            logger.debug(msg);
        } else {
            if(e != null){
                Logger.getLogger("PKISocketFactory").log(Level.SEVERE, e.getMessage());
            } else {
                Logger.getLogger("PKISocketFactory").log(Level.INFO, msg);
            }
        }
    }

    static class ClientHandshakeCB implements SSLHandshakeCompletedListener {
        Object sc;

        public ClientHandshakeCB(Object sc) {
            this.sc = sc;
        }

        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            log("SSL handshake happened");
        }
    }

    static class SSLClientCertificateSelectionCB implements SSLClientCertificateSelectionCallback {
        String desiredCertName = null;

        public SSLClientCertificateSelectionCB(String clientAuthCertNickname) {
            log("SSLClientCertificateSelectionCB: Setting desired cert nickname to: " + clientAuthCertNickname);
            desiredCertName = clientAuthCertNickname;
        }

        @Override
        public String select(Vector<String> certs) {

            log("SSLClientCertificatSelectionCB: Entering!");

            if(desiredCertName == null) {
                return null;
            }

            @SuppressWarnings("unchecked")
            Iterator<String> itr = certs.iterator();
            String selection = null;

            while(itr.hasNext()){
                String candidate = itr.next();
                log("Candidate cert: " + candidate);
                if(desiredCertName.equalsIgnoreCase(candidate)) {
                    selection = candidate;
                    log("SSLClientCertificateSelectionCB: desired cert found in list: " + desiredCertName);
                    break;
                }
            }

            log("SSLClientCertificateSelectionCB: returning: " + selection);
            return selection;

        }

    }

}
