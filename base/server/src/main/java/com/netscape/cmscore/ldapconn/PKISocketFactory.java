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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.mozilla.jss.ssl.SSLClientCertificateSelectionCallback;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedListener;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocketListener;

import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.certsrv.logging.event.ClientAccessSessionEstablishEvent;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;

/**
 * Uses HCL ssl socket.
 *
 * @author Lily Hsiao lhsiao@netscape.com
 */
public class PKISocketFactory implements LDAPSSLSocketFactoryExt {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKISocketFactory.class);

    private static SignedAuditLogger signedAuditLogger = SignedAuditLogger.getLogger();
    private boolean secure;
    private String clientCertNickname;
    private boolean mClientAuth = false;
    private boolean keepAlive = true;
    private String mClientCiphers = null;

    protected List<SSLSocketListener> socketListeners = new ArrayList<>();

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

    public PKISocketFactory(String clientCertNickname) {
        this.secure = true;
        this.clientCertNickname = clientCertNickname;
    }

    public PKISocketFactory(String clientCertNickname, boolean external) {
        this.secure = true;
        this.clientCertNickname = clientCertNickname;
        PKISocketFactory.external = external;
        init();
    }

    public String getClientCertNickname() {
        return clientCertNickname;
    }

    public void setClientCertNickname(String clientCertNickname) {
        this.clientCertNickname = clientCertNickname;
    }

    public void addSocketListener(SSLSocketListener socketListener) {
        socketListeners.add(socketListener);
    }

    public void removeSocketListener(SSLSocketListener socketListener) {
        socketListeners.remove(socketListener);
    }

    public void init() {
        init(null);
    }

    public void init(PKISocketConfig config) {

        logger.info("PKISocketFactory: Initializing PKISocketFactory");

        if (config == null) {
            // use defaults
            return;
        }

        try {
            keepAlive = config.isKeepAlive();
            logger.debug("PKISocketFactory: - keep alive: " + keepAlive);

            /*
             * about ciphers
             * # for RSA, in CS.cfg
             * tcp.clientCiphers=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
             *
             * # for ECC, in CS.cfg
             * tcp.clientCiphers=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
             *
             * Note: this setting will affect ALL TLS socket creations after
             *   unless overwritten by further settings such as either:
             *   CA->KRA: ca.connector.KRA.clientCiphers
             *   TPS->KRA/CA/TKS: tps.connector.<ca|kra|tks id>.clientCiphers
             */
            mClientCiphers = config.getClientCiphers();
            logger.debug("PKISocketFactory: - client ciphers: " + mClientCiphers);

            if (mClientCiphers != null) {
                mClientCiphers = mClientCiphers.trim();

                if (!mClientCiphers.isEmpty()) {
                    CryptoUtil.setClientCiphers(mClientCiphers);
                }
            }

        } catch (Exception e) {
            String message = "Unable to initialize socket factory: " + e.getMessage();
            logger.error("PKISocketFactory: " + message, e);
            throw new RuntimeException(message, e);
        }
    }

    public SSLSocket makeSSLSocket(String host, int port) throws UnknownHostException, IOException {

        logger.info("PKISocketFactory: Creating SSL socket for " + host + ":" + port);

        // let it inherit TLS range and cipher settings

        SSLSocket s;

        if (clientCertNickname == null) {
            s = new SSLSocket(host, port);

        } else {
            // Let's create a selection callback in the case the client auth
            // No longer manually set the cert name.
            // This two step process, used in the JSS client auth test suite,
            // appears to be needed to get this working.

            Socket js = new Socket(InetAddress.getByName(host), port);
            s = new SSLSocket(js, host,
                    null,
                    new SSLClientCertificateSelectionCB(clientCertNickname));
        }

        s.setUseClientMode(true);
        s.enableV2CompatibleHello(false);

        for (SSLSocketListener socketListener : socketListeners) {
            s.addSocketListener(socketListener);
        }

       /** opt for general setting in constructor init() above rather than
        *   socket-specific setting
        if (mClientCiphers != null && !mClientCiphers.isEmpty())
            CryptoUtil.setClientCiphers(s, mClientCiphers);
        else { // if tcp.clientCiphers in CS.cfg not set, take default
            //  debug default ciphers
            int ciphers[] = s.getImplementedCipherSuites();
            if (ciphers == null)
                log(method + "hmm... no ciphers returned from getImplementedCipherSuites");
            for (int cipher : ciphers) {
                boolean enabled = SSLSocket.getCipherPreferenceDefault(cipher);
                String cipherString = "0x" + Integer.toHexString(cipher);
                if (enabled) {
                    log (method + "cipher " + cipherString + " enabled by default");
                } else
                    log (method + "cipher " + cipherString + " NOT enabled by default");
            }
        }
        */

        SSLHandshakeCompletedListener listener = null;

        listener = new ClientHandshakeCB(this);
        s.addHandshakeCompletedListener(listener);

        if (clientCertNickname != null) {
            logger.debug("PKISocketFactory: - client cert: " + clientCertNickname);
            mClientAuth = true;

            //We have already established the manual cert selection callback
            //Doing it this way will provide some debugging info on the candidate certs
        }
        s.forceHandshake();

        return s;
    }

    @Override
    public Socket makeSocket(String host, int port) throws LDAPException {

        Socket s = null;

        try {
            if (!secure) {
                logger.info("PKISocketFactory: Creating socket for " + host + ":" + port);
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

            String message = "Unable to create socket: " + e.getMessage();
            logger.error("PKISocketFactory: " + message, e);

            if (s != null) {
                try {
                    s.close();
                } catch (IOException e1) {
                    logger.error("PKISocketFactory: Unable to close socket: " + e1.getMessage(), e1);
                }
            }

            throw new LDAPException(message, LDAPException.UNAVAILABLE);
        }

        return s;
    }

    @Override
    public boolean isClientAuth() {
        return mClientAuth;
    }

    @Override
    public Object getCipherSuites() {
        return null;
    }

    static class ClientHandshakeCB implements SSLHandshakeCompletedListener {
        Object sc;

        public ClientHandshakeCB(Object sc) {
            this.sc = sc;
        }

        @Override
        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            logger.debug("ClientHandshakeCB: SSL handshake happened");
        }
    }

    static class SSLClientCertificateSelectionCB implements SSLClientCertificateSelectionCallback {
        String desiredCertName = null;

        public SSLClientCertificateSelectionCB(String clientAuthCertNickname) {
            logger.debug("SSLClientCertificateSelectionCB: Setting desired cert nickname to: " + clientAuthCertNickname);
            desiredCertName = clientAuthCertNickname;
        }

        @Override
        public String select(Vector<String> certs) {

            logger.debug("SSLClientCertificatSelectionCB: Entering!");

            if(desiredCertName == null) {
                return null;
            }

            Iterator<String> itr = certs.iterator();
            String selection = null;

            while(itr.hasNext()){
                String candidate = itr.next();
                logger.debug("SSLClientCertificatSelectionCB: Candidate cert: " + candidate);
                if(desiredCertName.equalsIgnoreCase(candidate)) {
                    selection = candidate;
                    logger.debug("SSLClientCertificateSelectionCB: desired cert found in list: " + desiredCertName);
                    break;
                }
            }

            logger.debug("SSLClientCertificateSelectionCB: returning: " + selection);
            return selection;
        }
    }
}
