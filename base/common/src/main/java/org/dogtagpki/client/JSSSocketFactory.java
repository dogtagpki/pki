//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.http.conn.scheme.SchemeLayeredSocketFactory;
import org.apache.http.params.HttpParams;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.mozilla.jss.ssl.SSLAlertDescription;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLAlertLevel;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSocketListener;
import org.mozilla.jss.ssl.javax.JSSSocket;

import com.netscape.certsrv.client.PKIConnection;

/**
 * This class provides a ocket factory for PKIConnection based on JSSSocket.
 *
 * JSSSocket support both communication models: sync and async. The model is
 * defined in the initial socket and if not specified it is sync.
 */
public class JSSSocketFactory implements SchemeLayeredSocketFactory {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JSSSocketFactory.class);

    PKIConnection connection;

    public JSSSocketFactory(PKIConnection connection) {
        this.connection = connection;
    }

    @Override
    public Socket createSocket(HttpParams params) throws IOException {
        return null;
    }

    @Override
    public Socket connectSocket(Socket socket,
            InetSocketAddress remoteAddress,
            InetSocketAddress localAddress,
            HttpParams params)
            throws IOException,
            UnknownHostException {

        String hostname = null;
        int port = 0;
        if (remoteAddress != null) {
            hostname = remoteAddress.getHostName();
            port = remoteAddress.getPort();
        }

        int localPort = 0;
        InetAddress localAddr = null;

        if (localAddress != null) {
            localPort = localAddress.getPort();
            localAddr = localAddress.getAddress();
        }

        SSLSocketFactory socketFactory;
        try {
            CryptoManager.getInstance();

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
            KeyManager[] kms = kmf.getKeyManagers();

            JSSTrustManager trustManager = new JSSTrustManager();
            trustManager.setHostname(hostname);
            trustManager.setCallback(connection.getCallback());
            trustManager.setEnableCertRevokeVerify(true);

            TrustManager[] tms = new TrustManager[] { trustManager };

            SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
            ctx.init(kms, tms, null);

            socketFactory = ctx.getSocketFactory();

        } catch (Exception e) {
            throw new IOException("Unable to create SSL socket factory: " + e.getMessage(), e);
        }

        JSSSocket jssSocket;
        try {
            if (socket == null) {
                logger.info("Creating new SSL socket");
                jssSocket = (JSSSocket) socketFactory.createSocket(
                        InetAddress.getByName(hostname),
                        port,
                        localAddr,
                        localPort);

            } else {
                logger.info("Creating SSL socket with existing socket");
                jssSocket = (JSSSocket) socketFactory.createSocket(
                        socket,
                        hostname,
                        port,
                        true);
            }

        } catch (Exception e) {
            throw new IOException("Unable to create SSL socket: " + e.getMessage(), e);
        }

        jssSocket.setUseClientMode(true);

        String certNickname = connection.getConfig().getCertNickname();
        if (certNickname != null) {
            logger.info("Client certificate: "+certNickname);
            jssSocket.setCertFromAlias(certNickname);
        }

        jssSocket.setListeners(Arrays.asList(new SSLSocketListener() {

            @Override
            public void alertReceived(SSLAlertEvent event) {

                int intLevel = event.getLevel();
                SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                int intDescription = event.getDescription();
                SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                    logger.error(level + ": SSL alert received: " + description);
                }
            }

            @Override
            public void alertSent(SSLAlertEvent event) {

                int intLevel = event.getLevel();
                SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                int intDescription = event.getDescription();
                SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                    logger.error(level + ": SSL alert sent: " + description);
                }
            }

            @Override
            public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            }
        }));

        jssSocket.startHandshake();

        return jssSocket;
    }

    @Override
    public boolean isSecure(Socket sock) {
        // We only use this factory in the case of SSL Connections.
        return true;
    }

    @Override
    public Socket createLayeredSocket(Socket socket, String target, int port, HttpParams params)
            throws IOException, UnknownHostException {
        // This method implementation is required to get SSL working.
        return null;
    }
}
