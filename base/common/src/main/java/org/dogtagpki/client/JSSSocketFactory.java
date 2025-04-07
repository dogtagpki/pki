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

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.http.HttpHost;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.protocol.HttpContext;
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
public class JSSSocketFactory implements LayeredConnectionSocketFactory {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JSSSocketFactory.class);

    PKIConnection connection;

    public JSSSocketFactory(PKIConnection connection) {
        this.connection = connection;
    }

    @Override
    public Socket createSocket(HttpContext arg0) throws IOException {
        return SocketFactory.getDefault().createSocket();
    }

    @Override
    public Socket createLayeredSocket(Socket socket, String remoteHost, int port, HttpContext context)
            throws IOException, UnknownHostException {
        JSSSocket jssSocket;

        SSLSocketFactory socketFactory;
        try {
            CryptoManager.getInstance();

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
            KeyManager[] kms = kmf.getKeyManagers();

            JSSTrustManager trustManager = new JSSTrustManager();
            trustManager.setHostname(remoteHost);
            trustManager.setCallback(connection.getCallback());
            trustManager.setEnableCertRevokeVerify(connection.getConfig().isCertRevocationVerify());

            TrustManager[] tms = new TrustManager[] { trustManager };

            SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
            ctx.init(kms, tms, null);

            socketFactory = ctx.getSocketFactory();

        } catch (Exception e) {
            throw new IOException("Unable to create SSL socket factory: " + e.getMessage(), e);
        }

        try {
            if (socket == null) {
                logger.info("Creating new SSL socket");
                jssSocket = (JSSSocket) socketFactory.createSocket(
                        InetAddress.getByName(remoteHost),
                        port);

            } else {
                logger.info("Creating SSL socket with existing socket");
                jssSocket = (JSSSocket) socketFactory.createSocket(
                        socket,
                        remoteHost,
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
    public Socket connectSocket(
            int connTimeout,
            Socket socket,
            HttpHost host,
            InetSocketAddress remoteAddress,
            InetSocketAddress localAddress,
            HttpContext context)
            throws IOException,
            UnknownHostException {

        String hostname = null;
        int port = 0;

        if (host != null) {
            hostname = host.getHostName();
            port = host.getPort();
        } else if(remoteAddress != null) {
            hostname = remoteAddress.getHostName();
            port = remoteAddress.getPort();
        }

        if (socket == null) {
            socket = new Socket();
        }
        if (!socket.isConnected()) {
            if (localAddress != null) {
                socket.bind(localAddress);
            }
            if (remoteAddress != null) {
                socket.connect(remoteAddress, connTimeout);
            }
        }

        return createLayeredSocket(socket, hostname, port, context);
    }

}
