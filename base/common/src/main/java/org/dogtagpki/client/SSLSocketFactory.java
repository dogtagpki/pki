//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.client;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.SocketFactory;

import org.apache.http.HttpHost;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.protocol.HttpContext;
import org.mozilla.jss.ssl.SSLAlertDescription;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLAlertLevel;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocketListener;

import com.netscape.certsrv.client.PKIConnection;

/**
 * This class provides blocking socket factory for PKIConnection based on SSLSocket.
 */
public class SSLSocketFactory implements LayeredConnectionSocketFactory {

    PKIConnection connection;

    public SSLSocketFactory(PKIConnection connection) {
        this.connection = connection;
    }

    @Override
    public Socket createSocket(HttpContext arg0) throws IOException {
        return SocketFactory.getDefault().createSocket();
    }

    @Override
    public Socket createLayeredSocket(Socket sock, String remoteHost, int port, HttpContext context)
            throws IOException, UnknownHostException {



        SSLSocket socket;
        if (sock == null) {
            socket = new SSLSocket(remoteHost,
                    port,
                    null,
                    0,
                    connection.getCallback(),
                    null);

        } else {
            socket = new SSLSocket(sock, remoteHost, connection.getCallback(), null);
        }

        String certNickname = connection.getConfig().getCertNickname();
        if (certNickname != null) {
            PKIConnection.logger.info("Client certificate: "+certNickname);
            socket.setClientCertNickname(certNickname);
        }

        socket.addSocketListener(new SSLSocketListener() {

            @Override
            public void alertReceived(SSLAlertEvent event) {

                int intLevel = event.getLevel();
                SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                int intDescription = event.getDescription();
                SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                if (level == SSLAlertLevel.FATAL || PKIConnection.logger.isInfoEnabled()) {
                    PKIConnection.logger.error(level + ": SSL alert received: " + description);
                }
            }

            @Override
            public void alertSent(SSLAlertEvent event) {

                int intLevel = event.getLevel();
                SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                int intDescription = event.getDescription();
                SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                if (level == SSLAlertLevel.FATAL || PKIConnection.logger.isInfoEnabled()) {
                    PKIConnection.logger.error(level + ": SSL alert sent: " + description);
                }
            }

            @Override
            public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            }

        });
        return socket;
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
