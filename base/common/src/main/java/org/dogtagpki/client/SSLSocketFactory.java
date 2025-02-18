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

import org.apache.http.conn.scheme.SchemeLayeredSocketFactory;
import org.apache.http.params.HttpParams;
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
public class SSLSocketFactory implements SchemeLayeredSocketFactory {

    PKIConnection connection;

    public SSLSocketFactory(PKIConnection connection) {
        this.connection = connection;
    }

    @Override
    public Socket createSocket(HttpParams params) throws IOException {
        return null;
    }

    @Override
    public Socket connectSocket(
            Socket sock,
            InetSocketAddress remoteAddress,
            InetSocketAddress localAddress,
            HttpParams params)
            throws IOException,
            UnknownHostException {

        String hostName = null;
        int port = 0;
        if (remoteAddress != null) {
            hostName = remoteAddress.getHostName();
            port = remoteAddress.getPort();
        }

        int localPort = 0;
        InetAddress localAddr = null;

        if (localAddress != null) {
            localPort = localAddress.getPort();
            localAddr = localAddress.getAddress();
        }

        SSLSocket socket;
        if (sock == null) {
            socket = new SSLSocket(InetAddress.getByName(hostName),
                    port,
                    localAddr,
                    localPort,
                    connection.getCallback(),
                    null);

        } else {
            socket = new SSLSocket(sock, hostName, connection.getCallback(), null);
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
