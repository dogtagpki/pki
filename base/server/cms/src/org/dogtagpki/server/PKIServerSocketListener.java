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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.Principal;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.ssl.SSLAlertDescription;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSecurityStatus;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocketListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.logging.IAuditor;

public class PKIServerSocketListener implements SSLSocketListener {

    private static Logger logger = LoggerFactory.getLogger(PKIServerSocketListener.class);

    @Override
    public void alertReceived(SSLAlertEvent event) {
    }

    @Override
    public void alertSent(SSLAlertEvent event) {
        try {
            SSLSocket socket = event.getSocket();

            SocketAddress remoteSocketAddress = socket.getRemoteSocketAddress();
            InetAddress clientAddress = remoteSocketAddress == null ? null : ((InetSocketAddress)remoteSocketAddress).getAddress();
            InetAddress serverAddress = socket.getLocalAddress();
            String clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
            String serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

            SSLSecurityStatus status = socket.getStatus();
            X509Certificate peerCertificate = status.getPeerCertificate();
            Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
            String subjectID = subjectDN == null ? "" : subjectDN.toString();

            int description = event.getDescription();
            String reason = SSLAlertDescription.valueOf(description).toString();

            logger.debug("SSL alert sent:");
            logger.debug(" - client: " + clientAddress);
            logger.debug(" - server: " + serverAddress);
            logger.debug(" - reason: " + reason);

            IAuditor auditor = CMS.getAuditor();

            if (description == SSLAlertDescription.CLOSE_NOTIFY.getID()) {

                String auditMessage = CMS.getLogMessage(
                        "LOGGING_SIGNED_AUDIT_ACCESS_SESSION_TERMINATED",
                        clientIP,
                        serverIP,
                        subjectID);

                auditor.log(auditMessage);

            } else {

                String auditMessage = CMS.getLogMessage(
                        "LOGGING_SIGNED_AUDIT_ACCESS_SESSION_ESTABLISH_FAILURE",
                        clientIP,
                        serverIP,
                        subjectID,
                        reason);

                auditor.log(auditMessage);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
        try {
            SSLSocket socket = event.getSocket();

            SocketAddress remoteSocketAddress = socket.getRemoteSocketAddress();
            InetAddress clientAddress = remoteSocketAddress == null ? null : ((InetSocketAddress)remoteSocketAddress).getAddress();
            InetAddress serverAddress = socket.getLocalAddress();
            String clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
            String serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

            SSLSecurityStatus status = socket.getStatus();
            X509Certificate peerCertificate = status.getPeerCertificate();
            Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
            String subjectID = subjectDN == null ? "" : subjectDN.toString();

            logger.debug("Handshake completed:");
            logger.debug(" - client: " + clientAddress);
            logger.debug(" - server: " + serverAddress);
            logger.debug(" - subject: " + subjectDN);

            IAuditor auditor = CMS.getAuditor();

            String auditMessage = CMS.getLogMessage(
                    "LOGGING_SIGNED_AUDIT_ACCESS_SESSION_ESTABLISH_SUCCESS",
                    clientIP,
                    serverIP,
                    subjectID);

            auditor.log(auditMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
