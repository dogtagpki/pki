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
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;

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
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.IAuditor;

public class PKIServerSocketListener implements SSLSocketListener {

    private static Logger logger = LoggerFactory.getLogger(PKIServerSocketListener.class);

    /**
     * The socketInfos map is a storage for socket information that may not be available
     * after the socket has been closed such as client IP address and subject ID. The
     * WeakHashMap is used here to allow the map key (i.e. the socket object) to be
     * garbage-collected since there is no guarantee that socket will be closed with an
     * SSL alert for a proper map entry removal.
     */
    Map<SSLSocket,Map<String,Object>> socketInfos = new WeakHashMap<>();

    @Override
    public void alertReceived(SSLAlertEvent event) {
        try {
            SSLSocket socket = event.getSocket();

            InetAddress clientAddress = socket.getInetAddress();
            InetAddress serverAddress = socket.getLocalAddress();
            String clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
            String serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

            SSLSecurityStatus status = socket.getStatus();
            X509Certificate peerCertificate = status.getPeerCertificate();
            Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
            String subjectID = subjectDN == null ? "" : subjectDN.toString();

            int description = event.getDescription();
            String reason = SSLAlertDescription.valueOf(description).toString();

            logger.debug("SSL alert received:");
            logger.debug(" - reason: " + reason);
            logger.debug(" - client: " + clientIP);
            logger.debug(" - server: " + serverIP);
            logger.debug(" - subject: " + subjectID);

            IAuditor auditor = CMS.getAuditor();

            String auditMessage = CMS.getLogMessage(
                    AuditEvent.ACCESS_SESSION_TERMINATED,
                    clientIP,
                    serverIP,
                    subjectID,
                    reason);

            auditor.log(auditMessage);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    @Override
    public void alertSent(SSLAlertEvent event) {
        try {
            SSLSocket socket = event.getSocket();

            int description = event.getDescription();
            String reason = SSLAlertDescription.valueOf(description).toString();

            String eventType;
            String clientIP;
            String serverIP;
            String subjectID;

            if (description == SSLAlertDescription.CLOSE_NOTIFY.getID()) {

                eventType = AuditEvent.ACCESS_SESSION_TERMINATED;

                // get socket info from socketInfos map since socket has been closed
                Map<String,Object> info = socketInfos.get(socket);
                clientIP = (String)info.get("clientIP");
                serverIP = (String)info.get("serverIP");
                subjectID = (String)info.get("subjectID");

            } else {

                eventType = AuditEvent.ACCESS_SESSION_ESTABLISH_FAILURE;

                // get socket info from the socket itself
                InetAddress clientAddress = socket.getInetAddress();
                InetAddress serverAddress = socket.getLocalAddress();
                clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
                serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

                SSLSecurityStatus status = socket.getStatus();
                X509Certificate peerCertificate = status.getPeerCertificate();
                Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
                subjectID = subjectDN == null ? "" : subjectDN.toString();
            }

            logger.debug("SSL alert sent:");
            logger.debug(" - reason: " + reason);
            logger.debug(" - client: " + clientIP);
            logger.debug(" - server: " + serverIP);
            logger.debug(" - subject: " + subjectID);

            IAuditor auditor = CMS.getAuditor();

            String auditMessage = CMS.getLogMessage(
                    eventType,
                    clientIP,
                    serverIP,
                    subjectID,
                    reason);

            auditor.log(auditMessage);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    @Override
    public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
        try {
            SSLSocket socket = event.getSocket();

            InetAddress clientAddress = socket.getInetAddress();
            InetAddress serverAddress = socket.getLocalAddress();
            String clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
            String serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

            SSLSecurityStatus status = socket.getStatus();
            X509Certificate peerCertificate = status.getPeerCertificate();
            Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
            String subjectID = subjectDN == null ? "" : subjectDN.toString();

            logger.debug("Handshake completed:");
            logger.debug(" - client: " + clientIP);
            logger.debug(" - server: " + serverIP);
            logger.debug(" - subject: " + subjectID);

            // store socket info in socketInfos map
            Map<String,Object> info = new HashMap<>();
            info.put("clientIP", clientIP);
            info.put("serverIP", serverIP);
            info.put("subjectID", subjectID);
            socketInfos.put(socket, info);

            IAuditor auditor = CMS.getAuditor();

            String auditMessage = CMS.getLogMessage(
                    AuditEvent.ACCESS_SESSION_ESTABLISH_SUCCESS,
                    clientIP,
                    serverIP,
                    subjectID);

            auditor.log(auditMessage);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }
}
