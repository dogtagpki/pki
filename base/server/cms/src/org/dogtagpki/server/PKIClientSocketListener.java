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

import java.lang.Integer;
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

import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.certsrv.logging.event.ClientAccessSessionEstablishEvent;
import com.netscape.certsrv.logging.event.ClientAccessSessionTerminatedEvent;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.certsrv.apps.CMS;

public class PKIClientSocketListener implements SSLSocketListener {

    private static Logger logger = LoggerFactory.getLogger(PKIClientSocketListener.class);
    private static SignedAuditLogger signedAuditLogger = SignedAuditLogger.getLogger();

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
        String method = "PKIClientSocketListener.alertReceived: ";
CMS.debug(method + "begins");
        try {
            SSLSocket socket = event.getSocket();

            InetAddress serverAddress = socket.getInetAddress();
            InetAddress clientAddress = socket.getLocalAddress();
            String clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
            String serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();
            String serverPort = Integer.toString(socket.getPort());

            SSLSecurityStatus status = socket.getStatus();
/*
            X509Certificate peerCertificate = status.getPeerCertificate();
            Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
            String subjectID = subjectDN == null ? "" : subjectDN.toString();
*/
String subjectID = "SYSTEM";

            int description = event.getDescription();
            String reason = SSLAlertDescription.valueOf(description).toString();

            logger.debug("SSL alert received:");
            logger.debug(" - reason: " + reason);
            logger.debug(" - client: " + clientIP);
            logger.debug(" - server: " + serverIP);
            logger.debug(" - subject: " + subjectID);


            signedAuditLogger.log(ClientAccessSessionTerminatedEvent.createEvent(
                    clientIP,
                    serverIP,
                    serverPort,
                    subjectID,
                    reason));

        CMS.debug(method + "CS_CLIENT_ACCESS_SESSION_TERMINATED");
CMS.debug(method + "clientIP=" + clientIP + " serverIP=" + serverIP + " serverPort=" + serverPort + " reason=" + reason);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    @Override
    public void alertSent(SSLAlertEvent event) {
        String method = "PKIClientSocketListener.alertSent: ";
CMS.debug(method + "begins");
        try {
            SSLSocket socket = event.getSocket();

            int description = event.getDescription();
CMS.debug(method + "got description:"+ description);
            String reason = SSLAlertDescription.valueOf(description).toString();
CMS.debug(method + "got reason:"+ reason);

            SignedAuditEvent auditEvent;
            String clientIP;
            String serverIP;
            String serverPort;
            String subjectID;

            if (description == SSLAlertDescription.CLOSE_NOTIFY.getID()) {

                // get socket info from socketInfos map since socket has been closed
                Map<String,Object> info = socketInfos.get(socket);
                clientIP = (String)info.get("clientIP");
                serverIP = (String)info.get("serverIP");
                serverPort = (String)info.get("serverPort");
                subjectID = (String)info.get("subjectID");

                auditEvent = ClientAccessSessionTerminatedEvent.createEvent(
                        clientIP,
                        serverIP,
                        serverPort,
                        subjectID,
                        reason);

        CMS.debug(method + "CS_CLIENT_ACCESS_SESSION_TERMINATED");
	CMS.debug(method + "clientIP=" + clientIP + " serverIP=" + serverIP+ " serverPort=" + serverPort + " reason=" + reason);

            } else {

                // get socket info from the socket itself
                InetAddress serverAddress = socket.getInetAddress();
                InetAddress clientAddress = socket.getLocalAddress();

                clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
                serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();
                serverPort = Integer.toString(socket.getPort());

                SSLSecurityStatus status = socket.getStatus();
/*
                X509Certificate peerCertificate = status.getPeerCertificate();
                Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
                subjectID = subjectDN == null ? "" : subjectDN.toString();
*/
subjectID = "SYSTEM";

                auditEvent = ClientAccessSessionEstablishEvent.createFailureEvent(
                        clientIP,
                        serverIP,
                        serverPort,
                        subjectID,
                        reason);

            }

            logger.debug("SSL alert sent:");
            logger.debug(" - reason: " + reason);
            logger.debug(" - client: " + clientIP);
            logger.debug(" - server: " + serverIP);
            logger.debug(" - subject: " + subjectID);

            signedAuditLogger.log(auditEvent);

        CMS.debug(method + "CS_CLIENT_ACCESS_SESSION_ESTABLISH_FAILURE");
CMS.debug(method + "clientIP=" + clientIP + " serverIP=" + serverIP + " serverPort=" + serverPort + " reason=" + reason);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    @Override
    public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
        String method = "PKIClientSocketListener.handshakeCompleted: ";
CMS.debug(method + "begins");
        try {
            SSLSocket socket = event.getSocket();

            InetAddress serverAddress = socket.getInetAddress();
            InetAddress clientAddress = socket.getLocalAddress();
            String serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();
            String clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
            String serverPort = Integer.toString(socket.getPort());

            SSLSecurityStatus status = socket.getStatus();
/*
            X509Certificate peerCertificate = status.getPeerCertificate();
            Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
            String subjectID = subjectDN == null ? "" : subjectDN.toString();
*/
String subjectID = "SYSTEM";

            logger.debug("Handshake completed:");
            logger.debug(" - client: " + clientIP);
            logger.debug(" - server: " + serverIP);
            logger.debug(" - subject: " + subjectID);

            // store socket info in socketInfos map
            Map<String,Object> info = new HashMap<>();
            info.put("clientIP", clientIP);
            info.put("serverIP", serverIP);
            info.put("serverPort", serverPort);
            info.put("subjectID", subjectID);
            socketInfos.put(socket, info);

            signedAuditLogger.log(ClientAccessSessionEstablishEvent.createSuccessEvent(
                    clientIP,
                    serverIP,
                    serverPort,
                    subjectID));

        CMS.debug(method + "CS_CLIENT_ACCESS_SESSION_ESTABLISH_SUCCESS");
CMS.debug(method + "clientIP=" + clientIP + " serverIP=" + serverIP + " serverPort=" + serverPort);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }
}
