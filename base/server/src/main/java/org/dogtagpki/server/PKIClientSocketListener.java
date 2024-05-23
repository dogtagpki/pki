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

import java.math.BigInteger;
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
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;

public class PKIClientSocketListener implements SSLSocketListener {

    private static Logger logger = LoggerFactory.getLogger(PKIClientSocketListener.class);

    protected CMSEngine engine;

    /**
     * The socketInfos map is a storage for socket information that may not be available
     * after the socket has been closed such as client IP address and subject ID. The
     * WeakHashMap is used here to allow the map key (i.e. the socket object) to be
     * garbage-collected since there is no guarantee that socket will be closed with an
     * SSL alert for a proper map entry removal.
     */
    Map<SSLSocket,Map<String,Object>> socketInfos = new WeakHashMap<>();

    public PKIClientSocketListener() {
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    @Override
    public void alertReceived(SSLAlertEvent event) {
        String method = "PKIClientSocketListener.alertReceived: ";
        logger.debug(method + "begins");

        Auditor auditor = engine.getAuditor();

        try {
            SSLSocket socket = event.getSocket();

            InetAddress serverAddress = socket.getInetAddress();
            InetAddress clientAddress = socket.getLocalAddress();
            String clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
            String serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();
            String serverPort = Integer.toString(socket.getPort());

            SSLSecurityStatus status = socket.getStatus();

            X509Certificate peerCertificate = status.getPeerCertificate();
            String subjectID = "SYSTEM";
            String certID = null;
            String issuerID = null;
            if (peerCertificate != null) {
                Principal subjectDN = peerCertificate.getSubjectDN();
                subjectID = subjectDN == null ? "SYSTEM" :subjectDN.toString();
                BigInteger serial = peerCertificate.getSerialNumber();
                certID = serial == null ? null : serial.toString();
                Principal issuerDN = peerCertificate.getIssuerDN();
                issuerID = issuerDN == null ? null : issuerDN.toString();
            }

            int description = event.getDescription();
            String reason = "clientAlertReceived: " + SSLAlertDescription.valueOf(description).toString();

            auditor.log(ClientAccessSessionTerminatedEvent.createEvent(
                    clientIP,
                    serverIP,
                    serverPort,
                    subjectID,
                    certID,
                    issuerID,
                    reason));

            //logger.debug(method + "CS_CLIENT_ACCESS_SESSION_TERMINATED");

            logger.debug("PKIClientSocketListener: SSL alert received:");
            logger.debug("- reason: " + reason);
            logger.debug("- client: " + clientIP);
            logger.debug("- server: " + serverIP);
            logger.debug("- server port: " + serverPort);
            logger.debug("- subject: " + subjectID);
            logger.debug("- serial: " + certID);
            logger.debug("- issuer: " + issuerID);

        } catch (Exception e) {
            logger.warn("PKIClientSocketListener: " + e.getMessage(), e);
        }
    }

    @Override
    public void alertSent(SSLAlertEvent event) {
        String method = "PKIClientSocketListener.alertSent: ";
        logger.debug(method + "begins");

        Auditor auditor = engine.getAuditor();

        try {
            SSLSocket socket = event.getSocket();

            int description = event.getDescription();
            logger.debug(method + "got description:"+ description);
            String reason = "clientAlertSent: " + SSLAlertDescription.valueOf(description).toString();
            logger.debug(method + "got reason:"+ reason);

            SignedAuditEvent auditEvent;
            String clientIP;
            String serverIP;
            String serverPort;
            String subjectID = "SYSTEM";
            String certID = null;
            String issuerID = null;

            if (description == SSLAlertDescription.CLOSE_NOTIFY.getID()) {

                // get socket info from socketInfos map since socket has been closed
                Map<String,Object> info = socketInfos.get(socket);
                clientIP = (String)info.get("clientIP");
                serverIP = (String)info.get("serverIP");
                serverPort = (String)info.get("serverPort");
                subjectID = (String)info.get("subjectID");
                certID = (String) info.get("certID");
                issuerID = (String) info.get("issuerID");

                auditEvent = ClientAccessSessionTerminatedEvent.createEvent(
                        clientIP,
                        serverIP,
                        serverPort,
                        subjectID,
                        certID,
                        issuerID,
                        reason);

            } else {

                // get socket info from the socket itself
                InetAddress serverAddress = socket.getInetAddress();
                InetAddress clientAddress = socket.getLocalAddress();

                clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
                serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();
                serverPort = Integer.toString(socket.getPort());

                SSLSecurityStatus status = socket.getStatus();

                X509Certificate peerCertificate = status.getPeerCertificate();
                if (peerCertificate != null) {
                    Principal subjectDN = peerCertificate.getSubjectDN();
                    subjectID = subjectDN == null ? "SYSTEM" :subjectDN.toString();
                    BigInteger serial = peerCertificate.getSerialNumber();
                    certID = serial == null ? null : serial.toString();
                    Principal issuerDN = peerCertificate.getIssuerDN();
                    issuerID = issuerDN == null ? null : issuerDN.toString();
                }

                auditEvent = ClientAccessSessionEstablishEvent.createFailureEvent(
                        clientIP,
                        serverIP,
                        serverPort,
                        subjectID,
                        certID,
                        issuerID,
                        reason);

            }

            auditor.log(auditEvent);

            logger.debug("PKIClientSocketListener: SSL alert sent:");
            logger.debug("- reason: " + reason);
            logger.debug("- client: " + clientIP);
            logger.debug("- server: " + serverIP);
            logger.debug("- subject: " + subjectID);
            logger.debug("- serial: " + certID);
            logger.debug("- issuer: " + issuerID);            
            logger.debug("- server port: " + serverPort);

        } catch (Exception e) {
            logger.warn("PKIClientSocketListener: " + e.getMessage(), e);
        }
    }

    @Override
    public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
        String method = "PKIClientSocketListener.handshakeCompleted: ";
        logger.debug(method + "begins");

        Auditor auditor = engine.getAuditor();

        try {
            SSLSocket socket = event.getSocket();

            InetAddress serverAddress = socket.getInetAddress();
            InetAddress clientAddress = socket.getLocalAddress();
            String serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();
            String clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
            String serverPort = Integer.toString(socket.getPort());

            SSLSecurityStatus status = socket.getStatus();

            X509Certificate peerCertificate = status.getPeerCertificate();
            String subjectID = "SYSTEM";
            String certID = null;
            String issuerID = null;
            if (peerCertificate != null) {
                Principal subjectDN = peerCertificate.getSubjectDN();
                subjectID = subjectDN == null ? "SYSTEM" :subjectDN.toString();
                BigInteger serial = peerCertificate.getSerialNumber();
                certID = serial == null ? null : serial.toString();
                Principal issuerDN = peerCertificate.getIssuerDN();
                issuerID = issuerDN == null ? null : issuerDN.toString();
            }

            logger.debug("PKIClientSocketListener: Handshake completed:");
            logger.debug("- client: " + clientIP);
            logger.debug("- server: " + serverIP);
            logger.debug("- server port: " + serverPort);
            logger.debug("- subject: " + subjectID);
            logger.debug("- serial: " + certID);
            logger.debug("- issuer: " + issuerID);

            // store socket info in socketInfos map
            Map<String,Object> info = new HashMap<>();
            info.put("clientIP", clientIP);
            info.put("serverIP", serverIP);
            info.put("serverPort", serverPort);
            info.put("subjectID", subjectID);
            info.put("certID", certID);
            info.put("issuerID", issuerID);
            socketInfos.put(socket, info);

            auditor.log(ClientAccessSessionEstablishEvent.createSuccessEvent(
                    clientIP,
                    serverIP,
                    serverPort,
                    subjectID,
                    certID,
                    issuerID));

        } catch (Exception e) {
            logger.warn("PKIClientSocketListener: " + e.getMessage(), e);
        }
    }
}
