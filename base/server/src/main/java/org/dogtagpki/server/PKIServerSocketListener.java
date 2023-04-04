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
import java.security.cert.Certificate;
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
import org.mozilla.jss.ssl.javax.JSSEngine;
import org.mozilla.jss.ssl.javax.JSSSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.certsrv.logging.event.AccessSessionEstablishEvent;
import com.netscape.certsrv.logging.event.AccessSessionTerminatedEvent;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmscore.apps.CMSEngine;

public class PKIServerSocketListener implements SSLSocketListener {

    private static Logger logger = LoggerFactory.getLogger(PKIServerSocketListener.class);
    private static SignedAuditLogger signedAuditLogger = SignedAuditLogger.getLogger();

    private static final String defaultUnknown = "--";

    protected CMSEngine engine;

    /**
     * The socketInfos map is a storage for socket information that may not be available
     * after the socket has been closed such as client IP address and subject ID. The
     * WeakHashMap is used here to allow the map key (i.e. the socket object) to be
     * garbage-collected since there is no guarantee that socket will be closed with an
     * SSL alert for a proper map entry removal.
     */
    Map<SSLSocket,Map<String,Object>> socketInfos = new WeakHashMap<>();

    public PKIServerSocketListener() {
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    @Override
    public void alertReceived(SSLAlertEvent event) {

        if (engine == null || engine.isInRunningState() == false) {
            return;
        }

        try {
            SSLSocket socket = event.getSocket();
            JSSEngine engine = event.getEngine();

            InetAddress clientAddress = null;
            InetAddress serverAddress = null;
            /**
             * Set these ip related quantities to -
             * This is because with the engine implementation we
             * can't get some of this info, but with a Socket we can
             */
            String clientIP = defaultUnknown;
            String serverIP = defaultUnknown;
            String subjectID = defaultUnknown;
            String hostname = defaultUnknown;
            SSLSecurityStatus status = null;

            if(socket != null) {
                clientAddress = socket.getInetAddress();
                serverAddress = socket.getLocalAddress();
                clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
                serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

                status = socket.getStatus();
                X509Certificate peerCertificate = status.getPeerCertificate();
                Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
                subjectID = subjectDN == null ? "" : subjectDN.toString();
            } else {
                if(engine != null) {
                    JSSSession session = engine.getSession();
                    if(session != null) {
                        Certificate[] certs = session.getPeerCertificates();
                        if(certs != null) {
                            X509Certificate cert = (X509Certificate) certs[0];
                            if(cert != null) {
                                subjectID = cert.getSubjectDN().toString();
                            }
                        }
                    }
                }
            }
            int description = event.getDescription();
            String reason = "serverAlertReceived: " + SSLAlertDescription.valueOf(description).toString();

            logger.debug("PKIServerSocketListener: SSL alert received:");
            logger.debug("- reason: " + reason);
            logger.debug("- client: " + clientIP);
            logger.debug("- server: " + serverIP);
            logger.debug("- subject: " + subjectID);

            signedAuditLogger.log(AccessSessionTerminatedEvent.createEvent(
                    clientIP,
                    serverIP,
                    subjectID,
                    reason));

        } catch (Exception e) {
            logger.error("PKIServerSocketListener: " + e.getMessage(), e);
        }
    }

    @Override
    public void alertSent(SSLAlertEvent event) {

        if (engine == null || engine.isInRunningState() == false) {
            return;
        }
        try {
            SSLSocket socket = event.getSocket();
            JSSEngine engine = event.getEngine();

            int description = event.getDescription();
            String reason = "serverAlertSent: " + SSLAlertDescription.valueOf(description).toString();

            SignedAuditEvent auditEvent;
            String clientIP = defaultUnknown;
            String serverIP = defaultUnknown;
            String subjectID = defaultUnknown;

            InetAddress clientAddress =  null;
            InetAddress serverAddress = null;

            if (description == SSLAlertDescription.CLOSE_NOTIFY.getID()) {

                // get socket info from socketInfos map since socket has been closed
            if(socket != null) {
                Map<String,Object> info = socketInfos.get(socket);
                clientIP = (String)info.get("clientIP");
                serverIP = (String)info.get("serverIP");
                subjectID = (String)info.get("subjectID");
            } else {
                if(engine != null) {
                    JSSSession session = engine.getSession();
                    if(session != null) {
                        Certificate[] certs = session.getPeerCertificates();
                        if(certs != null) {
                             X509Certificate cert = (X509Certificate) certs[0];
                             subjectID = cert.getSubjectDN().toString();
                        }
                    }
                }
            }

            auditEvent = AccessSessionTerminatedEvent.createEvent(
                    clientIP,
                    serverIP,
                    subjectID,
                    reason);

            } else {
                // get socket info from the socket itself
                if(socket != null) {
                    clientAddress = socket.getInetAddress();
                    serverAddress = socket.getLocalAddress();
                    clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
                    serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

                    SSLSecurityStatus status = socket.getStatus();
                    X509Certificate peerCertificate = status.getPeerCertificate();
                    Principal subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
                    subjectID = subjectDN == null ? "" : subjectDN.toString();

               } else {
                   if(engine != null) {
                        JSSSession session = engine.getSession();
                        if(session != null) {
                            Certificate[] certs = session.getPeerCertificates();
                            if(certs != null) {
                                 X509Certificate cert = (X509Certificate) certs[0];
                                 if(cert != null) {
                                     subjectID = cert.getSubjectDN().toString();
                                 }
                            }
                        }
                    }
                }

                auditEvent = AccessSessionEstablishEvent.createFailureEvent(
                        clientIP,
                        serverIP,
                        subjectID,
                        reason);
            }

            logger.debug("PKIServerSocketListener: SSL alert sent:");
            logger.debug("- reason: " + reason);
            logger.debug("- client: " + clientIP);
            logger.debug("- server: " + serverIP);
            logger.debug("- subject: " + subjectID);

            signedAuditLogger.log(auditEvent);

        } catch (Exception e) {
            logger.error("PKIServerSocketListener: " + e.getMessage(), e);
        }
    }

    @Override
    public void handshakeCompleted(SSLHandshakeCompletedEvent event) {

        if (engine == null || engine.isInRunningState() == false) {
            return;
        }

        try {
            SSLSocket socket = event.getSocket();
            JSSEngine engine = event.getEngine();

            InetAddress clientAddress = null;
            InetAddress serverAddress = null;
            String clientIP = defaultUnknown;
            String serverIP = defaultUnknown;
            SSLSecurityStatus status = null;
            X509Certificate peerCertificate = null;
            Principal subjectDN = null;
            String subjectID = defaultUnknown;

            if(socket != null) {
                clientAddress = socket.getInetAddress();
                serverAddress = socket.getLocalAddress();
                clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
                serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

                status = socket.getStatus();
                peerCertificate = status.getPeerCertificate();
                subjectDN = peerCertificate == null ? null : peerCertificate.getSubjectDN();
                subjectID = subjectDN == null ? "" : subjectDN.toString();
                // store socket info in socketInfos map
                Map<String,Object> info = new HashMap<>();
                info.put("clientIP", clientIP);
                info.put("serverIP", serverIP);
                info.put("subjectID", subjectID);
                socketInfos.put(socket, info);
            } else {
                if(engine != null) {
                    JSSSession session = engine.getSession();
                    if(session != null) {
                        Certificate[] certs = session.getPeerCertificates();
                        if(certs != null) {
                            X509Certificate cert = (X509Certificate) certs[0];
                            if(cert != null) {
                                subjectID = cert.getSubjectDN().toString();
                            }
                        }
                    }
                }
            }
            logger.debug("PKIServerSocketListener: Handshake completed:");
            logger.debug("- client: " + clientIP);
            logger.debug("- server: " + serverIP);
            logger.debug("- subject: " + subjectID);

            signedAuditLogger.log(AccessSessionEstablishEvent.createSuccessEvent(
                    clientIP,
                    serverIP,
                    subjectID));
        } catch (Exception e) {
            logger.error("PKIServerSocketListener: " + e.getMessage(), e);
        }
    }
}
