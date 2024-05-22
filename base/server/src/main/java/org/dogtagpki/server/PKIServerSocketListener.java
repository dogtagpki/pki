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

import java.security.cert.Certificate;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.ssl.SSLAlertDescription;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSecurityStatus;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.nss.SSLFDProxy;
import org.mozilla.jss.ssl.SSLSocketListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.certsrv.logging.event.AccessSessionEstablishEvent;
import com.netscape.certsrv.logging.event.AccessSessionTerminatedEvent;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.security.JssSubsystemConfig;
import org.mozilla.jss.ssl.javax.*;
import org.mozilla.jss.nss.SSL;
import org.mozilla.jss.nss.SSLFDProxy;


public class PKIServerSocketListener implements SSLSocketListener {

    private static Logger logger = LoggerFactory.getLogger(PKIServerSocketListener.class);
    private static SignedAuditLogger signedAuditLogger = SignedAuditLogger.getLogger();

    private static final String defaultUnknown = "--";
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
        CMSEngine cms = CMS.getCMSEngine();
        if(cms == null || cms.isInRunningState() == false) {
            return;
        }

        try {
            SSLSocket socket = event.getSocket();
            JSSEngine sslEngine = event.getEngine();

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
            String certID = defaultUnknown;
            String issuerID = defaultUnknown;
            String hostname = defaultUnknown;
            SSLSecurityStatus status = null;

            if(socket != null) { 
                clientAddress = socket.getInetAddress();
                serverAddress = socket.getLocalAddress();
                clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
                serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

                status = socket.getStatus();
                X509Certificate peerCertificate = status.getPeerCertificate();
                if (peerCertificate != null){
                    Principal subjectDN = peerCertificate.getSubjectDN();
                    subjectID = subjectDN == null ? "" : subjectDN.toString();
                    BigInteger serial = peerCertificate.getSerialNumber();
                    certID = serial == null ? "" : serial.toString();
                    Principal issuerDN = peerCertificate.getIssuerDN();
                    issuerID = issuerDN == null ? "" : issuerDN.toString();
                }
            } else {
                if(sslEngine != null) {
                    JSSSession session = sslEngine.getSession();
                    if(session != null) {
                        Certificate[] certs = session.getPeerCertificates();
                        if(certs != null) {
                            X509Certificate cert = (X509Certificate) certs[0];
                            if(cert != null) {
                                subjectID = cert.getSubjectDN().toString();
                                certID = cert.getSerialNumber().toString();
                                issuerID = cert.getIssuerDN().toString();
                            }
                        }
                        if(session.getRemoteAddr() != null) {
                            clientIP = session.getRemoteAddr();
                        }
                        if(session.getLocalAddr() != null) {
                            serverIP = session.getLocalAddr();
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
            logger.debug("- serial: " + certID);
            logger.debug("- issuer: " + issuerID);

            signedAuditLogger.log(AccessSessionTerminatedEvent.createEvent(
                    clientIP,
                    serverIP,
                    subjectID,
                    certID,
                    issuerID,
                    reason));
        } catch (Exception e) {
            logger.error("PKIServerSocketListener: " + e.getMessage(), e);
        }
    }

    @Override
    public void alertSent(SSLAlertEvent event) {
        CMSEngine cms = CMS.getCMSEngine();
        if(cms == null || cms.isInRunningState() == false) {
            return;
        }
        try {
            SSLSocket socket = event.getSocket();
            JSSEngine sslEngine = event.getEngine();

            int description = event.getDescription();
            String reason = "serverAlertSent: " + SSLAlertDescription.valueOf(description).toString();

            SignedAuditEvent auditEvent;
            String clientIP = defaultUnknown;
            String serverIP = defaultUnknown;
            String subjectID = defaultUnknown;
            String certID = defaultUnknown;
            String issuerID = defaultUnknown;

            InetAddress clientAddress =  null;
            InetAddress serverAddress = null;

            if (description == SSLAlertDescription.CLOSE_NOTIFY.getID()) {

                // get socket info from socketInfos map since socket has been closed
                if(socket != null) {
                    Map<String,Object> info = socketInfos.get(socket);
                    clientIP = (String)info.get("clientIP");
                    serverIP = (String)info.get("serverIP");
                    subjectID = (String)info.get("subjectID");
                    certID = (String)info.get("certID");
                    issuerID = (String)info.get("issuerID");
                } else {
                    if(sslEngine != null) {
                        JSSSession session = sslEngine.getSession();
                        if(session != null) {
                            Certificate[] certs = session.getPeerCertificates();
                            if(certs != null) {
                                X509Certificate cert = (X509Certificate) certs[0];
                                subjectID = cert.getSubjectDN().toString();
                                certID = cert.getSerialNumber().toString();
                                issuerID = cert.getIssuerDN().toString();
                            }
                            if(session.getRemoteAddr() != null) {
                                clientIP = session.getRemoteAddr();
                            }
                            if(session.getLocalAddr() != null) {
                                serverIP = session.getLocalAddr();
                            }
                        }
                    }
                }

                auditEvent = AccessSessionTerminatedEvent.createEvent(
                    clientIP,
                    serverIP,
                    subjectID,
                    certID,
                    issuerID,
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
                    if (peerCertificate != null) {
                        Principal subjectDN = peerCertificate.getSubjectDN();
                        subjectID = subjectDN == null ? "" : subjectDN.toString();
                        BigInteger serial = peerCertificate.getSerialNumber();
                        certID = serial == null ? "" : serial.toString();
                        Principal issuerDN = peerCertificate.getIssuerDN();
                        issuerID = issuerDN == null ? "" : issuerDN.toString();
                    }
               } else {
                   if(sslEngine != null) {
                        JSSSession session = sslEngine.getSession();
                        if(session != null) {
                            Certificate[] certs = session.getPeerCertificates();
                            if(certs != null) {
                                 X509Certificate cert = (X509Certificate) certs[0];
                                 if(cert != null) {
                                     subjectID = cert.getSubjectDN().toString();
                                     certID = cert.getSerialNumber().toString();
                                     issuerID = cert.getIssuerDN().toString();
                                 }
                            }
                            if(session.getRemoteAddr() != null) {
                                clientIP = session.getRemoteAddr();
                            }
                            if(session.getLocalAddr() != null) {
                                serverIP = session.getLocalAddr();
                            }
                        }
                    }
                }

                auditEvent = AccessSessionEstablishEvent.createFailureEvent(
                        clientIP,
                        serverIP,
                        subjectID,
                        certID,
                        issuerID,
                        reason);
            }

            logger.debug("PKIServerSocketListener: SSL alert sent:");
            logger.debug("- reason: " + reason);
            logger.debug("- client: " + clientIP);
            logger.debug("- server: " + serverIP);
            logger.debug("- subject: " + subjectID);
            logger.debug("- serial: " + certID);
            logger.debug("- issuer: " + issuerID);

            signedAuditLogger.log(auditEvent);

        } catch (Exception e) {
            logger.error("PKIServerSocketListener: " + e.getMessage(), e);
        }
    }

    @Override
    public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
        CMSEngine cms = CMS.getCMSEngine();
        if(cms == null || cms.isInRunningState() == false) {
            return;
        }

        //Note: This is an expensive brute force setting for testing only.
        //This config setting should only be set if this kind of testing is explicitly needed.
	boolean invalidateAfterHandshake = false;
	EngineConfig cfg =  null ;
        JssSubsystemConfig jcfg = null;	

	cfg = cms.getConfig();
	if(cfg != null) {
            jcfg = cfg.getJssSubsystemConfig();
	    if(jcfg != null) {
                try {
                    invalidateAfterHandshake = jcfg.getBoolean("ssl.server.invalidateSessionAfterHandshake",false);
                } catch(EBaseException e) {
                    invalidateAfterHandshake = false;
                }
            }
	 }

        try {
            SSLSocket socket = event.getSocket();
            JSSEngine sslEngine = event.getEngine();

            InetAddress clientAddress = null;
            InetAddress serverAddress = null;
            String clientIP = defaultUnknown;
            String serverIP = defaultUnknown;
            SSLSecurityStatus status = null;
            X509Certificate peerCertificate = null;
            Principal subjectDN = null;
            String subjectID = defaultUnknown;
            BigInteger serial = null;
            String certID = defaultUnknown;
            Principal issuerDN = null;
            String issuerID = defaultUnknown;

            if(socket != null) {
		if(invalidateAfterHandshake) {
                    logger.debug("PKIServerSocketListener: Handshake completed: about to invalidate SSLSocket socket as per configuration.");
                    socket.invalidateSession();
                }

                clientAddress = socket.getInetAddress();
                serverAddress = socket.getLocalAddress();
                clientIP = clientAddress == null ? "" : clientAddress.getHostAddress();
                serverIP = serverAddress == null ? "" : serverAddress.getHostAddress();

                status = socket.getStatus();
                peerCertificate = status.getPeerCertificate();
                if (peerCertificate != null) {
                    subjectDN = peerCertificate.getSubjectDN();
                    subjectID = subjectDN == null ? "" : subjectDN.toString();
                    serial = peerCertificate.getSerialNumber();
                    certID = serial == null ? "" : serial.toString();
                    issuerDN = peerCertificate.getIssuerDN();
                    issuerID = issuerDN == null ? "" : issuerDN.toString();
                }
                // store socket info in socketInfos map
                Map<String,Object> info = new HashMap<>();
                info.put("clientIP", clientIP);
                info.put("serverIP", serverIP);
                info.put("subjectID", subjectID);
                info.put("certID", certID);
                info.put("issuerID", issuerID);
                socketInfos.put(socket, info);
            } else {
                if(sslEngine != null) {
                    SSLFDProxy ssl_fd =  sslEngine.getSSLFDProxy();
                    if(ssl_fd != null) {
                        if(invalidateAfterHandshake) {
                            logger.debug("PKIServerSocketListener: Handshake completed: about to invalidate JSSEngine socket as per configuration.");
                            SSL.InvalidateSession(ssl_fd);
                        }
                    }
                    JSSSession session = sslEngine.getSession();
                    if(session != null) {
                        Certificate[] certs = session.getPeerCertificates();
                        if(certs != null) {
                            X509Certificate cert = (X509Certificate) certs[0];
                            if(cert != null) {
                                subjectDN = cert.getSubjectDN();
                                subjectID = subjectDN == null ? "" : subjectDN.toString();
                                serial = cert.getSerialNumber();
                                certID = serial == null ? "" : serial.toString();
                                issuerDN = cert.getIssuerDN();
                                issuerID = issuerDN == null ? "" : issuerDN.toString();
                            }
                        }
                    }
                    if(session.getRemoteAddr() != null) {
                        clientIP = session.getRemoteAddr();
                    }
                    if(session.getLocalAddr() != null) {
                        serverIP = session.getLocalAddr();
                    }
                }
            }
            logger.debug("PKIServerSocketListener: Handshake completed:");
            logger.debug("- client: " + clientIP);
            logger.debug("- server: " + serverIP);
            logger.debug("- subject: " + subjectID);
            logger.debug("- serial: " + certID);
            logger.debug("- issuer: " + issuerID);

            signedAuditLogger.log(AccessSessionEstablishEvent.createSuccessEvent(
                    clientIP,
                    serverIP,
                    subjectID,
                    certID,
                    issuerID));
        } catch (Exception e) {
            logger.error("PKIServerSocketListener: " + e.getMessage(), e);
        }
    }
}
