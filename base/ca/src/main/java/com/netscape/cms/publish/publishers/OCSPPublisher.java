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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.publish.publishers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.URLEncoder;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.RevokedCertificate;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.publish.Publisher;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.http.HttpRequest;
import com.netscape.cmsutil.http.JssSSLSocketFactory;

import netscape.ldap.LDAPConnection;

/**
 * This publisher writes certificate and CRL into
 * a directory.
 */
public class OCSPPublisher
        extends Publisher
        implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OCSPPublisher.class);

    private static final String PROP_HOST = "host";
    private static final String PROP_PORT = "port";
    private static final String PROP_PATH = "path";
    private static final String PROP_NICK = "nickName";
    private static final String PROP_CLIENT_AUTH_ENABLE = "enableClientAuth";

    private ConfigStore mConfig;
    private String mHost = null;
    private String mPort = null;
    private String mPath = null;
    private String mNickname = null;
    private boolean mClientAuthEnabled = true;

    /**
     * Returns the implementation name.
     */
    @Override
    public String getImplName() {
        return "OCSPPublisher";
    }

    /**
     * Returns the description of the ldap publisher.
     */
    @Override
    public String getDescription() {
        return "This publisher writes the CRL to CMS's OCSP server.";
    }

    @Override
    public String[] getExtendedPluginInfo() {
        String[] params = {
                PROP_HOST + ";string;Host of CMS's OCSP Secure agent service",
                PROP_PORT + ";string;Port of CMS's OCSP Secure agent service",
                PROP_PATH + ";string;URI of CMS's OCSP Secure agent service",
                PROP_NICK + ";string;Nickname of cert used for client authentication",
                PROP_CLIENT_AUTH_ENABLE + ";boolean;Client Authentication enabled",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ldappublish-publisher-ocsppublisher",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Publishes CRLs to a Online Certificate Status Manager, an OCSP responder provided by CMS."
            };

        return params;
    }

    /**
     * Returns the current instance parameters.
     */
    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<>();
        String host = "";
        String port = "";
        String path = "";
        String nickname = "";
        String clientAuthEnabled = "";

        try {
            host = mConfig.getString(PROP_HOST);
        } catch (EBaseException e) {
        }
        v.addElement(PROP_HOST + "=" + host);
        try {
            port = mConfig.getString(PROP_PORT);
        } catch (EBaseException e) {
        }
        v.addElement(PROP_PORT + "=" + port);
        try {
            path = mConfig.getString(PROP_PATH);
        } catch (EBaseException e) {
        }
        v.addElement(PROP_PATH + "=" + path);
        try {
            nickname = mConfig.getString(PROP_NICK);
        } catch (EBaseException e) {
        }
        v.addElement(PROP_NICK + "=" + nickname);
        try {
            clientAuthEnabled = mConfig.getString(PROP_CLIENT_AUTH_ENABLE);
        } catch (EBaseException e) {
        }
        v.addElement(PROP_CLIENT_AUTH_ENABLE + "=" + clientAuthEnabled);
        return v;
    }

    /**
     * Returns the initial default parameters.
     */
    @Override
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<>();

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        String nickname = "";
        // get subsystem cert nickname as default for client auth
        try {
            nickname = cs.getString("ca.subsystem.nickname", "");
            String tokenname = cs.getString("ca.subsystem.tokenname", "");
            if (!CryptoUtil.isInternalToken(tokenname))
                nickname = tokenname + ":" + nickname;
        } catch (Exception e) {
        }

        v.addElement(PROP_HOST + "=");
        v.addElement(PROP_PORT + "=");
        v.addElement(PROP_PATH + "=/ocsp/agent/ocsp/addCRL");
        v.addElement(PROP_CLIENT_AUTH_ENABLE + "=true");
        v.addElement(PROP_NICK + "=" + nickname);
        return v;
    }

    /**
     * Initializes this plugin.
     */
    @Override
    public void init(ConfigStore config) throws EBaseException {
        mConfig = config;
        mHost = mConfig.getString(PROP_HOST, "");
        mPort = mConfig.getString(PROP_PORT, "");
        mPath = mConfig.getString(PROP_PATH, "");
        mNickname = mConfig.getString(PROP_NICK, "");
        mClientAuthEnabled = mConfig.getBoolean(PROP_CLIENT_AUTH_ENABLE, true);
    }

    @Override
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    protected Socket Connect(String host, boolean secure, JssSSLSocketFactory factory) {
        Socket socket = null;
        StringTokenizer st = new StringTokenizer(host, " ");
        while (st.hasMoreTokens()) {
            String hp = st.nextToken(); // host:port
            StringTokenizer st1 = new StringTokenizer(hp, ":");
            String h = st1.nextToken();
            int p = Integer.parseInt(st1.nextToken());
            try {
                if (secure) {
                    socket = factory.makeSocket(h, p);
                } else {
                    socket = new Socket(h, p);
                }
                return socket;
            } catch (Exception e) {
                logger.warn("OCSPPublisher: " + e.getMessage(), e);
            }
            try {
                Thread.sleep(5000); // 5 seconds delay
            } catch (Exception e) {
            }
        }
        return null;
    }

    /**
     * Publishs a object to the ldap directory.
     *
     * @param conn a Ldap connection
     *            (null if LDAP publishing is not enabled)
     * @param dn dn of the ldap entry to publish cert
     *            (null if LDAP publishing is not enabled)
     * @param object object to publish
     *            (java.security.cert.X509Certificate or,
     *            java.security.cert.X509CRL)
     */
    @Override
    public synchronized void publish(LDAPConnection conn, String dn, Object object)
            throws DBException {
        try {
            if (!(object instanceof X509CRL)) {
                return;
            }

            X509CRL crl = (X509CRL) object;

            // talk to agent port of CMS

            // open the connection and prepare it to POST
            boolean secure = true;

            String host = mHost;
            int port = Integer.parseInt(mPort);
            String path = mPath;

            String url = "https://" + host + ":" + port + path;
            logger.info("OCSPPublisher: Publishing CRL to " + url);

            if (object instanceof X509CRLImpl crlImpl) {
                logger.info("OCSPPublisher: Revoked certs:");
                Set<RevokedCertificate> certs = crlImpl.getRevokedCertificates();
                if (certs != null) {
                    for (RevokedCertificate cert : certs) {
                        CertId certID = new CertId(cert.getSerialNumber());
                        logger.info("OCSPPublisher: - " + certID.toHexString());
                    }
                }
            }

            String pemCRL = CertUtil.CRL_HEADER + "\n" +
                    Utils.base64encode(crl.getEncoded(), true) +
                    CertUtil.CRL_FOOTER;
            logger.debug("OCSPPublisher: CRL:\n" + pemCRL);

            StringBuilder query = new StringBuilder();
            query.append("crl=");
            query.append(URLEncoder.encode(pemCRL, "UTF-8"));
            query.append("&noui=true");

            Socket socket = null;
            JssSSLSocketFactory factory;
            CAEngine engine = CAEngine.getInstance();

            if (mClientAuthEnabled) {
                factory = new JssSSLSocketFactory(mNickname);
            } else {
                factory = new JssSSLSocketFactory();
            }
            factory.addSocketListener(engine.getClientSocketListener());

            if (mHost != null && mHost.indexOf(' ') != -1) {
                // support failover hosts configuration
                // host parameter can be
                // "directory.knowledge.com:1050 people.catalog.com 199.254.1.2"
                do {
                    socket = Connect(mHost, secure, factory);
                } while (socket == null);
            } else {
                if (secure) {
                    socket = factory.makeSocket(host, port);
                } else {
                    socket = new Socket(host, port);
                }
            }

            if (socket == null) {
                logger.error("OCSPPublisher: Unable to connect to " + url);
                throw new DBException("Unable to connect to " + url);
            }

            // use HttpRequest and POST
            HttpRequest httpReq = new HttpRequest();

            httpReq.setMethod("POST");
            httpReq.setURI(path);
            httpReq.setHeader("Connection", "Keep-Alive");

            httpReq.setHeader("Content-Type",
                    "application/x-www-form-urlencoded");
            httpReq.setHeader("Content-Transfer-Encoding", "7bit");

            httpReq.setHeader("Content-Length",
                    Integer.toString(query.length()));
            httpReq.setContent(query.toString());
            OutputStream os = socket.getOutputStream();
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(os, "UTF8");

            logger.debug("OCSPPublisher: start sending CRL");

            long startTime = new Date().getTime();
            logger.debug("OCSPPublisher: start CRL sending startTime=" + startTime);

            httpReq.write(outputStreamWriter);

            long endTime = new Date().getTime();
            logger.debug("OCSPPublisher: done CRL sending endTime=" + endTime + " diff=" + (endTime - startTime));

            // Read the response
            logger.debug("OCSPPublisher: start getting response");
            BufferedReader dis = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String nextline;
            String error = "";
            boolean status = false;

            while ((nextline = dis.readLine()) != null) {
                if (nextline.startsWith("status=")) {
                    if (nextline.substring(7, nextline.length()).equals("0")) {
                        status = true;
                    }
                }
                if (nextline.startsWith("error=")) {
                    error = nextline.substring(6, nextline.length());
                }
            }
            dis.close();
            if (status) {
                logger.debug("OCSPPublisher: successful");
            } else {
                logger.warn("OCSPPublisher: Unable to publish CRL: " + error);
            }

        } catch (IOException e) {
            logger.warn("OCSPPublisher: Unable to publish CRL: " + e.getMessage(), e);
            logger.warn(CMS.getLogMessage("PUBLISH_OCSP_PUBLISHER_ERROR", e.toString()));

        } catch (CRLException e) {
            logger.warn("OCSPPublisher: Unable to publish CRL: " + e.getMessage(), e);
            logger.warn(CMS.getLogMessage("PUBLISH_OCSP_PUBLISHER_ERROR", e.toString()));

        } catch (Exception e) {
            logger.warn("OCSPPublisher: Unable to publish CRL: " + e.getMessage(), e);
            logger.warn(CMS.getLogMessage("PUBLISH_OCSP_PUBLISHER_ERROR", e.toString()));
        }
    }

    /**
     * Unpublishs a object to the ldap directory.
     *
     * @param conn the Ldap connection
     *            (null if LDAP publishing is not enabled)
     * @param dn dn of the ldap entry to unpublish cert
     *            (null if LDAP publishing is not enabled)
     * @param object object to unpublish
     *            (java.security.cert.X509Certificate)
     */
    @Override
    public void unpublish(LDAPConnection conn, String dn, Object object)
            throws DBException {
        // NOT USED
    }
}
