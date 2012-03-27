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
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.ldap.LDAPConnection;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.ILdapPublisher;
import com.netscape.cmsutil.http.HttpRequest;
import com.netscape.cmsutil.http.JssSSLSocketFactory;

/**
 * This publisher writes certificate and CRL into
 * a directory.
 *
 * @version $Revision$, $Date$
 */
public class OCSPPublisher implements ILdapPublisher, IExtendedPluginInfo {
    private static final String PROP_HOST = "host";
    private static final String PROP_PORT = "port";
    private static final String PROP_PATH = "path";
    private static final String PROP_NICK = "nickName";
    private static final String PROP_CLIENT_AUTH_ENABLE = "enableClientAuth";

    private IConfigStore mConfig = null;
    private String mHost = null;
    private String mPort = null;
    private String mPath = null;
    private String mNickname = null;
    private boolean mClientAuthEnabled = true;
    private ILogger mLogger = CMS.getLogger();

    /**
     * Returns the implementation name.
     */
    public String getImplName() {
        return "OCSPPublisher";
    }

    /**
     * Returns the description of the ldap publisher.
     */
    public String getDescription() {
        return "This publisher writes the CRL to CMS's OCSP server.";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
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
    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();
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
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        IConfigStore config = CMS.getConfigStore();
        String nickname = "";
        // get subsystem cert nickname as default for client auth
        try {
            nickname = config.getString("ca.subsystem.nickname", "");
            String tokenname = config.getString("ca.subsystem.tokenname", "");
            if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token"))
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
    public void init(IConfigStore config) {
        mConfig = config;
        try {
            mHost = mConfig.getString(PROP_HOST, "");
            mPort = mConfig.getString(PROP_PORT, "");
            mPath = mConfig.getString(PROP_PATH, "");
            mNickname = mConfig.getString(PROP_NICK, "");
            mClientAuthEnabled = mConfig.getBoolean(PROP_CLIENT_AUTH_ENABLE, true);
        } catch (EBaseException e) {
        }
    }

    public IConfigStore getConfigStore() {
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
    public synchronized void publish(LDAPConnection conn, String dn, Object object)
            throws ELdapException {
        try {
            if (!(object instanceof X509CRL))
                return;
            X509CRL crl = (X509CRL) object;

            // talk to agent port of CMS

            // open the connection and prepare it to POST
            boolean secure = true;

            String host = mHost;
            int port = Integer.parseInt(mPort);
            String path = mPath;

            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_INFO, "OCSPPublisher: " +
                            "Host='" + host + "' Port='" + port +
                            "' URL='" + path + "'");
            CMS.debug("OCSPPublisher: " +
                    "Host='" + host + "' Port='" + port +
                    "' URL='" + path + "'");

            StringBuffer query = new StringBuffer();
            query.append("crl=");
            query.append(URLEncoder.encode("-----BEGIN CERTIFICATE REVOCATION LIST-----\n", "UTF-8"));
            query.append(URLEncoder.encode(CMS.BtoA(crl.getEncoded()), "UTF-8"));
            query.append(URLEncoder.encode("\n-----END CERTIFICATE REVOCATION LIST-----", "UTF-8"));
            query.append("&noui=true");

            Socket socket = null;
            JssSSLSocketFactory factory;

            if (mClientAuthEnabled) {
                factory = new JssSSLSocketFactory(mNickname);
            } else {
                factory = new JssSSLSocketFactory();
            }

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
                CMS.debug("OCSPPublisher::publish() - socket is null!");
                throw new ELdapException("socket is null");
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

            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_INFO, "OCSPPublisher: start sending CRL");
            long startTime = CMS.getCurrentDate().getTime();
            CMS.debug("OCSPPublisher: start CRL sending startTime=" + startTime);
            httpReq.write(outputStreamWriter);
            long endTime = CMS.getCurrentDate().getTime();
            CMS.debug("OCSPPublisher: done CRL sending endTime=" + endTime + " diff=" + (endTime - startTime));

            // Read the response
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_INFO, "OCSPPublisher: start getting response");
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
                mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                        ILogger.LL_INFO, "OCSPPublisher: successful");
            } else {
                mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                        ILogger.LL_INFO, "OCSPPublisher: failed - " + error);
            }

        } catch (IOException e) {
            CMS.debug("OCSPPublisher: publish failed " + e.toString());
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_OCSP_PUBLISHER_ERROR", e.toString()));
        } catch (CRLException e) {
            CMS.debug("OCSPPublisher: publish failed " + e.toString());
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_OCSP_PUBLISHER_ERROR", e.toString()));
        } catch (Exception e) {
            CMS.debug("OCSPPublisher: publish failed " + e.toString());
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_OCSP_PUBLISHER_ERROR", e.toString()));
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
    public void unpublish(LDAPConnection conn, String dn, Object object)
            throws ELdapException {
        // NOT USED
    }
}
