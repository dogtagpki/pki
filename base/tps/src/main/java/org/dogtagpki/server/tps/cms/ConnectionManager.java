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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.cms;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.ws.rs.core.MediaType;

import org.dogtagpki.server.tps.TPSConfig;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.connector.Connector;
import com.netscape.certsrv.connector.ConnectorConfig;
import com.netscape.certsrv.connector.ConnectorsConfig;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.connector.HttpConnector;
import com.netscape.cmscore.connector.RemoteAuthority;

/**
 * ConnectionManager is a class for connection management
 * of its Remote Authorities
 *
 * @author cfu
 */
public class ConnectionManager
{
    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ConnectionManager.class);

    private Hashtable<String, Connector> connectors;
    List<String> caList;

    public ConnectionManager() throws EBaseException {
        // initialize the ca list for revocation routing:
        //    tps.connCAList=ca1,ca2...ca<n>
        TPSEngine engine = TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        TPSConfig conf = subsystem.getConfigStore();
        String caListString;

        try {
            caListString = conf.getString("connCAList");
            caList = Arrays.asList(caListString.split(","));
            logger.info("Revocation routing: " + caListString);

        } catch (EPropertyNotFound e) {
            logger.warn("Revocation routing not configured");
            return;
        }
    }

    public List<String> getCAList() {
        return caList;
    }

    /*
     * connector establishment with multi-uri support
     *
     * Initialize all connectors
     * tps.connector.<connID>.xxx
     *
     * e.g. (with Failover list under "host", separated by a space)
     *
     *   tps.connector.ca1.enable=true
     *   tps.connector.ca1.minHttpConns=1
     *   tps.connector.ca1.maxHttpConns=15
     *   tps.connector.ca1.host=host1.EXAMPLE.com:8445 host2.EXAMPLE.com:8445
     *   tps.connector.ca1.port=<port number; unused if for failover case>
     *   tps.connector.ca1.nickName=subsystemCert cert-pki-tomcat TPS
     *   tps.connector.ca1.timeout=30
     *   # In the example below,
     *   #   "enrollment", "getcert", "renewal", "revoke", and "unrevoke"
     *   #   are what's being referred to as "op" in the multi-uri support code
     *   tps.connector.ca1.uri.enrollment=/ca/ee/ca/profileSubmitSSLClient
     *   tps.connector.ca1.uri.renewal=/ca/ee/ca/profileSubmitSSLClient
     *   tps.connector.ca1.uri.getcert=/ca/ee/ca/displayBySerial
     *   tps.connector.ca1.uri.revoke=/ca/ee/subsystem/ca/doRevoke
     *   tps.connector.ca1.uri.unrevoke=/ca/ee/subsystem/ca/doUnrevoke
     */
    public void initConnectors() throws EBaseException {

        logger.debug("ConnectionManager: initConnectors(): begins.");

        TPSEngine engine = TPSEngine.getInstance();
        TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        TPSConfig conf = subsystem.getConfigStore();
        ConnectorsConfig connectorsConfig = conf.getConnectorsConfig();
        Enumeration<String> connector_enu = connectorsConfig.getSubStoreNames().elements();
        connectors = new Hashtable<>();
        while (connector_enu.hasMoreElements()) {
            String connectorID = connector_enu.nextElement();
            logger.debug("ConnectionManager: initConnectors(): initializing connector " + connectorID);
            ConnectorConfig connectorConfig = connectorsConfig.getConnectorConfig(connectorID);
            Connector conn = null;
            boolean enable = connectorConfig.getBoolean("enable", false);
            if (!enable) {
                logger.debug("ConnectionManager: initConnectors(): connector disabled.");
                continue;
            }
            logger.debug("ConnectionManager: initConnectors(): connector enabled.");
            conn = createConnector(connectorConfig);

            connectors.put(connectorID, conn);
            logger.debug("ConnectionManager: initConnectors(): connector "
                    + connectorID +
                    " initialized.");
        }
        logger.debug("ConnectionManager: initConnectors(): ends.");
    }

    /*
     * Creates and returns a connector
     *
     * @param conf config store of the connector
     * @return Connector the connector if created successfully; null if not
     */
    private Connector createConnector(ConnectorConfig conf) throws EBaseException {
        Connector connector = null;

        logger.debug("ConnectionManager: createConnector(): begins.");
        if (conf == null || conf.size() <= 0) {
            logger.error("ConnectionManager: createConnector(): conf null or empty.");
            throw new EBaseException("called with null config store");
        }

        String host = conf.getHost();
        if (host == null) {
            logger.error("ConnectionManager: createConnector(): host not found in config.");
            throw new EBaseException("host not found in config");
        }
        // port doesn't have to contain anything if failover supplied in host
        int port = conf.getPort();

        Hashtable<String, String> uris = new Hashtable<>();
        ConfigStore uriSubstore = conf.getURIs();
        if (uriSubstore == null) {
            logger.error("ConnectionManager: createConnector(): uri(s) not found in config.");
            throw new EBaseException("uri(s) not found in config");
        }
        logger.debug("ConnectionManager: createConnector(): uriSubstore name=" + uriSubstore.getName() + " size ="
                + uriSubstore.size());

        Enumeration<String> uri_enu = uriSubstore.getPropertyNames();
        while (uri_enu.hasMoreElements()) {
            String op = uri_enu.nextElement();
            if ((op != null) && !op.equals(""))
                logger.debug("ConnectionManager: createConnector(): op name=" + op);
            else
                continue;

            String uriValue = uriSubstore.getString(op);
            if ((uriValue != null) && !uriValue.equals(""))
                logger.debug("ConnectionManager: createConnector(): uri value=" + uriValue);
            else
                continue;
            uris.put(op, uriValue);
        }

        String nickname = conf.getNickname();
        if (nickname != null)
            logger.debug("ConnectionManager: createConnector(): nickName=" + nickname);
        else {
            logger.error("ConnectionManager: createConnector(): nickName not found in config");
            throw new EBaseException("nickName not found in config");
        }
        /*
         * if tps.connector.<ca>.clientCiphers is specified, it will
         * override the default;  If it is not specified, default will
         * be used.
         */
        String clientCiphers = conf.getClientCiphers();

        // "resendInterval" is for Request Queue, and not supported in TPS
        int resendInterval = -1;
        int timeout = conf.getTimeout();
        RemoteAuthority remauthority =
                new RemoteAuthority(host, port, uris, timeout, MediaType.APPLICATION_FORM_URLENCODED);

        logger.debug("ConnectionManager: createConnector(): establishing HttpConnector");
        if (timeout == 0) {
            connector =
                    new HttpConnector(nickname, clientCiphers, remauthority, resendInterval, conf);
        } else {
            connector =
                    new HttpConnector(nickname, clientCiphers, remauthority, resendInterval, conf, timeout);
        }

        connector.setCMSEngine(TPSEngine.getInstance());
        logger.debug("ConnectionManager: createConnector(): ends.");
        return connector;
    }

    /*
     * Gets an established connector to be used to send requests
     *     to a remote Authority (Note that Failover is supported in the
     *     underlying connector framework.
     *
     * Example usage (with example config for "ca1" defined above
     *       in initConnectors():
     *
     *   TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
     *   HttpConnector testConn =
     *       (HttpConnector) subsystem.getConnectionManager().getConnector(connectionID);
     *   HttpResponse resp =
     *     testConn.send("renewal",
     *       "serial_num=6&profileId=caTokenUserEncryptionKeyRenewal&renewal=true");
     *   if (resp != null) {
     *       logger.debug("Connector test: HttpResponse content:"+
     *           resp.getContent());
     *   } else {
     *       logger.warn("Connector test: HttpResponse content null");
     *   }
     *
     * @param connID connection id per defined in the configuration
     * @return Connector the connector matching the connection id
     */
    public Connector getConnector(String connID) {
        logger.debug("ConnectionManager: getConnector(): returning connID="+ connID);
        return connectors.get(connID);
    }

}
