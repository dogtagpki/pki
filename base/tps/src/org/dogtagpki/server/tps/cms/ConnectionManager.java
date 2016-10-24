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

import org.dogtagpki.server.tps.TPSSubsystem;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.connector.IConnector;
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
    private Hashtable<String, IConnector> connectors;
    List<String> caList;

    public ConnectionManager() {
        // initialize the ca list for revocation routing:
        //    tps.connCAList=ca1,ca2...ca<n>
        TPSSubsystem subsystem =
                (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        IConfigStore conf = subsystem.getConfigStore();
        String caListString;
        try {
            caListString = conf.getString("connCAList");
            CMS.debug("ConnectionManager: ConnectionManager(): Initializing CA routing list");
        } catch (EBaseException e) {
            CMS.debug("ConnectionManager: ConnectionManager(): no connCAList for ca discovery.  No revocation routing");
            return;
        }

        caList = Arrays.asList(caListString.split(","));
        CMS.debug("ConnectionManager: ConnectionManager(): CA routing list initialized.");
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
        CMS.debug("ConnectionManager: initConnectors(): begins.");
        TPSSubsystem subsystem =
                (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        IConfigStore conf = subsystem.getConfigStore();
        IConfigStore connectorSubstore = conf.getSubStore("connector");
        Enumeration<String> connector_enu = connectorSubstore.getSubStoreNames();
        connectors = new Hashtable<String, IConnector>();
        while (connector_enu.hasMoreElements()) {
            String connectorID = connector_enu.nextElement();
            CMS.debug("ConnectionManager: initConnectors(): initializing connector " + connectorID);
            IConfigStore connectorConfig =
                    connectorSubstore.getSubStore(connectorID);
            IConnector conn = null;
            boolean enable = connectorConfig.getBoolean("enable", false);
            if (!enable) {
                CMS.debug("ConnectionManager: initConnectors(): connector disabled.");
                continue;
            }
            CMS.debug("ConnectionManager: initConnectors(): connector enabled.");
            conn = createConnector(connectorConfig);

            connectors.put(connectorID, conn);
            CMS.debug("ConnectionManager: initConnectors(): connector "
                    + connectorID +
                    " initialized.");
        }
        CMS.debug("ConnectionManager: initConnectors(): ends.");
    }

    /*
     * Creates and returns a connector
     *
     * @param conf config store of the connector
     * @return IConnector the connector if created successfully; null if not
     */
    private IConnector createConnector(IConfigStore conf)
            throws EBaseException {
        IConnector connector = null;

        CMS.debug("ConnectionManager: createConnector(): begins.");
        if (conf == null || conf.size() <= 0) {
            CMS.debug("ConnectionManager: createConnector(): conf null or empty.");
            throw new EBaseException("called with null config store");
        }

        String host = conf.getString("host");
        if (host == null) {
            CMS.debug("ConnectionManager: createConnector(): host not found in config.");
            throw new EBaseException("host not found in config");
        }
        // port doesn't have to contain anything if failover supplied in host
        int port = conf.getInteger("port");

        Hashtable<String, String> uris = new Hashtable<String, String>();
        IConfigStore uriSubstore = conf.getSubStore("uri");
        if (uriSubstore == null) {
            CMS.debug("ConnectionManager: createConnector(): uri(s) not found in config.");
            throw new EBaseException("uri(s) not found in config");
        }
        CMS.debug("ConnectionManager: createConnector(): uriSubstore name=" + uriSubstore.getName() + " size ="
                + uriSubstore.size());

        Enumeration<String> uri_enu = uriSubstore.getPropertyNames();
        while (uri_enu.hasMoreElements()) {
            String op = uri_enu.nextElement();
            if ((op != null) && !op.equals(""))
                CMS.debug("ConnectionManager: createConnector(): op name=" + op);
            else
                continue;

            String uriValue = uriSubstore.getString(op);
            if ((uriValue != null) && !uriValue.equals(""))
                CMS.debug("ConnectionManager: createConnector(): uri value=" + uriValue);
            else
                continue;
            uris.put(op, uriValue);
        }

        String nickname = conf.getString("nickName", null);
        if (nickname != null)
            CMS.debug("ConnectionManager: createConnector(): nickName=" + nickname);
        else {
            CMS.debug("ConnectionManager: createConnector(): nickName not found in config");
            throw new EBaseException("nickName not found in config");
        }
        /*
         * if tps.connector.<ca>.clientCiphers is specified, it will
         * override the default;  If it is not specified, default will
         * be used.
         */
        String clientCiphers = conf.getString("clientCiphers", null);

        // "resendInterval" is for Request Queue, and not supported in TPS
        int resendInterval = -1;
        int timeout = conf.getInteger("timeout", 0);
        RemoteAuthority remauthority =
                new RemoteAuthority(host, port, uris, timeout, MediaType.APPLICATION_FORM_URLENCODED);

        CMS.debug("ConnectionManager: createConnector(): establishing HttpConnector");
        if (timeout == 0) {
            connector =
                    new HttpConnector(null, nickname, clientCiphers, remauthority, resendInterval, conf);
        } else {
            connector =
                    new HttpConnector(null, nickname, clientCiphers, remauthority, resendInterval, conf, timeout);
        }

        CMS.debug("ConnectionManager: createConnector(): ends.");
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
     *       CMS.debug("Connector test: HttpResponse content:"+
     *           resp.getContent());
     *   } else {
     *       CMS.debug("Connector test: HttpResponse content null");
     *   }
     *
     * @param connID connection id per defined in the configuration
     * @return IConnector the connector matching the connection id
     */
    public IConnector getConnector(String connID) {
        CMS.debug("ConnectionManager: getConnector(): returning connID="+ connID);
        return connectors.get(connID);
    }

}
