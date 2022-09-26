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
package com.netscape.cms.servlet.admin;

import java.util.ArrayList;
import java.util.Locale;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;

import com.netscape.ca.CAService;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.connector.Connector;
import com.netscape.certsrv.connector.ConnectorsConfig;
import com.netscape.certsrv.system.ConnectorNotFoundException;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Ade Lee
 */
public class KRAConnectorProcessor extends CAProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAConnectorProcessor.class);

    private boolean connectorExists;

    public final static String PREFIX = "ca.connector.KRA";

    public KRAConnectorProcessor(Locale locale) throws EPropertyNotFound, EBaseException {
        super("kraconnector", locale);

        CAEngine engine = CAEngine.getInstance();
        CAService caService = engine.getCAService();
        connectorExists = caService.getKRAConnector() != null;
    }

    public void removeConnector(String newHost, String newPort) throws EPropertyNotFound, EBaseException {

        if ((newHost == null) || (newPort == null)) {
            logger.error("KRAConnectorProcessor: Invalid request: Missing KRA host or port");
            throw new BadRequestException("Invalid request: Missing KRA host or port");
        }

        String hostport = newHost + ":" + newPort;
        logger.info("KRAConnectorProcessor: Removing KRA connector " + hostport);

        if (!connectorExists) {
            logger.info("KRAConnectorProcessor: No KRA connectors");
            return;
        }

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();

        String host = connectorsConfig.getString("KRA.host");
        logger.info("KRAConnectorProcessor: KRA connector host: " + host);

        String port = connectorsConfig.getString("KRA.port");
        logger.info("KRAConnectorProcessor: KRA connector port: " + port);

        if ((host == null) || (port == null)) {
            logger.error("KRAConnectorProcessor: Invalid KRA connector configuration: Missing KRA host or port");
            throw new PKIException("Invalid KRA connector configuration: Missing KRA host or port");
        }

        if ((host.equals(newHost)) && port.equals(newPort)) {
            logger.info("KRAConnectorProcessor: Removing the last KRA connector");
            connectorsConfig.removeSubStore("KRA");
            cs.commit(true);
            deleteConnector();
            return;
        }

        if (host.indexOf(' ') < 0) { // host is not a list
            logger.info("KRAConnectorProcessor: KRA connector " + hostport + " not found");
            return;
        }

        // host is a list
        String[] hostList = host.trim().split(" ");
        ArrayList<String> finalList = new ArrayList<>();
        for (String h : hostList) {
            if (! h.equals(hostport)) {
                finalList.add(h);
            }
        }

        if (finalList.size() == hostList.length) {
            logger.info("KRAConnectorProcessor: KRA connector " + hostport + " not found");
            return;
        }

        if (finalList.size() == 0) {
            logger.info("KRAConnectorProcessor: Removing the last KRA connector");
            connectorsConfig.removeSubStore("KRA");
            cs.commit(true);
            deleteConnector();
            return;
        }

        if (finalList.size() == 1) {

            host = finalList.get(0).split(":")[0];
            logger.info("KRAConnectorProcessor: KRA connector host: " + host);

            port = finalList.get(0).split(":")[1];
            logger.info("KRAConnectorProcessor: KRA connector port: " + port);

            connectorsConfig.putString("KRA.host", host);
            connectorsConfig.putString("KRA.port", port);
            cs.commit(true);
            replaceConnector();
            return;
        }

        String finalString = StringUtils.join(finalList, " ");
        logger.info("KRAConnectorProcessor: KRA connector host: " + finalString);
        connectorsConfig.putString("KRA.host", finalString.trim());
        cs.commit(true);
        replaceConnector();
    }

    public void stopConnector() {

        CAEngine engine = CAEngine.getInstance();
        CAService caService = engine.getCAService();
        Connector kraConnector = caService.getKRAConnector();
        if (kraConnector != null) {
            kraConnector.stop();
        }
    }

    public void startConnector() {

        CAEngine engine = CAEngine.getInstance();
        CAService caService = engine.getCAService();
        Connector kraConnector = caService.getKRAConnector();
        if (kraConnector != null) {
            kraConnector.start();
        }
    }

    public void replaceConnector() throws EBaseException {
        // stop the old connector
        stopConnector();

        CAEngine engine = CAEngine.getInstance();
        CAService caService = engine.getCAService();

        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();

        ConfigStore kraConnectorConfig = connectorsConfig.getSubStore("KRA", ConfigStore.class);
        Connector kraConnector = caService.getConnector(kraConnectorConfig);
        caService.setKRAConnector(kraConnector);

        startConnector();
    }

    public void deleteConnector() {
        stopConnector();

        CAEngine engine = CAEngine.getInstance();
        CAService caService = engine.getCAService();
        caService.setKRAConnector(null);
    }

    public void addConnector(KRAConnectorInfo info) throws EPropertyNotFound, EBaseException {

        logger.info("KRAConnectorProcessor: Adding KRA connector:");
        logger.info("KRAConnectorProcessor: - host: " + info.getHost());
        logger.info("KRAConnectorProcessor: - port: " + info.getPort());
        logger.info("KRAConnectorProcessor: - path: " + info.getUri());
        logger.info("KRAConnectorProcessor: - transport nickname: " + info.getTransportCertNickname());

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();

        String newHost = info.getHost();
        String newPort = info.getPort();
        String newTransportCert = info.getTransportCert();

        if ((newHost == null) || (newPort == null) || (newTransportCert == null)) {
            logger.error("KRAConnectorProcessor: Missing KRA connector host, port, or transport certificate");
            throw new BadRequestException("Missing KRA connector host, port, or transport certificate");
        }

        if (connectorExists) {
            String currentHost = connectorsConfig.getString("KRA.host");
            String currentPort = connectorsConfig.getString("KRA.port");

            if ((!currentHost.equals(newHost)) || (!currentPort.equals(newPort))) {
                //existing connector is not the same

                // check transport cert
                String transportCert = connectorsConfig.getString("KRA.transportCert");
                if (!transportCert.equals(newTransportCert)) {
                    logger.error("KRAConnectorProcessor: KRA connector already exists");
                    throw new BadRequestException("KRA connector already exists");
                }

                addHostPortToConnector(connectorsConfig, newHost, newPort, currentHost, currentPort);
                cs.commit(true);
                replaceConnector();
                return;
            }
        }

        // connector does not exist, or existing connector is the same host/port and we are replacing it
        logger.info("KRAConnectorProcessor: Storing KRA connector");

        connectorsConfig.putString("KRA.host", info.getHost());
        connectorsConfig.putString("KRA.port", info.getPort());
        connectorsConfig.putString("KRA.enable", info.getEnable() != null ? info.getEnable() : "true");
        connectorsConfig.putString("KRA.local", info.getLocal() != null ? info.getLocal(): "false");
        connectorsConfig.putString("KRA.timeout", info.getTimeout() != null ?  info.getTimeout() : "30");
        connectorsConfig.putString("KRA.uri", info.getUri() != null ? info.getUri() : "/kra/agent/kra/connector");
        connectorsConfig.putString("KRA.transportCert", info.getTransportCert());

        String nickname = cs.getString("ca.subsystem.nickname", "");
        String tokenname = cs.getString("ca.subsystem.tokenname", "");
        if (!CryptoUtil.isInternalToken(tokenname))
            nickname = tokenname + ":" + nickname;
        connectorsConfig.putString("KRA.nickName", nickname);
        cs.commit(true);

        replaceConnector();
    }

    public KRAConnectorInfo getConnectorInfo() throws EPropertyNotFound, EBaseException {

        if (!connectorExists) {
            logger.error("KRAConnectorProcessor: No KRA connectors");
            throw new ConnectorNotFoundException("No KRA connectors");
        }

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();

        KRAConnectorInfo info = new KRAConnectorInfo();
        info.setHost(connectorsConfig.getString("KRA.host"));
        info.setPort(connectorsConfig.getString("KRA.port"));
        info.setEnable(connectorsConfig.getString("KRA.enable"));
        info.setLocal(connectorsConfig.getString("KRA.local"));
        info.setTimeout(connectorsConfig.getString("KRA.timeout"));
        info.setUri(connectorsConfig.getString("KRA.uri"));
        info.setTransportCert(connectorsConfig.getString("KRA.transportCert"));

        return info;
    }

    public void addHost(String newHost, String newPort) throws EPropertyNotFound, EBaseException {
        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();

        if ((newHost == null) || (newPort == null)) {
            logger.error("KRAConnectorProcessor: Missing KRA connector host, port, or transport certificate");
            throw new BadRequestException("Missing KRA connector host, port, or transport certificate");
        }

        if (connectorExists) {
            String currentHost = connectorsConfig.getString("KRA.host");
            String currentPort = connectorsConfig.getString("KRA.port");

            if ((!currentHost.equals(newHost)) || (!currentPort.equals(newPort))) {
                addHostPortToConnector(connectorsConfig, newHost, newPort, currentHost, currentPort);
                cs.commit(true);
                replaceConnector();
            }
        } else {
            throw new BadRequestException("No KRA connectors");
        }
    }

    private void addHostPortToConnector(
            ConnectorsConfig connectorsConfig,
            String newHost,
            String newPort,
            String currentHost,
            String currentPort) throws EBaseException {

        String hostport = newHost + ":" + newPort;
        logger.info("KRAConnectorProcessor: Adding KRA connector " + hostport);

        if (currentHost.indexOf(' ') != -1) {
            // host is a list
            String[] hostList = currentHost.trim().split(" ");
            for (String h : hostList) {
                if (h.equals(hostport)) {
                    logger.info("KRAConnectorProcessor: KRA connector for " + hostport + " already exists");
                    return;
                }
            }

            connectorsConfig.putString("KRA.host", currentHost + " " + hostport);
        } else {
            // host is not a list, turn it into one
            connectorsConfig.putString("KRA.host", currentHost + ":" + currentPort + " " + hostport);
        }
    }
}
