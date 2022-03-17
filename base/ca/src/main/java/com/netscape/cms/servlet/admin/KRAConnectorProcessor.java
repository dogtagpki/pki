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
import org.dogtagpki.server.ca.CAEngine;

import com.netscape.ca.CAService;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.system.ConnectorNotFoundException;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.apps.EngineConfig;
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
        CertificateAuthority ca = engine.getCA();

        CAService caService = (CAService)ca.getCAService();
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
        EngineConfig cs = engine.getConfig();

        String host = cs.getString(PREFIX + ".host");
        logger.info("KRAConnectorProcessor: KRA connector host: " + host);

        String port = cs.getString(PREFIX + ".port");
        logger.info("KRAConnectorProcessor: KRA connector port: " + port);

        if ((host == null) || (port == null)) {
            logger.error("KRAConnectorProcessor: Invalid KRA connector configuration: Missing KRA host or port");
            throw new PKIException("Invalid KRA connector configuration: Missing KRA host or port");
        }

        if ((host.equals(newHost)) && port.equals(newPort)) {
            logger.info("KRAConnectorProcessor: Removing the last KRA connector");
            cs.removeSubStore(PREFIX);
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
            cs.removeSubStore(PREFIX);
            cs.commit(true);
            deleteConnector();
            return;
        }

        if (finalList.size() == 1) {

            host = finalList.get(0).split(":")[0];
            logger.info("KRAConnectorProcessor: KRA connector host: " + host);

            port = finalList.get(0).split(":")[1];
            logger.info("KRAConnectorProcessor: KRA connector port: " + port);

            cs.putString(PREFIX + ".host", host);
            cs.putString(PREFIX + ".port", port);
            cs.commit(true);
            replaceConnector();
            return;
        }

        String finalString = StringUtils.join(finalList, " ");
        logger.info("KRAConnectorProcessor: KRA connector host: " + finalString);
        cs.putString(PREFIX + ".host", finalString.trim());
        cs.commit(true);
        replaceConnector();
    }

    public void stopConnector() {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        CAService caService = (CAService) ca.getCAService();
        IConnector kraConnector = caService.getKRAConnector();
        if (kraConnector != null) {
            kraConnector.stop();
        }
    }

    public void startConnector() {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        CAService caService = (CAService) ca.getCAService();
        IConnector kraConnector = caService.getKRAConnector();
        if (kraConnector != null) {
            kraConnector.start();
        }
    }

    public void replaceConnector() throws EBaseException {
        // stop the old connector
        stopConnector();

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        CAService caService = (CAService) ca.getCAService();

        EngineConfig cs = engine.getConfig();
        IConnector kraConnector = caService.getConnector(cs.getSubStore(PREFIX, ConfigStore.class));
        caService.setKRAConnector(kraConnector);

        startConnector();
    }

    public void deleteConnector() {
        stopConnector();

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        CAService caService = (CAService)ca.getCAService();
        caService.setKRAConnector(null);
    }

    public void addConnector(KRAConnectorInfo info) throws EPropertyNotFound, EBaseException {

        logger.info("KRAConnectorProcessor: Adding KRA connector:");
        logger.info("KRAConnectorProcessor: - host: " + info.getHost());
        logger.info("KRAConnectorProcessor: - port: " + info.getPort());
        logger.info("KRAConnectorProcessor: - path: " + info.getUri());
        logger.info("KRAConnectorProcessor: - transport nickname: " + info.getTransportCertNickname());

        CAEngine engine = CAEngine.getInstance();
        EngineConfig cs = engine.getConfig();

        String newHost = info.getHost();
        String newPort = info.getPort();
        String newTransportCert = info.getTransportCert();

        if ((newHost == null) || (newPort == null) || (newTransportCert == null)) {
            logger.error("KRAConnectorProcessor: Missing KRA connector host, port, or transport certificate");
            throw new BadRequestException("Missing KRA connector host, port, or transport certificate");
        }

        if (connectorExists) {
            String currentHost = cs.getString(PREFIX + ".host");
            String currentPort = cs.getString(PREFIX + ".port");

            if ((!currentHost.equals(newHost)) || (!currentPort.equals(newPort))) {
                //existing connector is not the same

                // check transport cert
                String transportCert = cs.getString(PREFIX + ".transportCert");
                if (!transportCert.equals(newTransportCert)) {
                    logger.error("KRAConnectorProcessor: KRA connector already exists");
                    throw new BadRequestException("KRA connector already exists");
                }

                addHostPortToConnector(cs, newHost, newPort, currentHost, currentPort);
                return;
            }
        }

        // connector does not exist, or existing connector is the same host/port and we are replacing it
        logger.info("KRAConnectorProcessor: Storing KRA connector");

        cs.putString(PREFIX + ".host", info.getHost());
        cs.putString(PREFIX + ".port", info.getPort());
        cs.putString(PREFIX + ".enable", info.getEnable() != null ? info.getEnable() : "true");
        cs.putString(PREFIX + ".local", info.getLocal() != null ? info.getLocal(): "false");
        cs.putString(PREFIX + ".timeout", info.getTimeout() != null ?  info.getTimeout() : "30");
        cs.putString(PREFIX + ".uri", info.getUri() != null ? info.getUri() : "/kra/agent/kra/connector");
        cs.putString(PREFIX + ".transportCert", info.getTransportCert());

        String nickname = cs.getString("ca.subsystem.nickname", "");
        String tokenname = cs.getString("ca.subsystem.tokenname", "");
        if (!CryptoUtil.isInternalToken(tokenname))
            nickname = tokenname + ":" + nickname;
        cs.putString(PREFIX + ".nickName", nickname);
        cs.commit(true);

        replaceConnector();
    }

    public KRAConnectorInfo getConnectorInfo() throws EPropertyNotFound, EBaseException {

        if (!connectorExists) {
            logger.error("KRAConnectorProcessor: No KRA connectors");
            throw new ConnectorNotFoundException("No KRA connectors");
        }

        CAEngine engine = CAEngine.getInstance();
        EngineConfig cs = engine.getConfig();

        KRAConnectorInfo info = new KRAConnectorInfo();
        info.setHost(cs.getString(PREFIX + ".host"));
        info.setPort(cs.getString(PREFIX + ".port"));
        info.setEnable(cs.getString(PREFIX + ".enable"));
        info.setLocal(cs.getString(PREFIX + ".local"));
        info.setTimeout(cs.getString(PREFIX + ".timeout"));
        info.setUri(cs.getString(PREFIX + ".uri"));
        info.setTransportCert(cs.getString(PREFIX + ".transportCert"));

        return info;
    }

    public void addHost(String newHost, String newPort) throws EPropertyNotFound, EBaseException {
        CAEngine engine = CAEngine.getInstance();
        EngineConfig cs = engine.getConfig();

        if ((newHost == null) || (newPort == null)) {
            logger.error("KRAConnectorProcessor: Missing KRA connector host, port, or transport certificate");
            throw new BadRequestException("Missing KRA connector host, port, or transport certificate");
        }

        if (connectorExists) {
            String currentHost = cs.getString(PREFIX + ".host");
            String currentPort = cs.getString(PREFIX + ".port");

            if ((!currentHost.equals(newHost)) || (!currentPort.equals(newPort))) {
                addHostPortToConnector(cs, newHost, newPort, currentHost, currentPort);
            }
        } else {
            throw new BadRequestException("No KRA connectors");
        }
    }

    private void addHostPortToConnector(
            IConfigStore cs,
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

            cs.putString(PREFIX + ".host", currentHost + " " + hostport);
        } else {
            // host is not a list, turn it into one
            cs.putString(PREFIX + ".host", currentHost + ":" + currentPort + " " + hostport);
        }

        cs.commit(true);
        replaceConnector();
    }
}
