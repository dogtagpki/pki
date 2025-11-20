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
package com.netscape.cmstools.system;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.ConnectorNotFoundException;
import com.netscape.certsrv.system.KRAConnectorClient;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Ade Lee
 */
public class KRAConnectorAddCLI extends SubsystemCommandCLI {

    public KRAConnectorCLI kraConnectorCLI;

    public KRAConnectorAddCLI(KRAConnectorCLI kraConnectorCLI) {
        super("add", "Add KRA Connector", kraConnectorCLI);
        this.kraConnectorCLI = kraConnectorCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(
                getFullName() + " --input-file <file> | --host <KRA host> --port <KRA port>", options);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "host", true, "KRA host");
        option.setArgName("host");
        options.addOption(option);

        option = new Option(null, "port", true, "KRA port");
        option.setArgName("port");
        options.addOption(option);

        option = new Option(null, "input-file", true, "Input file");
        option.setArgName("input-file");
        options.addOption(option);

        option = new Option(null, "url", true, "Connector URL");
        option.setArgName("URL");
        options.addOption(option);

        option = new Option(null, "subsystem-cert", true, "Subsystem certificate path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "transport-cert", true, "Transport certificate path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "transport-nickname", true, "Transport certificate nickname");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "enable", true, "Enable (default: true)");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option(null, "local", true, "Local (default: false)");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option(null, "timeout", true, "Timeout (default: 30)");
        option.setArgName("seconds");
        options.addOption(option);

        option = new Option(null, "session", true, "Session ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "install-token", true, "Install token");
        option.setArgName("path");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String kraHost = cmd.getOptionValue("host");
        String kraPort = cmd.getOptionValue("port");
        String inputFile = cmd.getOptionValue("input-file");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        KRAConnectorClient kraConnectorClient = kraConnectorCLI.getKRAConnectorClient(client);

        if (inputFile != null) {

            try {
                KRAConnectorInfo info = kraConnectorClient.getConnectorInfo();

                logger.info("KRA connector:");
                logger.info("- host: " + info.getHost());
                logger.info("- port: " + info.getPort());
                logger.info("- path: " + info.getUri());

                throw new Exception("Cannot add new connector from file.  " +
                        "Delete the existing connector first");

            } catch (ConnectorNotFoundException e) {
                // no existing KRA connector
            }

            String xml = new String(Files.readAllBytes(Paths.get(inputFile)));
            KRAConnectorInfo info = JSONSerializer.fromJSON(xml, KRAConnectorInfo.class);

            kraConnectorClient.addConnector(info);
            MainCLI.printMessage("Added KRA connector");
            return;
        }

        if (kraHost != null || kraPort != null) {

            try {
                KRAConnectorInfo info = kraConnectorClient.getConnectorInfo();

                logger.info("KRA connector:");
                logger.info("- host: " + info.getHost());
                logger.info("- port: " + info.getPort());
                logger.info("- path: " + info.getUri());

            } catch (ConnectorNotFoundException e) {
                throw new Exception("Cannot add new host to existing connector.  " +
                        "No connector currently exists");
            }

            kraConnectorClient.addHost(kraHost, kraPort);
            MainCLI.printMessage("Added KRA host \"" + kraHost + ":" + kraPort + "\"");
            return;
        }

        String installToken = cmd.getOptionValue("install-token");
        String sessionID;

        if (installToken != null) {
            sessionID = new String(Files.readAllBytes(Paths.get(installToken)));
        } else {
            sessionID = cmd.getOptionValue("session");
        }

        if (sessionID == null) {
            throw new Exception("Missing session ID or install token");
        }

        KRAConnectorInfo info = new KRAConnectorInfo();

        String connectorURL = cmd.getOptionValue("url");
        if (connectorURL != null) {
            URL url = new URL(connectorURL);
            info.setHost(url.getHost());
            info.setPort(url.getPort() + "");
            info.setUri(url.getPath());
        }

        String subsystemCertPath = cmd.getOptionValue("subsystem-cert");
        if (subsystemCertPath != null) {
            String subsystemCert = new String(Files.readAllBytes(Paths.get(subsystemCertPath)));
            info.setSubsystemCert(subsystemCert);
        }

        String transportCertPath = cmd.getOptionValue("transport-cert");
        if (transportCertPath != null) {
            String transportCert = new String(Files.readAllBytes(Paths.get(transportCertPath)));
            info.setTransportCert(transportCert);
        }

        String transportNickname = cmd.getOptionValue("transport-nickname");
        if (transportNickname != null) {
            info.setTransportCertNickname(transportNickname);
        }

        String enable = cmd.getOptionValue("enable", "true");
        info.setEnable(enable);

        String local = cmd.getOptionValue("local", "false");
        info.setLocal(local);

        String timeout = cmd.getOptionValue("timeout", "30");
        info.setTimeout(timeout);

        CAClient caClient = new CAClient(client);
        caClient.addKRAConnector(info, sessionID);
    }
}
