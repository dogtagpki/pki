//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.system;

import java.io.ByteArrayInputStream;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainJoinCLI extends CommandCLI {

    public SecurityDomainCLI securityDomainCLI;

    public SecurityDomainJoinCLI(SecurityDomainCLI securityDomainCLI) {
        super("join", "Join security domain", securityDomainCLI);
        this.securityDomainCLI = securityDomainCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <host ID>", options);
    }

    public void createOptions() {

        Option option = new Option(null, "session", true, "Session ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "type", true, "Subsystem type");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "hostname", true, "Hostname");
        option.setArgName("hostname");
        options.addOption(option);

        option = new Option(null, "unsecure-port", true, "Unsecure port (default: 8080)");
        option.setArgName("port");
        options.addOption(option);

        option = new Option(null, "secure-port", true, "Secure port (default: 8443)");
        option.setArgName("port");
        options.addOption(option);

        options.addOption(null, "domain-manager", false, "Domain manager");
        options.addOption(null, "clone", false, "Clone");
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing host ID");
        }

        String hostID = cmdArgs[0];

        String sessionID = cmd.getOptionValue("session");
        if (sessionID == null) {
            throw new Exception("Missing session ID");
        }

        String type = cmd.getOptionValue("type");
        if (type == null) {
            throw new Exception("Missing subsystem type");
        }

        String hostname = cmd.getOptionValue("hostname");
        if (hostname == null) {
            throw new Exception("Missing hostname");
        }

        String unsecurePort = cmd.getOptionValue("unsecure-port", "8080");
        String securePort = cmd.getOptionValue("secure-port", "8443");
        boolean domainManager = cmd.hasOption("domain-manager");
        boolean clone = cmd.hasOption("clone");

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("sessionID", sessionID);
        content.putSingle("list", type + "List");
        content.putSingle("type", type);
        content.putSingle("name", hostID);
        content.putSingle("host", hostname);
        content.putSingle("httpport", unsecurePort);
        content.putSingle("sport", securePort);
        content.putSingle("agentsport", securePort);
        content.putSingle("adminsport", securePort);
        content.putSingle("eeclientauthsport", securePort);
        content.putSingle("dm", domainManager ? "true" : "false");
        content.putSingle("clone", clone ? "true" : "false");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        String response = client.post("/ca/admin/ca/updateDomainXML", content, String.class);

        if (StringUtils.isEmpty(response)) {
            logger.error("Missing response");
            throw new Exception("Missing response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject obj = new XMLObject(bis);

        String status = obj.getValue("Status");
        logger.info("Status: " + status);

        if (status.equals("0")) {
            return;
        }

        if (status.equals("1")) {
            throw new Exception("Authentication failure");
        }

        String error = obj.getValue("Error");
        throw new Exception(error);
    }
}
