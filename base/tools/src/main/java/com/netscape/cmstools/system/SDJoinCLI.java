//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.system;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.dogtagpki.cli.CLIException;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * @author Endi S. Dewata
 */
public class SDJoinCLI extends SubsystemCommandCLI {

    public SDJoinCLI(SDCLI sdCLI) {
        super("join", "Join security domain", sdCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <host ID>", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "session", true, "Session ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "install-token", true, "Install token");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "type", true, "Subsystem type");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "hostname", true, "Hostname");
        option.setArgName("hostname");
        options.addOption(option);

        option = new Option(null, "unsecure-port", true, "Unsecure port");
        option.setArgName("port");
        options.addOption(option);

        option = new Option(null, "secure-port", true, "Secure port (default: 8443)");
        option.setArgName("port");
        options.addOption(option);

        options.addOption(null, "domain-manager", false, "Domain manager");
        options.addOption(null, "clone", false, "Clone");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing host ID");
        }

        String hostID = cmdArgs[0];

        String installToken = cmd.getOptionValue("install-token");
        String sessionID;

        if (installToken != null) {
            sessionID = new String(Files.readAllBytes(Paths.get(installToken)));
        } else {
            sessionID = cmd.getOptionValue("session");
        }

        if (sessionID == null) {
            throw new CLIException("Missing session ID or install token");
        }

        String type = cmd.getOptionValue("type");
        if (type == null) {
            throw new CLIException("Missing subsystem type");
        }

        String hostname = cmd.getOptionValue("hostname");
        if (hostname == null) {
            throw new CLIException("Missing hostname");
        }

        String unsecurePort = cmd.getOptionValue("unsecure-port");
        String securePort = cmd.getOptionValue("secure-port", "8443");
        boolean domainManager = cmd.hasOption("domain-manager");
        boolean clone = cmd.hasOption("clone");

        List<NameValuePair> content = new ArrayList<>();
        content.add(new BasicNameValuePair("sessionID", sessionID));
        content.add(new BasicNameValuePair("list", type + "List"));
        content.add(new BasicNameValuePair("type", type));
        content.add(new BasicNameValuePair("name", hostID));
        content.add(new BasicNameValuePair("host", hostname));

        if (unsecurePort != null) {
            content.add(new BasicNameValuePair("httpport", unsecurePort));
        }

        content.add(new BasicNameValuePair("sport", securePort));
        content.add(new BasicNameValuePair("agentsport", securePort));
        content.add(new BasicNameValuePair("adminsport", securePort));
        content.add(new BasicNameValuePair("eeclientauthsport", securePort));
        content.add(new BasicNameValuePair("dm", domainManager ? "true" : "false"));
        content.add(new BasicNameValuePair("clone", clone ? "true" : "false"));

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = getPKIClient();
        String response = client.post("ca/admin/ca/updateDomainXML", content, String.class);

        if (StringUtils.isEmpty(response)) {
            logger.error("Missing response");
            throw new CLIException("Missing response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject obj = new XMLObject(bis);

        String status = obj.getValue("Status");
        logger.info("Status: " + status);

        if (status.equals("0")) {
            return;
        }

        if (status.equals("1")) {
            throw new CLIException("Authentication failure");
        }

        String error = obj.getValue("Error");
        throw new CLIException(error);
    }
}
