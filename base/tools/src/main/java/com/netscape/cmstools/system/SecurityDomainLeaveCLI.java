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
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainLeaveCLI extends CommandCLI {

    SecurityDomainCLI securityDomainCLI;

    public SecurityDomainLeaveCLI(SecurityDomainCLI securityDomainCLI) {
        super("leave", "Leave security domain", securityDomainCLI);
        this.securityDomainCLI = securityDomainCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <host ID>", options);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "type", true, "Subsystem type");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "hostname", true, "Hostname");
        option.setArgName("hostname");
        options.addOption(option);

        option = new Option(null, "secure-port", true, "Secure port (default: 8443)");
        option.setArgName("port");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing host ID");
        }

        String hostID = cmdArgs[0];

        String type = cmd.getOptionValue("type");
        if (type == null) {
            throw new CLIException("Missing subsystem type");
        }

        String hostname = cmd.getOptionValue("hostname");
        if (hostname == null) {
            throw new CLIException("Missing hostname");
        }

        String securePort = cmd.getOptionValue("secure-port", "8443");

        MultivaluedMap<String, String> content = new MultivaluedHashMap<>();
        content.putSingle("type", type);
        content.putSingle("name", hostID);
        content.putSingle("host", hostname);
        content.putSingle("sport", securePort);
        content.putSingle("operation", "remove");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        String response = client.post("ca/agent/ca/updateDomainXML", content, String.class);

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
