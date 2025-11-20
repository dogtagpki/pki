//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.ca;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class PublisherOCSPAddCLI extends SubsystemCommandCLI {

    public PublisherOCSPCLI publisherOCSPCLI;

    public PublisherOCSPAddCLI(PublisherOCSPCLI publisherOCSPCLI) {
        super("add", "Add OCSP publisher", publisherOCSPCLI);
        this.publisherOCSPCLI = publisherOCSPCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "url", true, "Publisher URL");
        option.setArgName("URL");
        options.addOption(option);

        option = new Option(null, "subsystem-cert", true, "Subsystem certificate path");
        option.setArgName("path");
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

        String publisherURL = cmd.getOptionValue("url");
        if (publisherURL == null) {
            throw new Exception("Missing publisher URL");
        }

        URL url = new URL(publisherURL);

        String subsystemCertPath = cmd.getOptionValue("subsystem-cert");
        if (subsystemCertPath == null) {
            throw new Exception("Missing subsystem certificate");
        }

        String subsystemCert = new String(Files.readAllBytes(Paths.get(subsystemCertPath)));

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

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CAClient caClient = new CAClient(client);

        caClient.addOCSPPublisher(url, subsystemCert, sessionID);
    }
}
