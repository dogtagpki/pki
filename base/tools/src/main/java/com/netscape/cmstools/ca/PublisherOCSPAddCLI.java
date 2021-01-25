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
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;

public class PublisherOCSPAddCLI extends CommandCLI {

    public PublisherOCSPCLI publisherOCSPCLI;

    public PublisherOCSPAddCLI(PublisherOCSPCLI publisherOCSPCLI) {
        super("add", "Add OCSP publisher", publisherOCSPCLI);
        this.publisherOCSPCLI = publisherOCSPCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {

        Option option = new Option(null, "url", true, "Publisher URL");
        option.setArgName("URL");
        options.addOption(option);

        option = new Option(null, "session-file", true, "Session file");
        option.setArgName("path");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        String publisherURL = cmd.getOptionValue("url");
        if (publisherURL == null) {
            throw new Exception("Missing publisher URL");
        }

        URL url = new URL(publisherURL);

        String sessionFile = cmd.getOptionValue("session-file");
        if (sessionFile == null) {
            throw new Exception("Missing session file");
        }

        String sessionID = new String(Files.readAllBytes(Paths.get(sessionFile)));

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CAClient caClient = new CAClient(client);

        caClient.addOCSPPublisher(url, sessionID);
    }
}
