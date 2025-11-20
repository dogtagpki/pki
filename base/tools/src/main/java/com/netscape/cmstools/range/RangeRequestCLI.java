//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.range;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.common.Range;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class RangeRequestCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RangeRequestCLI.class);

    public RangeCLI rangeCLI;

    public RangeRequestCLI(RangeCLI rangeCLI) {
        super("request", "Request range", rangeCLI);
        this.rangeCLI = rangeCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <type>", options);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "session", true, "Session ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "install-token", true, "Install token");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing range type");
        }

        String type = cmdArgs[0];

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

        String outputFormat = cmd.getOptionValue("output-format", "text");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = rangeCLI.subsystemCLI.getSubsystemClient(client);
        Range range = subsystemClient.requestRange(type, sessionID);

        if ("json".equalsIgnoreCase(outputFormat)) {
            System.out.println(range.toJSON());

        } else {
            System.out.println("  Begin: " + range.getBegin());
            System.out.println("  End: " + range.getEnd());
        }
    }
}
