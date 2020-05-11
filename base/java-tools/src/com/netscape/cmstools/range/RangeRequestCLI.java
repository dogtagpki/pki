//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.range;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.common.Range;

import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.cmstools.cli.MainCLI;

public class RangeRequestCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RangeRequestCLI.class);

    public RangeCLI rangeCLI;

    public RangeRequestCLI(RangeCLI rangeCLI) {
        super("request", "Request range", rangeCLI);
        this.rangeCLI = rangeCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <type>", options);
    }

    public void createOptions() {
        Option option = new Option(null, "session", true, "Session ID.");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json");
        option.setArgName("format");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing range type");
        }

        String type = cmdArgs[0];
        String sessionID = cmd.getOptionValue("session");

        if (sessionID == null) {
            throw new Exception("Missing session ID");
        }

        String outputFormat = cmd.getOptionValue("output-format", "text");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        SubsystemClient subsystemClient = rangeCLI.subsystemCLI.getSubsystemClient();
        Range range = subsystemClient.requestRange(type, sessionID);

        if ("json".equalsIgnoreCase(outputFormat)) {
            System.out.println(range.toJSON());

        } else {
            System.out.println("  Begin: " + range.getBegin());
            System.out.println("  End: " + range.getEnd());
        }
    }
}
