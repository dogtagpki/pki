package com.netscape.cmstools.key;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class KeyRequestReviewCLI extends CLI {
    public KeyCLI keyCLI;

    public KeyRequestReviewCLI(KeyCLI keyCLI) {
        super("request-review", "Review key request", keyCLI);
        this.keyCLI = keyCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Request ID> --action <action> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "action", true,
                "Action to be performed on the request.\nValid values: approve, reject, cancel.");
        option.setArgName("Action to perform");
        option.setRequired(true);
        options.addOption(option);
    }

    public void execute(String[] args) {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            System.err.println("Error: Incorrect number of arguments specified.");
            printHelp();
            System.exit(-1);
        }

        RequestId reqId = new RequestId(cmdArgs[0]);

        String action = cmd.getOptionValue("action");
        switch (action.toLowerCase()) {
        case "approve":
            keyCLI.keyClient.approveRequest(reqId);
            break;
        case "reject":
            keyCLI.keyClient.rejectRequest(reqId);
            break;
        case "cancel":
            keyCLI.keyClient.cancelRequest(reqId);
            break;
        default:
            System.err.println("Error: Invalid action.");
            printHelp();
            System.exit(-1);
        }

        KeyRequestInfo keyRequestInfo = keyCLI.keyClient.getRequestInfo(reqId);

        MainCLI.printMessage("Result");
        KeyCLI.printKeyRequestInfo(keyRequestInfo);
    }
}
