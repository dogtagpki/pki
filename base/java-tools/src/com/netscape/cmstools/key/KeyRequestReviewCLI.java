package com.netscape.cmstools.key;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.key.KeyClient;
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

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("Incorrect number of arguments specified.");
        }

        RequestId reqId = new RequestId(cmdArgs[0]);
        KeyClient keyClient = keyCLI.getKeyClient();

        String action = cmd.getOptionValue("action");
        switch (action.toLowerCase()) {
        case "approve":
            keyClient.approveRequest(reqId);
            break;
        case "reject":
            keyClient.rejectRequest(reqId);
            break;
        case "cancel":
            keyClient.cancelRequest(reqId);
            break;
        default:
            throw new Exception("Invalid action.");
        }

        KeyRequestInfo keyRequestInfo = keyClient.getRequestInfo(reqId);

        MainCLI.printMessage("Result");
        KeyCLI.printKeyRequestInfo(keyRequestInfo);
    }
}
