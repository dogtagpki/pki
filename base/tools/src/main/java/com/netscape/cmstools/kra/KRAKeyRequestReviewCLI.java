package com.netscape.cmstools.kra;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class KRAKeyRequestReviewCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAKeyRequestReviewCLI.class);

    public KRAKeyCLI keyCLI;

    public KRAKeyRequestReviewCLI(KRAKeyCLI keyCLI) {
        super("request-review", "Review key request", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Request ID> --action <action> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "action", true,
                "Action to be performed on the request.\nValid values: approve, reject, cancel.");
        option.setArgName("Action to perform");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("Incorrect number of arguments specified.");
        }

        RequestId reqId = new RequestId(cmdArgs[0]);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        KeyClient keyClient = keyCLI.getKeyClient(client);

        String action = cmd.getOptionValue("action");

        if (action == null) {
            throw new Exception("Missing action");
        }

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
        KRAKeyCLI.printKeyRequestInfo(keyRequestInfo);
    }
}
