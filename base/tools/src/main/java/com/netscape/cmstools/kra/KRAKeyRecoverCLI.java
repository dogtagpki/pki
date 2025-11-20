package com.netscape.cmstools.kra;

import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class KRAKeyRecoverCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAKeyRecoverCLI.class);

    public KRAKeyCLI keyCLI;

    public KRAKeyRecoverCLI(KRAKeyCLI keyCLI) {
        super("recover", "Create a key recovery request", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "keyID", true, "Key Identifier for the secret to be recovered.");
        option.setArgName("Key Identifier");
        options.addOption(option);

        option = new Option(null, "input", true, "Location of the request file.");
        option.setArgName("Input file path");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String requestFile = cmd.getOptionValue("input");
        String keyID = cmd.getOptionValue("keyID");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        KeyClient keyClient = keyCLI.getKeyClient(client);

        KeyRequestResponse response = null;
        if (requestFile != null) {
            String json = Files.readString(Path.of(requestFile));
            KeyRecoveryRequest req = JSONSerializer.fromJSON(json, KeyRecoveryRequest.class);
            response = keyClient.recoverKey(
                    req.getKeyId(),
                    Utils.base64decode(req.getSessionWrappedPassphrase()),
                    Utils.base64decode(req.getTransWrappedSessionKey()),
                    Utils.base64decode(req.getNonceData()),
                    req.getCertificate());

        } else if (keyID != null) {
            String keyId = cmd.getOptionValue("keyID");
            response = keyClient.recoverKey(new KeyId(keyId), null, null, null, null);
        } else {
            throw new Exception("Neither a key ID nor a request file's path is specified.");
        }

        MainCLI.printMessage("Key Recovery Request Information");
        KRAKeyCLI.printKeyRequestInfo(response.getRequestInfo());

    }
}
