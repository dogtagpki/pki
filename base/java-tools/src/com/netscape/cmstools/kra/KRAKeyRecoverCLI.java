package com.netscape.cmstools.kra;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.cmstools.cli.MainCLI;
import org.mozilla.jss.netscape.security.util.Utils;

public class KRAKeyRecoverCLI extends CLI {
    public KRAKeyCLI keyCLI;

    public KRAKeyRecoverCLI(KRAKeyCLI keyCLI) {
        super("recover", "Create a key recovery request", keyCLI);
        this.keyCLI = keyCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "keyID", true, "Key Identifier for the secret to be recovered.");
        option.setArgName("Key Identifier");
        options.addOption(option);

        option = new Option(null, "input", true, "Location of the request file.");
        option.setArgName("Input file path");
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

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String requestFile = cmd.getOptionValue("input");
        String keyID = cmd.getOptionValue("keyID");

        KeyRequestResponse response = null;
        KeyClient keyClient = keyCLI.getKeyClient();

        if (requestFile != null) {
            try {
                JAXBContext context = JAXBContext.newInstance(KeyRecoveryRequest.class);
                Unmarshaller unmarshaller = context.createUnmarshaller();
                FileInputStream fis = new FileInputStream(requestFile);
                KeyRecoveryRequest req = (KeyRecoveryRequest) unmarshaller.unmarshal(fis);
                response = keyClient.recoverKey(req.getKeyId(),
                        Utils.base64decode(req.getSessionWrappedPassphrase()),
                        Utils.base64decode(req.getTransWrappedSessionKey()), Utils.base64decode(req.getNonceData()),
                        req.getCertificate());
            } catch (JAXBException e) {
                throw new Exception("Cannot parse the request file.", e);
            } catch (FileNotFoundException e) {
                throw new Exception("Cannot locate file at path: " + requestFile, e);
            }

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
