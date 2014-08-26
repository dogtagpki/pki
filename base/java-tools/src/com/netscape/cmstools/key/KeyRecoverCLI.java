package com.netscape.cmstools.key;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.util.Utils;

public class KeyRecoverCLI extends CLI {
    public KeyCLI keyCLI;

    public KeyRecoverCLI(KeyCLI keyCLI) {
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

        if (cmdArgs.length != 0) {
            System.err.println("Error: Too many arguments specified.");
            printHelp();
            System.exit(-1);
        }

        String requestFile = cmd.getOptionValue("input");
        String keyID = cmd.getOptionValue("keyID");

        KeyRequestResponse response = null;

        if (requestFile != null) {
            try {
                JAXBContext context = JAXBContext.newInstance(KeyRecoveryRequest.class);
                Unmarshaller unmarshaller = context.createUnmarshaller();
                FileInputStream fis = new FileInputStream(requestFile);
                KeyRecoveryRequest req = (KeyRecoveryRequest) unmarshaller.unmarshal(fis);
                response = keyCLI.keyClient.recoverKey(req.getKeyId(),
                        Utils.base64decode(req.getSessionWrappedPassphrase()),
                        Utils.base64decode(req.getTransWrappedSessionKey()), Utils.base64decode(req.getNonceData()),
                        req.getCertificate());
            } catch (JAXBException e) {
                System.err.println("Error: Cannot parse the request file.");
                if (verbose)
                    e.printStackTrace();
                System.exit(-1);
            } catch (FileNotFoundException e) {
                System.err.println("Error: Cannot locate file at path: " + requestFile);
                if (verbose)
                    e.printStackTrace();
                System.exit(-1);
            }

        } else if (keyID != null) {
            String keyId = cmd.getOptionValue("keyID");
            response = keyCLI.keyClient.recoverKey(new KeyId(keyId), null, null, null, null);
        } else {
            System.err.println("Error: Neither a key ID nor a request file's path is specified.");
            printHelp();
            System.exit(-1);
        }

        MainCLI.printMessage("Key Recovery Request Information");
        KeyCLI.printKeyRequestInfo(response.getRequestInfo());

    }
}
