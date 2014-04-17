package com.netscape.cmstools.key;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

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
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS]", options);
    }

    public void execute(String[] args) {

        Option option = new Option(null, "keyID", true, "Key Identifier for the secret to be recovered.");
        option.setArgName("Key Identifier");
        options.addOption(option);

        option = new Option(null, "input", true, "Location of the request template file.");
        option.setArgName("Input file path");
        options.addOption(option);

        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);

        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        if (cmd.hasOption("help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        String requestFile = cmd.getOptionValue("input");

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

        } else {
            String keyId = cmd.getOptionValue("keyID");
            response = keyCLI.keyClient.recoverKey(new KeyId(keyId), null, null, null, null);
        }

        MainCLI.printMessage("Key Recovery Request Information");
        KeyCLI.printKeyRequestInfo(response.getRequestInfo());

    }
}
