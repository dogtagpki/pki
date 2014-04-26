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

import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.util.Utils;

public class KeyArchiveCLI extends CLI {
    public KeyCLI keyCLI;

    public KeyArchiveCLI(KeyCLI keyCLI) {
        super("archive", "Archive a secret in the DRM.", keyCLI);
        this.keyCLI = keyCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "clientKeyID", true, "Unique client key identifier.");
        option.setArgName("Client Key Identifier");
        options.addOption(option);

        option = new Option(null, "passphrase", true, "Passphrase to be stored.");
        option.setArgName("Passphrase");
        options.addOption(option);

        option = new Option(null, "input", true,
                "Location of the request template file.\nUsed for archiving already encrypted data.");
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

        KeyRequestResponse response = null;

        if (requestFile != null) {
            // Case where the request template file is used. For pre-encrypted data.
            try {
                JAXBContext context = JAXBContext.newInstance(KeyArchivalRequest.class);
                Unmarshaller unmarshaller = context.createUnmarshaller();
                FileInputStream fis = new FileInputStream(requestFile);
                KeyArchivalRequest req = (KeyArchivalRequest) unmarshaller.unmarshal(fis);

                if (req.getPKIArchiveOptions() != null) {
                    response = keyCLI.keyClient.archivePKIOptions(req.getClientKeyId(), req.getDataType(),
                            req.getKeyAlgorithm(), req.getKeySize(), Utils.base64decode(req.getPKIArchiveOptions()));
                } else {
                    response = keyCLI.keyClient.archiveEncryptedData(req.getClientKeyId(), req.getDataType(),
                            req.getKeyAlgorithm(), req.getKeySize(), req.getAlgorithmOID(),
                            Utils.base64decode(req.getSymmetricAlgorithmParams()),
                            Utils.base64decode(req.getWrappedPrivateData()),
                            Utils.base64decode(req.getTransWrappedSessionKey()));
                }

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
            // Simple case for archiving a passphrase
            String clientKeyId = cmd.getOptionValue("clientKeyID");
            String passphrase = cmd.getOptionValue("passphrase");
            if (clientKeyId == null) {
                System.err.println("Error: Client Key Id is not specified.");
                printHelp();
                System.exit(-1);
            }
            if (passphrase == null) {
                System.err.println("Error: No passphrase provided to archive.");
                printHelp();
                System.exit(-1);
            }
            try {
                response = keyCLI.keyClient.archivePassphrase(clientKeyId, passphrase);
            } catch (Exception e) {
                System.err.println(e.getMessage());
                if (verbose)
                    e.printStackTrace();
                System.exit(-1);
            }
        }

        MainCLI.printMessage("Archival request details");
        KeyCLI.printKeyRequestInfo(response.getRequestInfo());
    }
}
