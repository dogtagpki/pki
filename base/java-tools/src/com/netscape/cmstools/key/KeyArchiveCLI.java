package com.netscape.cmstools.key;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyClient;
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

        option = new Option(null, "realm", true, "Authorization realm.");
        option.setArgName("Realm");
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

        KeyRequestResponse response = null;
        KeyClient keyClient = keyCLI.getKeyClient();

        if (requestFile != null) {
            // Case where the request template file is used. For pre-encrypted data.
            try {
                JAXBContext context = JAXBContext.newInstance(KeyArchivalRequest.class);
                Unmarshaller unmarshaller = context.createUnmarshaller();
                FileInputStream fis = new FileInputStream(requestFile);
                KeyArchivalRequest req = (KeyArchivalRequest) unmarshaller.unmarshal(fis);

                if (req.getPKIArchiveOptions() != null) {
                    response = keyClient.archivePKIOptions(req.getClientKeyId(), req.getDataType(),
                            req.getKeyAlgorithm(), req.getKeySize(), Utils.base64decode(req.getPKIArchiveOptions()),
                            req.getRealm());
                } else {
                    response = keyClient.archiveEncryptedData(req.getClientKeyId(), req.getDataType(),
                            req.getKeyAlgorithm(), req.getKeySize(), req.getAlgorithmOID(),
                            Utils.base64decode(req.getSymmetricAlgorithmParams()),
                            Utils.base64decode(req.getWrappedPrivateData()),
                            Utils.base64decode(req.getTransWrappedSessionKey()),
                            req.getRealm());
                }

            } catch (JAXBException e) {
                throw new Exception("Cannot parse the request file.", e);

            } catch (FileNotFoundException e) {
                throw new Exception("Cannot locate file at path: " + requestFile, e);
            }

        } else {
            // Simple case for archiving a passphrase
            String clientKeyId = cmd.getOptionValue("clientKeyID");
            String passphrase = cmd.getOptionValue("passphrase");
            if (clientKeyId == null) {
                throw new Exception("Client Key Id is not specified.");
            }
            if (passphrase == null) {
                throw new Exception("No passphrase provided to archive.");
            }
            String realm = cmd.getOptionValue("realm");

            response = keyClient.archivePassphrase(clientKeyId, passphrase, realm);
        }

        MainCLI.printMessage("Archival request details");
        KeyCLI.printKeyRequestInfo(response.getRequestInfo());
    }
}
