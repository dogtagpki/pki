package com.netscape.cmstools.kra;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class KRAKeyArchiveCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAKeyArchiveCLI.class);

    public KRAKeyCLI keyCLI;

    public KRAKeyArchiveCLI(KRAKeyCLI keyCLI) {
        super("archive", "Archive a secret in the DRM.", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "clientKeyID", true, "Unique client key identifier.");
        option.setArgName("Client Key Identifier");
        options.addOption(option);

        option = new Option(null, "input-data", true, "Input file containing the data to be stored.");
        option.setArgName("Path");
        options.addOption(option);

        option = new Option(null, "passphrase", true, "Passphrase to be stored.");
        option.setArgName("Passphrase");
        options.addOption(option);

        option = new Option(null, "input-format", true, "Input format: xml (default), json");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "input", true,
                "Location of the request file.\nUsed for archiving already encrypted data.");
        option.setArgName("Input file path");
        options.addOption(option);

        option = new Option(null, "realm", true, "Authorization realm.");
        option.setArgName("Realm");
        options.addOption(option);

        option = new Option(null, "transport", true, "Transport certificate nickname.");
        option.setArgName("Nickname");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: none (default), json");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "oaep", false, "Use OAEP key wrap algorithm.");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String inputDataFile = cmd.getOptionValue("input-data");
        String passphrase = cmd.getOptionValue("passphrase");
        String clientKeyId = cmd.getOptionValue("clientKeyID");
        String realm = cmd.getOptionValue("realm");
        String inputFormat = cmd.getOptionValue("input-format", "xml");
        String requestFile = cmd.getOptionValue("input");
        String transportNickname = cmd.getOptionValue("transport");
        String outputFormat = cmd.getOptionValue("output-format", "none");
        boolean useOAEP = cmd.hasOption("oaep");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        KeyClient keyClient = keyCLI.getKeyClient(client, transportNickname);
        keyClient.setUseOAEP(useOAEP);

        KeyRequestResponse response = null;
        if (inputDataFile != null) {
            // archiving a binary data

            if (clientKeyId == null) {
                throw new Exception("Missing Client Key ID.");
            }

            Path path = Paths.get(inputDataFile);
            byte[] data = Files.readAllBytes(path);
            response = keyClient.archiveSecret(clientKeyId, data, realm);

        } else if (passphrase != null) {
            // archiving a passphrase

            if (clientKeyId == null) {
                throw new Exception("Missing Client Key ID.");
            }

            byte[] data = passphrase.getBytes("UTF-8");
            response = keyClient.archiveSecret(clientKeyId, data, realm);

        } else if (requestFile != null) {
            // Case where the request file is used. For pre-encrypted data.
            KeyArchivalRequest req;

            Path path = Paths.get(requestFile);
            String input = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);

            if ("json".equalsIgnoreCase(inputFormat)) {
                req = JSONSerializer.fromJSON(input, KeyArchivalRequest.class);
                logger.info("Request: " + req.toJSON());

            } else {
                throw new Exception("Unsupported input format: " + inputFormat);
            }

            if (req.getPKIArchiveOptions() != null) {
                response = keyClient.archivePKIOptions(
                        req.getClientKeyId(),
                        req.getDataType(),
                        req.getKeyAlgorithm(),
                        req.getKeySize(),
                        Utils.base64decode(req.getPKIArchiveOptions()),
                        req.getRealm());
            } else {
                response = keyClient.archiveEncryptedData(
                        req.getClientKeyId(),
                        req.getDataType(),
                        req.getKeyAlgorithm(),
                        req.getKeySize(),
                        req.getAlgorithmOID(),
                        Utils.base64decode(req.getSymmetricAlgorithmParams()),
                        Utils.base64decode(req.getWrappedPrivateData()),
                        Utils.base64decode(req.getTransWrappedSessionKey()),
                        req.getRealm());
            }

        } else {
            throw new Exception("Missing input data, passphrase, or request.");
        }

        if (outputFormat.equalsIgnoreCase("json")) {
            System.out.println(response.toJSON());

        } else if (outputFormat.equalsIgnoreCase("none")) {
            MainCLI.printMessage("Archival request details");
            KRAKeyCLI.printKeyRequestInfo(response.getRequestInfo());

        } else {
            throw new Exception("Unsupported output format: " + outputFormat);
        }
    }
}
