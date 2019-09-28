package com.netscape.cmstools.kra;

import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.Key;
import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.MainCLI;

public class KRAKeyRetrieveCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAKeyRetrieveCLI.class);

    public KRAKeyCLI keyCLI;
    private boolean clientEncryption = true;

    public KRAKeyRetrieveCLI(KRAKeyCLI keyCLI) {
        super("retrieve", "Retrieve key", keyCLI);
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

        option = new Option(null, "requestID", true, "Request Identifier for approved recovery request.");
        option.setArgName("Recovery Request Identifier");
        options.addOption(option);

        option = new Option(null, "passphrase", true, "Passphrase to encrypt the key information.");
        option.setArgName("Passphrase");
        options.addOption(option);

        option = new Option(null, "input-format", true, "Input format: xml (default), json");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "input", true, "Location of the request template file.");
        option.setArgName("Input file path");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: xml (default), json");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "output", true, "Location to store the retrieved key information");
        option.setArgName("File path to store key information");
        options.addOption(option);

        option = new Option(null, "output-data", true, "Output file to store the retrieved data.");
        option.setArgName("Path");
        options.addOption(option);

        option = new Option(null, "transport", true, "Transport certificate nickname.");
        option.setArgName("Nickname");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(PKILogger.Level.INFO);

        } else if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        if (cmd.getOptions().length == 0) {
            throw new Exception("Incorrect number of parameters provided.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        KeyData keyData = null;
        Key key = null;

        try {
            String keyId = cmd.getOptionValue("keyID");
            String passphrase = cmd.getOptionValue("passphrase");
            String requestId = cmd.getOptionValue("requestID");
            String requestFile = cmd.getOptionValue("input");
            String inputFormat = cmd.getOptionValue("input-format", "xml");
            String outputFilePath = cmd.getOptionValue("output");
            String outputDataFile = cmd.getOptionValue("output-data");
            String outputFormat = cmd.getOptionValue("output-format", "xml");
            String transportNickname = cmd.getOptionValue("transport");

            KeyClient keyClient = keyCLI.getKeyClient(transportNickname);

            if (requestFile != null) {
                Path path = Paths.get(requestFile);
                String input = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);

                KeyRecoveryRequest req;
                if ("xml".equalsIgnoreCase(inputFormat)) {
                    req = KeyRecoveryRequest.fromXML(input);
                    logger.info("Request: " + req.toXML());

                } else if ("json".equalsIgnoreCase(inputFormat)) {
                    req = KeyRecoveryRequest.fromJSON(input);
                    logger.info("Request: " + req.toJSON());

                } else {
                    throw new Exception("Unsupported format: " + inputFormat);
                }

                if (req.getKeyId() == null) {
                    throw new Exception("Key ID must be specified in the request file.");
                }

                if (req.getCertificate() != null) {
                    keyData = keyClient.retrieveKeyByPKCS12(req.getKeyId(), req.getCertificate(),
                            req.getPassphrase());
                    key = new Key(keyData);

                } else if (req.getPassphrase() != null) {
                    keyData = keyClient.retrieveKeyByPassphrase(req.getKeyId(), req.getPassphrase());
                    key = new Key(keyData);

                } else if (req.getSessionWrappedPassphrase() != null) {
                    keyData = keyClient.retrieveKeyUsingWrappedPassphrase(req.getKeyId(),
                            Utils.base64decode(req.getTransWrappedSessionKey()),
                            Utils.base64decode(req.getSessionWrappedPassphrase()),
                            Utils.base64decode(req.getNonceData()));
                    key = new Key(keyData);

                } else if (req.getTransWrappedSessionKey() != null) {
                    keyData = keyClient.retrieveKey(req.getKeyId(),
                            Utils.base64decode(req.getTransWrappedSessionKey()));
                    key = new Key(keyData);

                } else {
                    SymmetricKey sessionKey = keyClient.generateSessionKey();
                    keyData = keyClient.retrieveKey(req.getKeyId(), sessionKey);
                    key = new Key(keyData);
                    keyClient.processKeyData(key, sessionKey);
                }

            } else {
                // Using command line options.
                if (requestId == null && keyId == null) {
                    throw new Exception("Either requestID or keyID must be specified");
                }

                if (passphrase != null) {
                    if (requestId != null) {
                        key = keyClient.retrieveKeyByRequestWithPassphrase(
                                new RequestId(requestId), passphrase);
                    } else {
                        keyData = keyClient.retrieveKeyByPassphrase(new KeyId(keyId), passphrase);
                        key = new Key(keyData);
                    }

                } else {
                    SymmetricKey sessionKey = keyClient.generateSessionKey();
                    if (requestId != null) {
                        keyData = keyClient.retrieveKeyByRequest(new RequestId(requestId), sessionKey);
                        key = new Key(keyData);
                    } else {
                        keyData = keyClient.retrieveKey(new KeyId(keyId), sessionKey);
                        key = new Key(keyData);
                    }
                    keyClient.processKeyData(key, sessionKey);

                    clientEncryption = false;

                    // No need to return the encrypted data since encryption
                    // is done locally.
                    key.setEncryptedData(null);
                }
            }

            if (outputDataFile != null) {

                byte[] data;
                if (clientEncryption) { // store encrypted data
                    data = key.getEncryptedData();

                } else { // store unencrypted data
                    data = key.getData();
                }

                Path path = Paths.get(outputDataFile);
                Files.write(path, data);

                MainCLI.printMessage("Retrieve Key Information");
                printKeyInfo(key);
                System.out.println("  Output: " + outputDataFile);

            } else if (outputFilePath != null) {

                try (FileWriter out = new FileWriter(outputFilePath)) {
                    if ("xml".equalsIgnoreCase(outputFormat)) {
                        out.write(key.toXML());
                    } else if ("json".equalsIgnoreCase(outputFormat)) {
                        out.write(keyData.toJSON());
                    }
                }

            } else if ("xml".equalsIgnoreCase(outputFormat)) {
                System.out.println(key.toXML());

            } else if ("json".equalsIgnoreCase(outputFormat)) {
                System.out.println(keyData.toJSON());

            } else {
                MainCLI.printMessage("Retrieve Key Information");

                printKeyInfo(key);
                printKeyData(key);
            }

        } catch (Exception e) {
            throw e;
        } finally {
            if (key != null) {
                key.clearSensitiveData();
            }
        }
    }

    public void printKeyInfo(Key key) {
        if (key.getRequestId() != null)
            System.out.println("  Recovery Request ID: " + key.getRequestId());
        if (key.getAlgorithm() != null)
            System.out.println("  Key Algorithm: " + key.getAlgorithm());
        if (key.getSize() != null)
            System.out.println("  Key Size: " + key.getSize());
        if (key.getNonceData() != null)
            System.out.println("  Nonce data: " + Utils.base64encode(key.getNonceData(), false));
    }

    public void printKeyData(Key key) {
        if (clientEncryption) {
            if (key.getEncryptedData() != null)
                System.out.println("  Encrypted Data:" + Utils.base64encode(key.getEncryptedData(), false));
        } else {
            if (key.getData() !=  null)
                System.out.println("  Actual archived data: " + Utils.base64encode(key.getData(), false));
        }

        if (key.getP12Data() != null) {
            System.out.println("  Key data in PKCS12 format: " + key.getP12Data());
        }
    }
}
