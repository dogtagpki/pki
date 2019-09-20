package com.netscape.cmstools.kra;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
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

        option = new Option(null, "input", true, "Location of the request template file.");
        option.setArgName("Input file path");
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

        if (cmd.getOptions().length == 0) {
            throw new Exception("Incorrect number of parameters provided.");
        }

        KeyData keyData = null;
        Key key = null;

        try {
            String keyId = cmd.getOptionValue("keyID");
            String passphrase = cmd.getOptionValue("passphrase");
            String requestId = cmd.getOptionValue("requestID");
            String outputFilePath = cmd.getOptionValue("output");
            String outputDataFile = cmd.getOptionValue("output-data");
            String requestFile = cmd.getOptionValue("input");
            String transportNickname = cmd.getOptionValue("transport");

            KeyClient keyClient = keyCLI.getKeyClient(transportNickname);

            if (requestFile != null) {
                JAXBContext context = JAXBContext.newInstance(KeyRecoveryRequest.class);
                Unmarshaller unmarshaller = context.createUnmarshaller();
                FileInputStream fis = new FileInputStream(requestFile);
                KeyRecoveryRequest req = (KeyRecoveryRequest) unmarshaller.unmarshal(fis);

                if (req.getKeyId() == null) {
                    throw new Exception("Key ID must be specified in the request file.");
                }

                if (req.getCertificate() != null) {
                    keyData = keyClient.retrieveKeyByPKCS12(req.getKeyId(), req.getCertificate(),
                            req.getPassphrase());
                    key = new Key(keyData);

                } else if (req.getPassphrase() != null) {
                    key = keyClient.retrieveKeyByPassphrase(req.getKeyId(), req.getPassphrase());

                } else if (req.getSessionWrappedPassphrase() != null) {
                    key = keyClient.retrieveKeyUsingWrappedPassphrase(req.getKeyId(),
                            Utils.base64decode(req.getTransWrappedSessionKey()),
                            Utils.base64decode(req.getSessionWrappedPassphrase()),
                            Utils.base64decode(req.getNonceData()));

                } else if (req.getTransWrappedSessionKey() != null) {
                    key = keyClient.retrieveKey(req.getKeyId(),
                            Utils.base64decode(req.getTransWrappedSessionKey()));

                } else {
                    SymmetricKey sessionKey = keyClient.generateSessionKey();
                    key = keyClient.retrieveKey(req.getKeyId(), sessionKey);
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
                        key = keyClient.retrieveKeyByPassphrase(new KeyId(keyId), passphrase);
                    }

                } else {
                    SymmetricKey sessionKey = keyClient.generateSessionKey();
                    if (requestId != null) {
                        key = keyClient.retrieveKeyByRequest(new RequestId(requestId), sessionKey);
                    } else {
                        key = keyClient.retrieveKey(new KeyId(keyId), sessionKey);
                    }

                    clientEncryption = false;

                    // No need to return the encrypted data since encryption
                    // is done locally.
                    key.setEncryptedData(null);
                }
            }

            MainCLI.printMessage("Retrieve Key Information");

            if (outputDataFile != null) {

                byte[] data;
                if (clientEncryption) { // store encrypted data
                    data = key.getEncryptedData();

                } else { // store unencrypted data
                    data = key.getData();
                }

                Path path = Paths.get(outputDataFile);
                Files.write(path, data);

                printKeyInfo(key);
                System.out.println("  Output: " + outputDataFile);

            } else if (outputFilePath != null) {
                JAXBContext context = JAXBContext.newInstance(Key.class);
                Marshaller marshaller = context.createMarshaller();
                marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
                marshaller.marshal(key, new File(outputFilePath));

                System.out.println("  Output: " + outputFilePath);

            } else {
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
