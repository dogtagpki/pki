package com.netscape.cmstools.key;

import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.Key;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.util.Utils;

public class KeyRetrieveCLI extends CLI {
    public KeyCLI keyCLI;
    private boolean clientEncryption = true;

    public KeyRetrieveCLI(KeyCLI keyCLI) {
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

        String requestFile = cmd.getOptionValue("input");

        Key keyData = null;

        if (requestFile != null) {
            JAXBContext context = JAXBContext.newInstance(KeyRecoveryRequest.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            FileInputStream fis = new FileInputStream(requestFile);
            KeyRecoveryRequest req = (KeyRecoveryRequest) unmarshaller.unmarshal(fis);

            if (req.getKeyId() == null) {
                throw new Exception("Key ID must be specified in the request file.");
            }

            if (req.getCertificate() != null) {
                keyData = keyCLI.keyClient.retrieveKeyByPKCS12(req.getKeyId(), req.getCertificate(),
                        req.getPassphrase());

            } else if (req.getPassphrase() != null) {
                keyData = keyCLI.keyClient.retrieveKeyByPassphrase(req.getKeyId(), req.getPassphrase());

            } else if (req.getSessionWrappedPassphrase() != null) {
                keyData = keyCLI.keyClient.retrieveKeyUsingWrappedPassphrase(req.getKeyId(),
                        Utils.base64decode(req.getTransWrappedSessionKey()),
                        Utils.base64decode(req.getSessionWrappedPassphrase()),
                        Utils.base64decode(req.getNonceData()));

            } else if (req.getTransWrappedSessionKey() != null) {
                keyData = keyCLI.keyClient.retrieveKey(req.getKeyId(),
                        Utils.base64decode(req.getTransWrappedSessionKey()));

            } else {
                keyData = keyCLI.keyClient.retrieveKey(req.getKeyId());
            }

        } else {
            // Using command line options.
            String keyId = cmd.getOptionValue("keyID");
            String passphrase = cmd.getOptionValue("passphrase");
            String requestId = cmd.getOptionValue("requestID");

            if ((requestId == null) && (keyId == null)) {
                throw new Exception("Either requestID or keyID must be specified");
            }

            if (passphrase != null) {
                if (requestId != null) {
                    keyData = keyCLI.keyClient.retrieveKeyByRequestWithPassphrase(
                            new RequestId(requestId), passphrase);
                } else {
                    keyData = keyCLI.keyClient.retrieveKeyByPassphrase(new KeyId(keyId), passphrase);
                }
            } else {
                if (requestId != null) {
                    keyData = keyCLI.keyClient.retrieveKeyByRequest(new RequestId(requestId));
                } else {
                    keyData = keyCLI.keyClient.retrieveKey(new KeyId(keyId));
                }

                clientEncryption = false;

                // No need to return the encrypted data since encryption
                // is done locally.
                keyData.setEncryptedData(null);
            }
        }

        String outputFilePath = cmd.getOptionValue("output");
        if (outputFilePath != null) {
            JAXBContext context = JAXBContext.newInstance(Key.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(keyData, new File(outputFilePath));

        } else {
            MainCLI.printMessage("Retrieve Key Information");
            printKeyData(keyData);
        }
    }

    public void printKeyData(Key key) {
        if (key.getRequestId() != null)
            System.out.println("  Recovery Request ID: " + key.getRequestId());
        if (key.getAlgorithm() != null)
            System.out.println("  Key Algorithm: " + key.getAlgorithm());
        if (key.getSize() != null)
            System.out.println("  Key Size: " + key.getSize());
        if (key.getNonceData() != null)
            System.out.println("  Nonce data: " + Utils.base64encode(key.getNonceData()));

        if (clientEncryption) {
            if (key.getEncryptedData() != null)
                System.out.println("  Encrypted Data:" + Utils.base64encode(key.getEncryptedData()));
        } else {
            if (key.getData() !=  null)
                System.out.println("  Actual archived data: " + Utils.base64encode(key.getData()));
        }

        if (key.getP12Data() != null) {
            System.out.println("  Key data in PKCS12 format: " + key.getP12Data());
        }
    }
}
