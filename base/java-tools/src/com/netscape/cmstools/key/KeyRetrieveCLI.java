package com.netscape.cmstools.key;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.Key;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.util.Utils;

public class KeyRetrieveCLI extends CLI {
    public KeyCLI keyCLI;
    private boolean clientEncryption = true;

    public KeyRetrieveCLI(KeyCLI keyCLI) {
        super("retrieve", "Retrieve key", keyCLI);
        this.keyCLI = keyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS]", options);
    }

    public void execute(String[] args) {

        Option option = new Option(null, "keyID", true, "Key Identifier for the secret to be recovered.");
        option.setArgName("Key Identifier");
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

        if(cmd.getOptions().length==0){
            System.err.println("Error: Insufficient parameters provided.");
            printHelp();
            System.exit(-1);
        }
        String requestFile = cmd.getOptionValue("input");

        Key keyData = null;

        if (requestFile != null) {
            try {
                JAXBContext context = JAXBContext.newInstance(KeyRecoveryRequest.class);
                Unmarshaller unmarshaller = context.createUnmarshaller();
                FileInputStream fis = new FileInputStream(requestFile);
                KeyRecoveryRequest req = (KeyRecoveryRequest) unmarshaller.unmarshal(fis);

                if (req.getKeyId() == null) {
                    System.err.println("Error: Key Id must be specified in the request file.");
                    System.exit(-1);
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
            } catch (Exception e) {
                System.err.println(e.getMessage());
                if (verbose)
                    e.printStackTrace();
                System.exit(-1);
            }

        } else {
            String keyId = cmd.getOptionValue("keyID");
            clientEncryption = false;
            try {
                keyData = keyCLI.keyClient.retrieveKey(new KeyId(keyId));

                // No need to return the encrypted data since encryption
                //is done locally.
                keyData.setEncryptedData(null);
            } catch (Exception e) {
                System.err.println(e.getMessage());
                if (verbose)
                    e.printStackTrace();
                System.exit(-1);
            }
        }

        String outputFilePath = cmd.getOptionValue("output");
        if (outputFilePath != null) {
            try {
                JAXBContext context = JAXBContext.newInstance(Key.class);
                Marshaller marshaller = context.createMarshaller();
                marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
                marshaller.marshal(keyData, new File(outputFilePath));
            } catch (JAXBException e) {
                System.err.println(e.getMessage());
                if (verbose)
                    e.printStackTrace();
                System.exit(-1);
            }
        } else {
            MainCLI.printMessage("Retrieve Key Information");
            printKeyData(keyData);
        }
    }

    public void printKeyData(Key key) {
        System.out.println("  Key Algorithm: " + key.getAlgorithm());
        System.out.println("  Key Size: " + key.getSize());
        System.out.println("  Nonce data: " + Utils.base64encode(key.getNonceData()));
        if(clientEncryption)
            System.out.println("  Encrypted Data:" + Utils.base64encode(key.getEncryptedData()));
        if (!clientEncryption)
            System.out.println("  Actual archived data: " + Utils.base64encode(key.getData()));
        if (key.getP12Data() != null) {
            System.out.println("  Key data in PKCS12 format: " + key.getP12Data());
        }
    }
}
