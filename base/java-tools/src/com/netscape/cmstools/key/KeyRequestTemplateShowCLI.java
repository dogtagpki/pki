package com.netscape.cmstools.key;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.base.ResourceMessage;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.SymKeyGenerationRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class KeyRequestTemplateShowCLI extends CLI {
    public KeyCLI keyCLI;

    public KeyRequestTemplateShowCLI(KeyCLI keyCLI) {
        super("template-show", "Get request template", keyCLI);
        this.keyCLI = keyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName()
                + " <Template ID [archiveKey, retrieveKey, recoverKey, generateKey]> [OPTIONS]", options);
    }

    public void execute(String[] args) {

        Option option = new Option(null, "output-file", true, "Location where the template has to be stored.");
        option.setArgName("File to write the template to.");
        options.addOption(option);

        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }
        ;

        String[] cmdArgs = cmd.getArgs();
        if (cmdArgs.length < 1) {
            printHelp();
            System.exit(-1);
        }

        String templateId = cmdArgs[0];
        String writeToFile = cmd.getOptionValue("output-file");

        ResourceMessage data = null;
        String message = null;
        switch (templateId) {
        case "archiveKey":
            data = getSampleArchivalRequest();
            message = "key archival request";
            break;
        case "retrieveKey":
        case "recoverKey":
            message = "key recover request";
            data = getSampleRecoveryRequest();
            break;
        case "generateKey":
            message = "symmetric key generation request";
            data = getSampleGenerationRequest();
            break;
        default:
            System.err.println("Error: Invalid template id.");
            printHelp();
            System.exit(-1);
        }

        if ((writeToFile != null) && (writeToFile.trim().length() != 0)) {
            try {
                FileOutputStream fOS = new FileOutputStream(writeToFile);
                printRequestTemplate(data, fOS);
            } catch (JAXBException e) {
                System.err.println("Error: Cannot write the file");
                if (verbose)
                    e.printStackTrace();
            } catch (FileNotFoundException e) {
                System.err.println("Error: Cannot write the file");
                if (verbose)
                    e.printStackTrace();
            }
        } else {
            MainCLI.printMessage("Template for " + message);
            try {
                printRequestTemplate(data, System.out);
            } catch (JAXBException e) {
                System.err.println(e.getMessage());
                if (verbose)
                    e.printStackTrace();
            }
        }
    }

    public <T> void printRequestTemplate(T t, OutputStream os) throws JAXBException {
        JAXBContext context = JAXBContext.newInstance(t.getClass());
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(t, os);
    }

    public KeyArchivalRequest getSampleArchivalRequest() {
        KeyArchivalRequest data = new KeyArchivalRequest();
        data.setClientKeyId("");
        data.setDataType("symmetricKey/passphrase/asymmetricKey");
        data.setKeyAlgorithm("");
        data.setKeySize(0);
        data.setClientKeyId("");
        data.setAlgorithmOID("");
        data.setSymmetricAlgorithmParams("Base64 encoded NonceData");
        data.setWrappedPrivateData("Base64 encoded session key wrapped secret");
        data.setTransWrappedSessionKey("Base64 encoded transport key wrapped session key");
        data.setPKIArchiveOptions("Base 64 encoded PKIArchiveOptions object");
        return data;
    }

    public KeyRecoveryRequest getSampleRecoveryRequest() {
        KeyRecoveryRequest data = new KeyRecoveryRequest();
        data.setKeyId(new KeyId("1"));
        data.setRequestId(new RequestId("1"));
        data.setNonceData("Base64 encoded NonceData");
        data.setPassphrase("Passphrase to encrypt the secret with/Passphrase for the PKCS12 file returned");
        data.setSessionWrappedPassphrase("Base64 encoded session key wrapped passphrase");
        data.setTransWrappedSessionKey("Base64 encoded transport key wrapped session key");
        data.setCertificate("Base64 certificate used for recoring the key.");

        return data;
    }

    public SymKeyGenerationRequest getSampleGenerationRequest() {
        SymKeyGenerationRequest data = new SymKeyGenerationRequest();
        data.setClientKeyId("");
        data.setKeyAlgorithm("[AES/DES/DES3/DESede/RC2/RC4]");
        data.setKeySize(128);
        data.setUsages(Arrays.asList(new String[] { "wrap", "unwrap", "sign", "verify", "encrypt", "decrypt" }));

        return data;
    }
}
