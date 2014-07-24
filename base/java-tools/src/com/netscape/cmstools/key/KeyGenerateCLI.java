package com.netscape.cmstools.key;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class KeyGenerateCLI extends CLI {
    public KeyCLI keyCLI;

    public KeyGenerateCLI(KeyCLI keyCLI) {
        super("generate", "Generate key", keyCLI);
        this.keyCLI = keyCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Client Key ID> --key-algorithm <algorithm> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "key-algorithm", true,
                "Algorithm to be used to create a key.\nValid values: AES, DES, DES3, RC2, RC4, DESede, RSA, DSA");
        option.setArgName("algorithm");
        option.setRequired(true);
        options.addOption(option);

        option = new Option(
                null,
                "key-size",
                true,
                "Size of the key to be generated.\nThis is required for AES, RC2 and RC4.\n"
                        + "Valid values for AES: 128, 192. 256.\nValid values for RC2: 8-128.\n Valid values for RC4: Any positive integer."
                        + "\n Valid values for DSA: 512, 768, 1024.\nValid values for RSA: 256 + (16*n), n= [0-496]");
        option.setArgName("size");
        options.addOption(option);

        option = new Option(null, "usages", true, "Comma separated list of usages."
                + "\nValid values: wrap, unwrap, sign, verify, encrypt, decrypt."
                + "\nAdditional usages for RSA and DSA type keys: derive, sign_recover, verify_recover.");
        option.setArgName("list of usages");
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

        if (cmdArgs.length < 1) {
            System.err.println("Error: Missing Client Key Id.");
            printHelp();
            System.exit(-1);
        }

        String clientKeyId = cmdArgs[0];
        String keyAlgorithm = cmd.getOptionValue("key-algorithm");
        String keySize = cmd.getOptionValue("key-size");

        if (keySize == null) {
            switch (keyAlgorithm) {
            case KeyRequestResource.DES3_ALGORITHM:
            case KeyRequestResource.DESEDE_ALGORITHM:
                keySize = "168";
                break;
            case KeyRequestResource.DES_ALGORITHM:
                keySize = "56";
                break;
            case KeyRequestResource.RC4_ALGORITHM:
            case KeyRequestResource.AES_ALGORITHM:
            case KeyRequestResource.RC2_ALGORITHM:
            case KeyRequestResource.RSA_ALGORITHM:
            case KeyRequestResource.DSA_ALGORITHM:
                System.err.println("Error: Key size must be specified for the algorithm used.");
                printHelp();
                System.exit(-1);
            default:
                System.err.println("Error: Algorithm not supported.");
                printHelp();
                System.exit(-1);
            }
        }

        int size = 0;
        try {
            size = Integer.parseInt(keySize);
        } catch (NumberFormatException e) {
            System.err.println("Error: Key size must be an integer.");
            printHelp();
            System.exit(-1);
        }
        List<String> usages = null;
        String givenUsages = cmd.getOptionValue("usages");
        if (givenUsages != null) {
            usages = Arrays.asList(givenUsages.split(","));
        }
        KeyRequestResponse response = null;
        switch (keyAlgorithm) {
        case KeyRequestResource.DES3_ALGORITHM:
        case KeyRequestResource.DESEDE_ALGORITHM:
        case KeyRequestResource.DES_ALGORITHM:
        case KeyRequestResource.RC4_ALGORITHM:
        case KeyRequestResource.AES_ALGORITHM:
        case KeyRequestResource.RC2_ALGORITHM:
            response = keyCLI.keyClient.generateSymmetricKey(clientKeyId, keyAlgorithm,
                    size,
                    usages, null);
            break;
        case KeyRequestResource.RSA_ALGORITHM:
        case KeyRequestResource.DSA_ALGORITHM:
            response = keyCLI.keyClient.generateAsymmetricKey(clientKeyId, keyAlgorithm,
                    size,
                    usages, null);
            break;
        default:
            System.err.println("Error: Algorithm not supported.");
            printHelp();
            System.exit(-1);
        }
        MainCLI.printMessage("Key generation request info");
        KeyCLI.printKeyRequestInfo(response.getRequestInfo());
    }

}
