package com.netscape.cmstools.kra;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.cmstools.cli.MainCLI;

public class KRAKeyGenerateCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAKeyGenerateCLI.class);

    public KRAKeyCLI keyCLI;

    public KRAKeyGenerateCLI(KRAKeyCLI keyCLI) {
        super("generate", "Generate key", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Client Key ID> --key-algorithm <algorithm> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "key-algorithm", true,
                "Algorithm to be used to create a key.\nValid values: AES, DES, DES3, RC2, RC4, DESede, RSA, DSA");
        option.setArgName("algorithm");
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

        option = new Option(
                null,
                "realm",
                true,
                "Authorization realm");
        option.setArgName("realm");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing Client Key Id.");
        }

        String clientKeyId = cmdArgs[0];
        String keyAlgorithm = cmd.getOptionValue("key-algorithm");
        String keySize = cmd.getOptionValue("key-size");
        String realm = cmd.getOptionValue("realm");

        if (keyAlgorithm == null) {
            throw new Exception("Missing key algorithm");
        }

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
                throw new Exception("Key size must be specified for the algorithm used.");
            default:
                throw new Exception("Algorithm not supported.");
            }
        }

        int size = 0;
        try {
            size = Integer.parseInt(keySize);
        } catch (NumberFormatException e) {
            throw new Exception("Key size must be an integer.", e);
        }

        List<String> usages = null;
        String givenUsages = cmd.getOptionValue("usages");
        if (givenUsages != null) {
            usages = Arrays.asList(givenUsages.split(","));
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        KeyClient keyClient = keyCLI.getKeyClient();

        KeyRequestResponse response = null;
        switch (keyAlgorithm) {
        case KeyRequestResource.DES3_ALGORITHM:
        case KeyRequestResource.DESEDE_ALGORITHM:
        case KeyRequestResource.DES_ALGORITHM:
        case KeyRequestResource.RC4_ALGORITHM:
        case KeyRequestResource.AES_ALGORITHM:
        case KeyRequestResource.RC2_ALGORITHM:
            response = keyClient.generateSymmetricKey(
                    clientKeyId, keyAlgorithm, size, usages, null, realm);
            break;
        case KeyRequestResource.RSA_ALGORITHM:
        case KeyRequestResource.DSA_ALGORITHM:
            response = keyClient.generateAsymmetricKey(
                    clientKeyId, keyAlgorithm, size, usages, null, realm);
            break;
        default:
            throw new Exception("Algorithm not supported.");
        }

        MainCLI.printMessage("Key generation request info");
        KRAKeyCLI.printKeyRequestInfo(response.getRequestInfo());
    }

}
