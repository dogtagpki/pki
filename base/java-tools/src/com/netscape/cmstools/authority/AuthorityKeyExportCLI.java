package com.netscape.cmstools.authority;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class AuthorityKeyExportCLI extends CLI {

    public AuthorityCLI authorityCLI;

    public AuthorityKeyExportCLI(AuthorityCLI authorityCLI) {
        super("key-export", "Export wrapped CA signing key", authorityCLI);
        this.authorityCLI = authorityCLI;

        options.addOption(null, "help", false, "Show usage");

        Option option = new Option("o", "output", true, "Output file");
        option.setArgName("filename");
        options.addOption(option);

        option = new Option(null, "wrap-nickname", true, "Nickname of wrapping key");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "target-nickname", true, "Nickname of target key");
        option.setArgName("nickname");
        options.addOption(option);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + "--wrap-nickname NICKNAME --target-nickname NICKNAME -o FILENAME", options);
    }

    public void execute(String[] args) throws Exception {
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        if (cmd.hasOption("help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        String filename = cmd.getOptionValue("output");
        if (filename == null) {
            System.err.println("Error: No output file specified.");
            printHelp();
            System.exit(-1);
        }

        String wrapNick = cmd.getOptionValue("wrap-nickname");
        if (wrapNick == null) {
            System.err.println("Error: no wrapping key nickname specified.");
            printHelp();
            System.exit(-1);
        }

        String targetNick = cmd.getOptionValue("target-nickname");
        if (targetNick == null) {
            System.err.println("Error: no target key nickname specified.");
            printHelp();
            System.exit(-1);
        }

        try {
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate wrapCert = cm.findCertByNickname(wrapNick);
            X509Certificate targetCert = cm.findCertByNickname(targetNick);

            PublicKey wrappingKey = wrapCert.getPublicKey();
            PrivateKey toBeWrapped = cm.findPrivKeyByCert(targetCert);
            CryptoToken token = cm.getInternalKeyStorageToken();

            byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
            IVParameterSpec ivps = new IVParameterSpec(iv);

            byte[] data = CryptoUtil.createPKIArchiveOptions(
                token, wrappingKey, toBeWrapped,
                KeyGenAlgorithm.DES3, 0, ivps);

            Files.newOutputStream(Paths.get(filename)).write(data);
        } catch (Throwable e) {
            e.printStackTrace();
            System.exit(-1);
        }

    }
}
