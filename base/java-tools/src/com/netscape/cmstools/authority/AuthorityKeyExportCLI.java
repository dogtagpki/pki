package com.netscape.cmstools.authority;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

import com.netscape.cmstools.cli.CLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.security.util.WrappingParams;

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

        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        String filename = cmd.getOptionValue("output");
        if (filename == null) {
            throw new Exception("No output file specified.");
        }

        String wrapNick = cmd.getOptionValue("wrap-nickname");
        if (wrapNick == null) {
            throw new Exception("No wrapping key nickname specified.");
        }

        String targetNick = cmd.getOptionValue("target-nickname");
        if (targetNick == null) {
            throw new Exception("No target key nickname specified.");
        }

        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate wrapCert = cm.findCertByNickname(wrapNick);
        X509Certificate targetCert = cm.findCertByNickname(targetNick);

        PublicKey wrappingKey = wrapCert.getPublicKey();
        PrivateKey toBeWrapped = cm.findPrivKeyByCert(targetCert);
        CryptoToken token = cm.getInternalKeyStorageToken();

        EncryptionAlgorithm encAlg = EncryptionAlgorithm.AES_256_CBC;

        byte iv[] = new byte[encAlg.getBlockSize()];
        (new SecureRandom()).nextBytes(iv);
        IVParameterSpec ivps = new IVParameterSpec(iv);

        WrappingParams params = new WrappingParams(
                SymmetricKey.AES, KeyGenAlgorithm.AES, encAlg.getKeyStrength(),
                KeyWrapAlgorithm.RSA, encAlg,
                KeyWrapAlgorithm.AES_CBC_PAD, ivps, ivps);

        AlgorithmIdentifier aid = new AlgorithmIdentifier(
                encAlg.toOID(),
                new OCTET_STRING(ivps.getIV()));

        byte[] data = CryptoUtil.createEncodedPKIArchiveOptions(
                token,
                wrappingKey,
                toBeWrapped,
                params,
                aid);

        Files.newOutputStream(Paths.get(filename)).write(data);
    }
}
