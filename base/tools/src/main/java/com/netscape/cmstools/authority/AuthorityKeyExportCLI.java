package com.netscape.cmstools.authority;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.WrappingParams;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class AuthorityKeyExportCLI extends SubsystemCommandCLI {

    public AuthorityCLI authorityCLI;

    private OBJECT_IDENTIFIER DES_EDE3_CBC_OID =
        new OBJECT_IDENTIFIER("1.2.840.113549.3.7");
    private OBJECT_IDENTIFIER AES_128_CBC_OID =
        new OBJECT_IDENTIFIER("2.16.840.1.101.3.4.1.2");

    public AuthorityKeyExportCLI(AuthorityCLI authorityCLI) {
        super("key-export", "Export wrapped CA signing key", authorityCLI);
        this.authorityCLI = authorityCLI;
    }

    @Override
    public void createOptions() {

        Option option = new Option("o", "output", true, "Output file");
        option.setArgName("filename");
        options.addOption(option);

        option = new Option(null, "wrap-nickname", true, "Nickname of wrapping key");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "target-nickname", true, "Nickname of target key");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "algorithm", true, "Symmetric encryption algorithm");
        option.setArgName("OID");
        options.addOption(option);

        option = new Option(null,"oaep", false, "Use RSA OAEP key wrap algorithm");
        options.addOption(option);

    }

    @Override
    public void printHelp() {
        formatter.printHelp(
            getFullName()
                + " --wrap-nickname NICKNAME --target-nickname NICKNAME -o FILENAME"
                + " [--algorithm OID]",
            options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

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

        boolean useOAEP = false;

        if(cmd.hasOption("oaep") ) {
            useOAEP = true;
        }

        // Old servers only support DES and do not specify
        // the algorithm to use, so default to DES.
        OBJECT_IDENTIFIER algOid = DES_EDE3_CBC_OID;
        String algOidString = cmd.getOptionValue("algorithm");
        if (algOidString != null) {
            algOid = new OBJECT_IDENTIFIER(algOidString);
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate wrapCert = cm.findCertByNickname(wrapNick);
        X509Certificate targetCert = cm.findCertByNickname(targetNick);

        PublicKey wrappingKey = wrapCert.getPublicKey();
        PrivateKey toBeWrapped = cm.findPrivKeyByCert(targetCert);
        CryptoToken token = cm.getInternalKeyStorageToken();

        AlgorithmIdentifier aid = null;
        WrappingParams params = null;
        KeyWrapAlgorithm wrapAlg = KeyWrapAlgorithm.RSA;

        if(useOAEP == true) {
            wrapAlg = KeyWrapAlgorithm.RSA_OAEP;
        }
        if (algOid.equals(DES_EDE3_CBC_OID)) {
            EncryptionAlgorithm encAlg = EncryptionAlgorithm.DES3_CBC_PAD;
            byte iv[] = CryptoUtil.getNonceData(encAlg.getIVLength());
            IVParameterSpec ivps = new IVParameterSpec(iv);


            params = new WrappingParams(
                SymmetricKey.DES3, KeyGenAlgorithm.DES3, 168,
                wrapAlg, encAlg,
                KeyWrapAlgorithm.DES3_CBC_PAD, ivps, ivps);

            aid = new AlgorithmIdentifier(algOid, new OCTET_STRING(iv));
        }

        else if (algOid.equals(AES_128_CBC_OID)) {
            EncryptionAlgorithm encAlg = EncryptionAlgorithm.AES_CBC_PAD;
            byte iv[] = CryptoUtil.getNonceData(encAlg.getIVLength());
            IVParameterSpec ivps = new IVParameterSpec(iv);

            params = new WrappingParams(
                SymmetricKey.AES, KeyGenAlgorithm.AES, 128,
                wrapAlg, encAlg,
                KeyWrapAlgorithm.AES_CBC_PAD, ivps, ivps);

            aid = new AlgorithmIdentifier(algOid, new OCTET_STRING(iv));
        }

        else {
            throw new Exception("Unsupported algorithm: " + algOid.toString());
        }

        byte[] data = CryptoUtil.createEncodedPKIArchiveOptions(
                token,
                wrappingKey,
                toBeWrapped,
                params,
                aid);

        try (OutputStream os = Files.newOutputStream(Paths.get(filename))) {
            os.write(data);
        }
    }
}
