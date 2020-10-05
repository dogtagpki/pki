import java.math.BigInteger;
import java.security.KeyPair;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.RSAParameterSpec;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.pkix.cms.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cms.SignerIdentifier;
import org.mozilla.jss.pkix.cms.SignerInfo;
import org.mozilla.jss.pkix.primitive.Name;

class Main {

    public static void main(String[] args) throws Exception {
        CryptoManager.initialize(args[0]);
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken ct = cm.getInternalKeyStorageToken();
        KeyPairGenerator gen = ct.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        gen.initialize(new RSAParameterSpec(1024, new BigInteger("65537")));
        KeyPair keyPair = gen.genKeyPair();
        PrivateKey pk = (PrivateKey) keyPair.getPrivate();

        Name iss = new Name();
        INTEGER ser = new INTEGER(1);
        IssuerAndSerialNumber ias = new IssuerAndSerialNumber(iss, ser);
        SignerIdentifier iasSignerId = SignerIdentifier.createIssuerAndSerialNumber(ias);
        SignerInfo signerInfo = createSignerInfo(iasSignerId, pk);
        System.out.println("Version (should be 1) = " + signerInfo.getVersion());

        SignerIdentifier skiSignerId = SignerIdentifier.createSubjectKeyIdentifier(
            new OCTET_STRING(new byte[20]));
        signerInfo = createSignerInfo(skiSignerId, pk);
        System.out.println("Version (should be 3) = " + signerInfo.getVersion());
    }

    static SignerInfo createSignerInfo(SignerIdentifier signerId, PrivateKey pk)
            throws Exception {
        return new SignerInfo(
            signerId,
            new SET(), // signedAttributes
            new SET(), // unsignedAttributes
            new OBJECT_IDENTIFIER("1.2.3.4"),  // contentType
            new byte[32], // messageDigest
            SignatureAlgorithm.RSASignatureWithSHA256Digest,
            pk
        );
    }

}
