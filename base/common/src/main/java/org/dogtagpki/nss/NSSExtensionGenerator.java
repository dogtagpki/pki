//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.nss;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.stream.Collectors;

import org.mozilla.jss.netscape.security.extensions.AuthInfoAccessExtension;
import org.mozilla.jss.netscape.security.extensions.ExtendedKeyUsageExtension;
import org.mozilla.jss.netscape.security.extensions.OCSPNoCheckExtension;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CPSuri;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificatePoliciesExtension;
import org.mozilla.jss.netscape.security.x509.CertificatePolicyId;
import org.mozilla.jss.netscape.security.x509.CertificatePolicyInfo;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.PolicyQualifierInfo;
import org.mozilla.jss.netscape.security.x509.PolicyQualifiers;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.URIName;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class NSSExtensionGenerator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSExtensionGenerator.class);

    private Map<String, String> parameters = new LinkedHashMap<String, String>();

    public NSSExtensionGenerator() {
    }

    /**
     * Initialize cert extension generator with configuration file
     * based on the following format:
     * https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
     */
    public void init(String filename) throws Exception {

        Properties properties = new Properties();
        properties.load(new FileInputStream(filename));

        parameters.clear();
        for (String name : properties.stringPropertyNames()) {
            String value = properties.getProperty(name);
            parameters.put(name, value);
        }
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters.clear();
        this.parameters.putAll(parameters);
    }

    public Collection<String> getParameterNames() {
        return parameters.keySet();
    }

    public Collection<String> getParameterNames(String parent) {

        String prefix = parent + ".";
        int length = prefix.length();

        return parameters.keySet().stream()
            .filter(name -> name.startsWith(prefix))
            .map(name -> name.substring(length))
            .collect(Collectors.toSet());
    }

    public String getParameter(String name) {
        return parameters.get(name);
    }

    public void setParameter(String name, String value) {
        parameters.put(name, value);
    }

    public String removeParameter(String name) {
        return parameters.remove(name);
    }

    public BasicConstraintsExtension createBasicConstraintsExtension() throws Exception {

        String basicConstraints = getParameter("basicConstraints");
        if (basicConstraints == null) return null;

        logger.info("Creating basic constraint extension:");

        boolean critical = false;
        boolean ca = false;
        int pathLength = -1;

        List<String> options = Arrays.asList(basicConstraints.split("\\s*,\\s*"));
        for (String option : options) {

            if (option.equals("critical")) {
                logger.info("- critical");
                critical = true;
                continue;
            }

            if (option.startsWith("CA:")) {
                ca = Boolean.parseBoolean(option.substring(3));
                logger.info("- CA: " + ca);
                continue;
            }

            if (option.startsWith("pathlen:")) {
                pathLength = Integer.parseInt(option.substring(8));
                logger.info("- path length: " + pathLength);
                continue;
            }

            throw new Exception("Unsupported option: " + option);
        }

        return new BasicConstraintsExtension(ca, critical, pathLength);
    }

    public AuthorityKeyIdentifierExtension createAKIDExtension(
            org.mozilla.jss.crypto.X509Certificate issuer) throws Exception {

        if (issuer == null) return null;

        String authorityKeyIdentifier = getParameter("authorityKeyIdentifier");
        if (authorityKeyIdentifier == null) return null;

        logger.info("Creating AKID extension:");

        boolean keyid = false;

        List<String> options = Arrays.asList(authorityKeyIdentifier.split("\\s*,\\s*"));
        for (String option : options) {
            option = option.trim();
            logger.info("- " + option);

            if (option.equals("keyid") || option.equals("keyid:always")) {
                keyid = true;
                continue;
            }

            throw new Exception("Unsupported option: " + option);
        }

        X509CertImpl issuerImpl = new X509CertImpl(issuer.getEncoded());

        SubjectKeyIdentifierExtension skidExtension = (SubjectKeyIdentifierExtension)
                issuerImpl.getExtension("2.5.29.14");

        KeyIdentifier keyID = (KeyIdentifier) skidExtension.get(SubjectKeyIdentifierExtension.KEY_ID);
        String akid = "0x" + Utils.HexEncode(keyID.getIdentifier());
        logger.info("- AKID: " + akid);

        return new AuthorityKeyIdentifierExtension(keyID, null, null);
    }

    public SubjectKeyIdentifierExtension createSKIDExtension(PKCS10 pkcs10) throws Exception {

        if (pkcs10 == null) return null;

        String subjectKeyIdentifier = getParameter("subjectKeyIdentifier");
        if (subjectKeyIdentifier == null) return null;

        logger.info("Creating SKID extension:");

        byte[] bytes;

        if (subjectKeyIdentifier.equals("hash")) {
            logger.info("- hash");

            X509Key subjectKey = pkcs10.getSubjectPublicKeyInfo();
            bytes = CryptoUtil.generateKeyIdentifier(subjectKey.getKey());

        } else {
            throw new Exception("Unsupported subjectKeyIdentifier: " + subjectKeyIdentifier);
        }

        String skid = "0x" + Utils.HexEncode(bytes);
        logger.info("- SKID: " + skid);

        return new SubjectKeyIdentifierExtension(bytes);
    }

    public AuthInfoAccessExtension createAIAExtension() throws Exception {

        String authorityInfoAccess = getParameter("authorityInfoAccess");
        if (authorityInfoAccess == null) return null;

        logger.info("Creating AIA extension:");

        AuthInfoAccessExtension extension = new AuthInfoAccessExtension(false);

        List<String> options = Arrays.asList(authorityInfoAccess.split("\\s*,\\s*"));
        for (int i = 0; i < options.size(); i++) {
            String option = options.get(i).trim();

            ObjectIdentifier method;
            String value;

            if (option.startsWith("caIssuers;")) {
                value = option.substring(10);
                logger.info("- CA issuers");

                method = AuthInfoAccessExtension.METHOD_CA_ISSUERS;

            } else if (option.startsWith("OCSP;")) {
                value = option.substring(5);
                logger.info("- OCSP");

                method = AuthInfoAccessExtension.METHOD_OCSP;

            } else {
                throw new Exception("Unsupported AIA method: " + option);
            }

            GeneralName location;
            if (value.startsWith("URI:")) {
                String uri = value.substring(4);
                logger.info("  - URI: " + uri);

                location = new GeneralName(new URIName(uri));

            } else {
                throw new Exception("Unsupported AIA location: " + value);
            }

            extension.addAccessDescription(method, location);
        }

        // Call AuthInfoAccessExtension.encode() to generate the extensionValue,
        // otherwise the extensionValue will be null.
        //
        // TODO: Implement AuthInfoAccessExtension.getExtensionValue() to generate
        // the extensionValue whenever it's needed.

        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            extension.encode(os);
        }

        return extension;
    }

    public KeyUsageExtension createKeyUsageExtension() throws Exception {

        String keyUsage = getParameter("keyUsage");
        if (keyUsage == null) return null;

        logger.info("Creating key usage extension:");

        KeyUsageExtension extension = new KeyUsageExtension(false, new boolean[0]);

        List<String> options = Arrays.asList(keyUsage.split("\\s*,\\s*"));
        for (String option : options) {
            logger.info("- " + option);

            if ("critical".equals(option)) {
                extension.setCritical(true);

            } else if ("digitalSignature".equals(option)) {
                extension.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);

            } else if ("nonRepudiation".equals(option)) {
                extension.set(KeyUsageExtension.NON_REPUDIATION, true);

            } else if ("keyEncipherment".equals(option)) {
                extension.set(KeyUsageExtension.KEY_ENCIPHERMENT, true);

            } else if ("dataEncipherment".equals(option)) {
                extension.set(KeyUsageExtension.DATA_ENCIPHERMENT, true);

            } else if ("keyAgreement".equals(option)) {
                extension.set(KeyUsageExtension.KEY_AGREEMENT, true);

            } else if ("keyCertSign".equals(option)) {
                extension.set(KeyUsageExtension.KEY_CERTSIGN, true);

            } else if ("cRLSign".equals(option)) {
                extension.set(KeyUsageExtension.CRL_SIGN, true);

            } else if ("encipherOnly".equals(option)) {
                extension.set(KeyUsageExtension.ENCIPHER_ONLY, true);

            } else if ("decipherOnly".equals(option)) {
                extension.set(KeyUsageExtension.DECIPHER_ONLY, true);

            } else {
                throw new Exception("Unsupported key usage: " + option);
            }
        }

        return extension;
    }

    public ExtendedKeyUsageExtension createExtendedKeyUsageExtension() throws Exception {

        String extendedKeyUsage = getParameter("extendedKeyUsage");
        if (extendedKeyUsage == null) return null;

        logger.info("Creating extended key usage extension:");

        boolean critical = false;
        Vector<ObjectIdentifier> oids = new Vector<>();

        List<String> options = Arrays.asList(extendedKeyUsage.split("\\s*,\\s*"));
        for (String option : options) {
            logger.info("- " + option);

            if ("critical".equals(option)) {
                critical = true;

            } else if ("serverAuth".equals(option)) {
                oids.add(ObjectIdentifier.getObjectIdentifier("1.3.6.1.5.5.7.3.1"));

            } else if ("clientAuth".equals(option)) {
                oids.add(ObjectIdentifier.getObjectIdentifier("1.3.6.1.5.5.7.3.2"));

            } else {
                throw new Exception("Unsupported extended key usage: " + option);
            }

            // TODO: Support other extended key usages.
        }

        return new ExtendedKeyUsageExtension(critical, oids);
    }

    public CertificatePoliciesExtension createCertificatePoliciesExtension() throws Exception {

        String certificatePolicies = getParameter("certificatePolicies");
        if (certificatePolicies == null) return null;

        logger.info("Creating certificate policies extension:");

        Vector<CertificatePolicyInfo> infos = new Vector<>();

        List<String> options = Arrays.asList(certificatePolicies.split("\\s*,\\s*"));

        for (int i = 0; i < options.size(); i++) {
            String option = options.get(i);

            CertificatePolicyInfo info;

            if (option.startsWith("@")) {
                String section = option.substring(1);
                String oid = getParameter(section + ".id");
                logger.info("- " + oid);

                CertificatePolicyId policyID = new CertificatePolicyId(
                        ObjectIdentifier.getObjectIdentifier(oid));

                PolicyQualifiers qualifiers = new PolicyQualifiers();

                // create CPS qualifiers
                String cpsProperty = section + ".CPS";
                List<String> cpsIDs = new ArrayList<>(getParameterNames(cpsProperty));

                for (int j = 0; j < cpsIDs.size(); j++) {
                    String cpsID = cpsIDs.get(j);
                    String uri = getParameter(cpsProperty + "." + cpsID);
                    logger.info("  - CPS: " + uri);

                    CPSuri cpsURI = new CPSuri(uri);

                    PolicyQualifierInfo cpsQualifierInfo = new PolicyQualifierInfo(
                            PolicyQualifierInfo.QT_CPS, cpsURI);

                    qualifiers.add(cpsQualifierInfo);
                }

                // TODO: Add support for user notice qualifiers.

                if (qualifiers.size() == 0) qualifiers = null;
                info = new CertificatePolicyInfo(policyID, qualifiers);

            } else {
                logger.info("- " + option);

                CertificatePolicyId policyID = new CertificatePolicyId(
                        ObjectIdentifier.getObjectIdentifier(option));
                info = new CertificatePolicyInfo(policyID);
            }

            infos.add(info);
        }

        return new CertificatePoliciesExtension(infos);
    }

    public OCSPNoCheckExtension createOCSPNoCheckExtension() throws Exception {

        String noCheck = getParameter("noCheck");
        if (noCheck == null) return null;

        logger.info("Creating OCSP No Check extension");

        return new OCSPNoCheckExtension();
    }

    public CertificateExtensions createExtensions() throws Exception {
        return createExtensions(null, null);
    }

    public CertificateExtensions createExtensions(
            org.mozilla.jss.crypto.X509Certificate issuer,
            PKCS10 pkcs10) throws Exception {

        CertificateExtensions extensions = new CertificateExtensions();

        BasicConstraintsExtension basicConstraintsExtension = createBasicConstraintsExtension();
        if (basicConstraintsExtension != null) {
            extensions.parseExtension(basicConstraintsExtension);
        }

        AuthorityKeyIdentifierExtension akidExtension = createAKIDExtension(issuer);
        if (akidExtension != null) {
            extensions.parseExtension(akidExtension);
        }

        SubjectKeyIdentifierExtension skidExtension = createSKIDExtension(pkcs10);
        if (skidExtension != null) {
            extensions.parseExtension(skidExtension);
        }

        AuthInfoAccessExtension aiaExtension = createAIAExtension();
        if (aiaExtension != null) {
            extensions.parseExtension(aiaExtension);
        }

        KeyUsageExtension keyUsageExtension = createKeyUsageExtension();
        if (keyUsageExtension != null) {
            extensions.parseExtension(keyUsageExtension);
        }

        ExtendedKeyUsageExtension extendedKeyUsageExtension = createExtendedKeyUsageExtension();
        if (extendedKeyUsageExtension != null) {
            extensions.parseExtension(extendedKeyUsageExtension);
        }

        CertificatePoliciesExtension certificatePoliciesExtension = createCertificatePoliciesExtension();
        if (certificatePoliciesExtension != null) {
            extensions.parseExtension(certificatePoliciesExtension);
        }

        OCSPNoCheckExtension ocspNoCheckExtension = createOCSPNoCheckExtension();
        if (ocspNoCheckExtension != null) {
            extensions.parseExtension(ocspNoCheckExtension);
        }

        return extensions;
    }
}
