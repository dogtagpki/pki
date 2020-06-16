//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.nss;

import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
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

        return extensions;
    }
}
