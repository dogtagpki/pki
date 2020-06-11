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
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;

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

        return extensions;
    }
}
