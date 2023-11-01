// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.nss;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CLIException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.netscape.security.extensions.AccessDescription;
import org.mozilla.jss.netscape.security.extensions.AuthInfoAccessExtension;
import org.mozilla.jss.netscape.security.extensions.ExtendedKeyUsageExtension;
import org.mozilla.jss.netscape.security.extensions.OCSPNoCheckExtension;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CPSuri;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificatePoliciesExtension;
import org.mozilla.jss.netscape.security.x509.CertificatePolicyId;
import org.mozilla.jss.netscape.security.x509.CertificatePolicyInfo;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.PolicyQualifierInfo;
import org.mozilla.jss.netscape.security.x509.PolicyQualifiers;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11ECPrivateKey;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkcs11.PK11RSAPrivateKey;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.PasswordStore;

/**
 * @author Endi S. Dewata
 */
public class NSSDatabase {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSDatabase.class);

    FileAttribute<Set<PosixFilePermission>> FILE_PERMISSIONS =
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));

    FileAttribute<Set<PosixFilePermission>> DIR_PERMISSIONS =
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));

    Path path;
    PasswordStore passwordStore;

    public NSSDatabase() {
    }

    public NSSDatabase(Path path) {
        this.path = path;
    }

    public NSSDatabase(File directory) {
        this(directory.toPath());
    }

    public NSSDatabase(String directory) {
        this(Paths.get(directory));
    }

    public Path getPath() {
        return path;
    }

    public void setPath(Path path) {
        this.path = path;
    }

    public File getDirectory() {
        return path.toFile();
    }

    public void setDirectory(File directory) {
        path = directory.toPath();
    }

    public PasswordStore getPasswordStore() {
        return passwordStore;
    }

    public void setPasswordStore(PasswordStore passwordStore) {
        this.passwordStore = passwordStore;
    }

    public boolean exists() {
        return Files.exists(path);
    }

    public void create() throws Exception {
        String password = passwordStore.getPassword("internal", 0);
        create(password);
    }

    public void create(String password) throws Exception {
        create(password, false);
    }

    public void create(String password, boolean enableTrustPolicy) throws Exception {

        logger.debug("NSSDatabase: Creating NSS database in " + path);

        Files.createDirectories(path);

        Path passwordPath = path.resolve("password.txt");

        try {
            List<String> command = new ArrayList<>();
            command.add("certutil");
            command.add("-N");
            command.add("-d");
            command.add(path.toAbsolutePath().toString());

            if (password == null) {
                command.add("--empty-password");

            } else {
                try (PrintWriter out = new PrintWriter(new FileWriter(passwordPath.toFile()))) {
                    out.println(password);
                }

                command.add("-f");
                command.add(passwordPath.toAbsolutePath().toString());
            }

            debug(command);

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.inheritIO();

            Process p = pb.start();
            int rc = p.waitFor();

            if (rc != 0) {
                throw new Exception("Command failed: rc=" + rc);
            }

        } finally {
            if (Files.exists(passwordPath)) Files.delete(passwordPath);
        }

        if (enableTrustPolicy && !moduleExists("p11-kit-trust")) {
            addModule("p11-kit-trust", "/usr/share/pki/lib/p11-kit-trust.so");
        }
    }

    public boolean moduleExists(String name) throws Exception {

        logger.debug("NSSDatabase: Checking module " + name);

        List<String> command = new ArrayList<>();
        command.add("modutil");
        command.add("-dbdir");
        command.add(path.toAbsolutePath().toString());
        command.add("-rawlist");

        debug(command);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);

        Process p = pb.start();

        // searching for name="<module>"
        String pattern = " name=\"" + name + "\" ";

        try (Reader reader = new InputStreamReader(p.getInputStream());
                BufferedReader in = new BufferedReader(reader)) {

            String line;
            while ((line = in.readLine()) != null) {
                if (line.contains(pattern)) return true;
            }
        }

        int rc = p.waitFor();

        if (rc != 0) {
            throw new Exception("Command failed: rc=" + rc);
        }

        return false;
    }

    public void addModule(String name, String library) throws Exception {

        logger.debug("NSSDatabase: Installing " + name + " module with " + library);

        List<String> command = new ArrayList<>();
        command.add("modutil");
        command.add("-dbdir");
        command.add(path.toAbsolutePath().toString());
        command.add("-add");
        command.add(name);
        command.add("-libfile");
        command.add(library);
        command.add("-force");

        debug(command);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);

        Process p = pb.start();

        try (Writer writer = new OutputStreamWriter(p.getOutputStream());
                PrintWriter out = new PrintWriter(writer)) {

            // modutil will generate the following question:

            // WARNING: Manually adding a module while p11-kit is enabled could cause
            // duplicate module registration in your security database. It is suggested
            // to configure the module through p11-kit configuration file instead.
            //
            // Type 'q <enter>' to abort, or <enter> to continue:

            // respond with <enter>
            out.println();
        }

        int rc = p.waitFor();

        if (rc != 0) {
            throw new Exception("Command failed: rc=" + rc);
        }
    }

    public org.mozilla.jss.crypto.X509Certificate addCertificate(
            X509Certificate cert,
            String trustFlags) throws Exception {

        byte[] bytes = cert.getEncoded();
        CryptoManager manager = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate jssCert = manager.importCACertPackage(bytes);

        if (trustFlags != null) CryptoUtil.setTrustFlags(jssCert, trustFlags);

        return jssCert;
    }

    public org.mozilla.jss.crypto.X509Certificate addPEMCertificate(
            String filename,
            String trustFlags) throws Exception {

        String pemCert = new String(Files.readAllBytes(Paths.get(filename)));
        byte[] bytes = Cert.parseCertificate(pemCert);
        X509CertImpl cert = new X509CertImpl(bytes);

        return addCertificate(cert, trustFlags);
    }

    public void addCertificate(
            String nickname,
            X509CertImpl certImpl,
            String trustFlags) throws Exception {

        addCertificate(null, nickname, certImpl, trustFlags);
    }

    public void addCertificate(
            String tokenName,
            String nickname,
            X509CertImpl certImpl,
            String trustFlags) throws Exception {

        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        logger.info("NSSDatabase: Importing cert " + nickname + " into " + token.getName());

        CryptoStore store = token.getCryptoStore();

        org.mozilla.jss.crypto.X509Certificate cert = store.importCert(
                certImpl.getEncoded(),
                nickname);

        if (trustFlags != null) {
            PK11Cert pk11Cert = (PK11Cert) cert;
            pk11Cert.setTrustFlags(trustFlags);
        }
    }

    public void addPEMCertificate(
            String nickname,
            String filename,
            String trustFlags) throws Exception {

        addPEMCertificate(
                null,
                nickname,
                filename,
                trustFlags);
    }

    public void addPEMCertificate(
            String tokenName,
            String nickname,
            String filename,
            String trustFlags) throws Exception {

        Path passwordPath = null;
        if (trustFlags == null) trustFlags = ",,";

        try {
            List<String> cmd = new ArrayList<>();
            cmd.add("certutil");
            cmd.add("-A");
            cmd.add("-d");
            cmd.add(path.toString());

            if (tokenName != null) {
                cmd.add("-h");
                cmd.add(tokenName);
            }

            if (passwordStore != null) {

                String tag = tokenName == null ? "internal" : "hardware-" + tokenName;
                String password = passwordStore.getPassword(tag, 0);

                if (password != null) {
                    passwordPath = Files.createTempFile("nss-password-", ".txt", FILE_PERMISSIONS);
                    logger.debug("NSSDatabase: Storing password into " + passwordPath);

                    Files.write(passwordPath, password.getBytes());

                    cmd.add("-f");
                    cmd.add(passwordPath.toString());
                }
            }

            // accept PEM or PKCS #7 certificate
            cmd.add("-a");

            cmd.add("-n");
            cmd.add(nickname);

            cmd.add("-t");
            cmd.add(trustFlags);

            cmd.add("-i");
            cmd.add(filename);

            debug(cmd);

            Process p = new ProcessBuilder(cmd).start();

            readStdout(p);
            readStderr(p);

            int rc = p.waitFor();

            if (rc != 0) {
                throw new CLIException("Command failed. RC: " + rc, rc);
            }

        } finally {
            if (passwordPath != null) Files.delete(passwordPath);
        }
    }

    /**
     * This method provides the arguments and the standard input for certutil
     * to create a cert/CSR with basic constraints extension.
     *
     * @param cmd certutil command and arguments
     * @param stdin certutil's standard input
     * @param extension The extension to add
     */
    public void addBasicConstraintsExtension(
            List<String> cmd,
            PrintWriter stdin,
            BasicConstraintsExtension extension) throws Exception {

        logger.debug("NSSDatabase: Adding basic constraints extension:");

        cmd.add("-2");

        // Is this a CA certificate [y/N]?
        boolean ca = (boolean) extension.get(BasicConstraintsExtension.IS_CA);
        logger.debug("NSSDatabase: - CA: " + ca);
        if (ca) {
            stdin.print("y");
        }
        stdin.println();

        // Enter the path length constraint, enter to skip [<0 for unlimited path]: >
        int pathLength = (int) extension.get(BasicConstraintsExtension.PATH_LEN);
        logger.debug("NSSDatabase: - path length: " + pathLength);
        stdin.print(pathLength);
        stdin.println();

        // Is this a critical extension [y/N]?
        if (extension.isCritical()) {
            logger.debug("NSSDatabase: - critical");
            stdin.print("y");
        }
        stdin.println();
    }

    /**
     * This method provides the arguments and the standard input for certutil
     * to create a cert/CSR with AKID extension.
     *
     * @param cmd certutil command and arguments
     * @param stdin certutil's standard input
     * @param extension The extension to add
     */
    public void addAKIDExtension(
            List<String> cmd,
            PrintWriter stdin,
            AuthorityKeyIdentifierExtension extension) throws Exception {

        logger.debug("NSSDatabase: Adding AKID extension:");

        cmd.add("-3");

        // Enter value for the authKeyID extension [y/N]?
        stdin.println("y");

        KeyIdentifier keyID = (KeyIdentifier) extension.get(AuthorityKeyIdentifierExtension.KEY_ID);
        String akid = "0x" + Utils.HexEncode(keyID.getIdentifier());
        logger.debug("NSSDatabase: - AKID: " + akid);

        // Enter value for the key identifier fields,enter to omit:
        stdin.println(akid);

        // Select one of the following general name type:
        stdin.println();

        // Enter value for the authCertSerial field, enter to omit:
        stdin.println();

        // Is this a critical extension [y/N]?
        if (extension.isCritical()) {
            stdin.print("y");
        }
        stdin.println();
    }

    /**
     * This method provides the arguments and the standard input for certutil
     * to create a cert/CSR with SKID extension.
     *
     * @param cmd certutil command and arguments
     * @param stdin certutil's standard input
     * @param extension The extension to add
     */
    public void addSKIDExtension(
            List<String> cmd,
            PrintWriter stdin,
            SubjectKeyIdentifierExtension extension) throws Exception {

        logger.debug("NSSDatabase: Adding SKID extension:");

        cmd.add("--extSKID");

        KeyIdentifier keyID = (KeyIdentifier) extension.get(SubjectKeyIdentifierExtension.KEY_ID);
        String skid = "0x" + Utils.HexEncode(keyID.getIdentifier());
        logger.debug("NSSDatabase: - SKID: " + skid);

        // Enter value for the key identifier fields,enter to omit:
        stdin.println(skid);

        // Is this a critical extension [y/N]?
        if (extension.isCritical()) {
            stdin.print("y");
        }
        stdin.println();
    }

    /**
     * This method provides the arguments and the standard input for certutil
     * to create a cert/CSR with AIA extension.
     *
     * @param cmd certutil command and arguments
     * @param stdin certutil's standard input
     * @param extension The extension to add
     */
    public void addAIAExtension(
            List<String> cmd,
            PrintWriter stdin,
            AuthInfoAccessExtension extension) throws Exception {

        logger.debug("NSSDatabase: Adding AIA extension:");

        cmd.add("--extAIA");

        int size = extension.numberOfAccessDescription();
        for (int i = 0; i < size; i++) {
            AccessDescription ad = extension.getAccessDescription(i);

            ObjectIdentifier method = ad.getMethod();
            if (AuthInfoAccessExtension.METHOD_CA_ISSUERS.equals(method)) {
                logger.debug("NSSDatabase: - CA issuers");

                // Enter access method type for Authority Information Access extension:
                stdin.println("1");

            } else if (AuthInfoAccessExtension.METHOD_OCSP.equals(method)) {
                logger.debug("NSSDatabase: - OCSP");

                // Enter access method type for Authority Information Access extension:
                stdin.println("2");

            } else {
                throw new Exception("Unsupported AIA method: " + method);
            }

            GeneralName location = ad.getLocation();
            if (GeneralNameInterface.NAME_URI == location.getType()) {

                // TODO: Fix JSS to support the following code.
                // URIName uriName = (URIName) location;
                // String uri = uriName.getURI();

                byte[] bytes;
                try (DerOutputStream derOS = new DerOutputStream()) {
                    location.encode(derOS);
                    bytes = derOS.toByteArray();
                }

                DerValue derValue = new DerValue(new ByteArrayInputStream(bytes));
                derValue.resetTag(DerValue.tag_IA5String);
                String uri = derValue.getIA5String();
                logger.debug("NSSDatabase:   - URI: " + uri);

                // Select one of the following general name type:
                stdin.println("7");

                // Enter data:
                stdin.println(uri);

            } else {
                throw new Exception("Unsupported AIA location: " + location);
            }

            // Any other number to finish
            stdin.println();

            // Add another location to the Authority Information Access extension [y/N]
            if (i < size - 1) {
                stdin.print("y");
            }
            stdin.println();
        }

        // Is this a critical extension [y/N]?
        if (extension.isCritical()) {
            stdin.print("y");
        }
        stdin.println();
    }

    /**
     * This method provides the arguments for certutil to create a cert/CSR
     * with key usage extension.
     *
     * @param cmd certutil command and arguments
     * @param extension The extension to add
     */
    public void addKeyUsageExtension(
            List<String> cmd,
            KeyUsageExtension extension) throws Exception {

        logger.debug("NSSDatabase: Adding key usage extension:");

        cmd.add("--keyUsage");

        List<String> options = new ArrayList<>();

        if (extension.isCritical()) {
            logger.debug("NSSDatabase: - critical");
            options.add("critical");
        }

        Boolean digitalSignature = (Boolean) extension.get(KeyUsageExtension.DIGITAL_SIGNATURE);
        if (digitalSignature) {
            logger.debug("NSSDatabase: - digitalSignature");
            options.add("digitalSignature");
        }

        Boolean nonRepudiation = (Boolean) extension.get(KeyUsageExtension.NON_REPUDIATION);
        if (nonRepudiation) {
            logger.debug("NSSDatabase: - nonRepudiation");
            options.add("nonRepudiation");
        }

        Boolean keyEncipherment = (Boolean) extension.get(KeyUsageExtension.KEY_ENCIPHERMENT);
        if (keyEncipherment) {
            logger.debug("NSSDatabase: - keyEncipherment");
            options.add("keyEncipherment");
        }

        Boolean dataEncipherment = (Boolean) extension.get(KeyUsageExtension.DATA_ENCIPHERMENT);
        if (dataEncipherment) {
            logger.debug("NSSDatabase: - dataEncipherment");
            options.add("dataEncipherment");
        }

        Boolean keyAgreement = (Boolean) extension.get(KeyUsageExtension.KEY_AGREEMENT);
        if (keyAgreement) {
            logger.debug("NSSDatabase: - keyAgreement");
            options.add("keyAgreement");
        }

        Boolean certSigning = (Boolean) extension.get(KeyUsageExtension.KEY_CERTSIGN);
        if (certSigning) {
            logger.debug("NSSDatabase: - certSigning");
            options.add("certSigning");
        }

        Boolean crlSigning = (Boolean) extension.get(KeyUsageExtension.CRL_SIGN);
        if (crlSigning) {
            logger.debug("NSSDatabase: - crlSigning");
            options.add("crlSigning");
        }

        // TODO: Support other key usages.

        cmd.add(StringUtils.join(options, ","));
    }

    /**
     * This method provides the arguments for certutil to create a cert/CSR
     * with extended key usage extension.
     *
     * @param cmd certutil command and arguments
     * @param extension The extension to add
     */
    public void addExtendedKeyUsageExtension(
            List<String> cmd,
            ExtendedKeyUsageExtension extension) throws Exception {

        logger.debug("NSSDatabase: Adding extended key usage extension:");

        cmd.add("--extKeyUsage");

        List<String> options = new ArrayList<>();

        if (extension.isCritical()) {
            logger.debug("NSSDatabase: - critical");
            options.add("critical");
        }

        Enumeration<ObjectIdentifier> e = extension.getOIDs();
        while (e.hasMoreElements()) {
            ObjectIdentifier oid = e.nextElement();

            if (ObjectIdentifier.getObjectIdentifier("1.3.6.1.5.5.7.3.1").equals(oid)) {
                logger.debug("NSSDatabase: - serverAuth");
                options.add("serverAuth");

            } else if (ObjectIdentifier.getObjectIdentifier("1.3.6.1.5.5.7.3.2").equals(oid)) {
                logger.debug("NSSDatabase: - clientAuth");
                options.add("clientAuth");

            } else if (ObjectIdentifier.getObjectIdentifier("1.3.6.1.5.5.7.3.4").equals(oid)) {
                logger.debug("NSSDatabase: - emailProtection");
                options.add("emailProtection");

            } else if (ObjectIdentifier.getObjectIdentifier("1.3.6.1.5.5.7.3.9").equals(oid)) {
                logger.debug("NSSDatabase: - OCSPSigning");
                options.add("ocspResponder");

            } else {
                throw new Exception("Unsupported extended key usage: " + oid);
            }

            // TODO: Support other extended key usages.
        }

        cmd.add(StringUtils.join(options, ","));
    }

    /**
     * This method provides the arguments and the standard input for certutil
     * to create a cert/CSR with certificate policies extension.
     *
     * @param cmd certutil command and arguments
     * @param stdin certutil's standard input
     * @param extension The extension to add
     */
    public void addCertificatePoliciesExtension(
            List<String> cmd,
            PrintWriter stdin,
            CertificatePoliciesExtension extension) throws Exception {

        logger.debug("NSSDatabase: Adding certificate policies extension:");

        cmd.add("--extCP");

        Vector<CertificatePolicyInfo> infos = (Vector<CertificatePolicyInfo>)
                extension.get(CertificatePoliciesExtension.INFOS);

        for (int i = 0; i < infos.size(); i++) {
            CertificatePolicyInfo info = infos.get(i);

            CertificatePolicyId policyID = info.getPolicyIdentifier();
            ObjectIdentifier policyOID = policyID.getIdentifier();
            logger.debug("NSSDatabase: - " + policyOID);

            // Enter a CertPolicy Object Identifier (dotted decimal format)
            // or "any" for AnyPolicy: >
            stdin.println(policyOID);

            PolicyQualifiers qualifiers = info.getPolicyQualifiers();

            if (qualifiers == null || qualifiers.size() == 0) {
                // Choose the type of qualifier for policy:
                stdin.println();

            } else {

                int size = qualifiers.size();
                for (int j = 0; j < size; j++) {
                    PolicyQualifierInfo qualifierInfo = qualifiers.getInfoAt(j);
                    ObjectIdentifier qualifierOID = qualifierInfo.getId();

                    if (PolicyQualifierInfo.QT_CPS.equals(qualifierOID)) {

                        CPSuri cpsURI = (CPSuri) qualifierInfo.getQualifier();
                        String uri = cpsURI.getURI();
                        logger.debug("NSSDatabase:   - CPS: " + uri);

                        // Choose the type of qualifier for policy:
                        stdin.println("1");

                        // Enter CPS pointer URI:
                        stdin.println(uri);

                        // Enter another policy qualifier [y/N]
                        if (j < size - 1) {
                            stdin.print("y");
                        }
                        stdin.println();

                    } else {
                        throw new Exception("Unsupported certificate policy qualifier: " + qualifierOID);
                    }
                }
            }

            // Enter another PolicyInformation field [y/N]
            if (i < infos.size() - 1) {
                stdin.print("y");
            }
            stdin.println();
        }

        // Is this a critical extension [y/N]?
        if (extension.isCritical()) {
            stdin.print("y");
        }
        stdin.println();
    }

    /**
     * This method provides the arguments and the standard input for certutil
     * to create a cert/CSR with OCSP No Check extension.
     *
     * @param cmd certutil command and arguments
     * @param stdin certutil's standard input
     * @param extension The extension to add
     * @param tmpDir Temporary directory to store extension value
     */
    public void addOCSPNoCheckExtension(
            List<String> cmd,
            PrintWriter stdin,
            OCSPNoCheckExtension extension,
            Path tmpDir) throws Exception {

        logger.debug("NSSDatabase: Adding OCSP No Check extension:");

        cmd.add("--extGeneric");

        ObjectIdentifier oid = extension.getExtensionId();
        logger.debug("NSSDatabase: - OID: " + oid);

        boolean critical = extension.isCritical();
        logger.debug("NSSDatabase: - critical: " + critical);
        String flag = critical ? "critical" : "not-critical";

        byte[] value = extension.getExtensionValue();
        logger.debug("NSSDatabase: - value: " + (value == null ? null : Utils.base64encodeSingleLine(value)));
        Path file = tmpDir.resolve("ocsp-no-check.ext");
        Files.write(file, value);

        cmd.add(oid + ":" + flag + ":" + file);
    }

    public void addExtensions(
            List<String> cmd,
            StringWriter sw,
            Extensions extensions,
            Path tmpDir) throws Exception {

        PrintWriter stdin = new PrintWriter(sw, true);

        for (Extension extension : extensions) {

            if (extension instanceof BasicConstraintsExtension) {
                BasicConstraintsExtension basicConstraintsExtension = (BasicConstraintsExtension) extension;
                addBasicConstraintsExtension(cmd, stdin, basicConstraintsExtension);

            } else if (extension instanceof AuthorityKeyIdentifierExtension) {
                AuthorityKeyIdentifierExtension akidExtension = (AuthorityKeyIdentifierExtension) extension;
                addAKIDExtension(cmd, stdin, akidExtension);

            } else if (extension instanceof SubjectKeyIdentifierExtension) {
                SubjectKeyIdentifierExtension skidExtension = (SubjectKeyIdentifierExtension) extension;
                addSKIDExtension(cmd, stdin, skidExtension);

            } else if (extension instanceof AuthInfoAccessExtension) {
                AuthInfoAccessExtension aiaExtension = (AuthInfoAccessExtension) extension;
                addAIAExtension(cmd, stdin, aiaExtension);

            } else if (extension instanceof KeyUsageExtension) {
                KeyUsageExtension keyUsageExtension = (KeyUsageExtension) extension;
                addKeyUsageExtension(cmd, keyUsageExtension);

            } else if (extension instanceof ExtendedKeyUsageExtension) {
                ExtendedKeyUsageExtension extendedKeyUsageExtension = (ExtendedKeyUsageExtension) extension;
                addExtendedKeyUsageExtension(cmd, extendedKeyUsageExtension);

            } else if (extension instanceof CertificatePoliciesExtension) {
                CertificatePoliciesExtension certificatePoliciesExtension = (CertificatePoliciesExtension) extension;
                addCertificatePoliciesExtension(cmd, stdin, certificatePoliciesExtension);

            } else if (extension instanceof OCSPNoCheckExtension) {
                OCSPNoCheckExtension ocspNoCheckExtension = (OCSPNoCheckExtension) extension;
                addOCSPNoCheckExtension(cmd, stdin, ocspNoCheckExtension, tmpDir);
            }
        }
    }

    public KeyPair loadKeyPair(
            CryptoToken token,
            byte[] keyID) throws Exception {

        String hexKeyID = "0x" + Utils.HexEncode(keyID);
        logger.debug("NSSDatabase: Loading key " + hexKeyID);

        PK11PrivKey privateKey = (PK11PrivKey) CryptoUtil.findPrivateKey(token, keyID);

        if (privateKey == null) {
            throw new Exception("Private key not found: " + hexKeyID);
        }

        logger.debug("NSSDatabase: - class: " + privateKey.getClass().getName());
        logger.debug("NSSDatabase: - algorithm: " + privateKey.getAlgorithm());
        logger.debug("NSSDatabase: - format: " + privateKey.getFormat());

        PK11PubKey publicKey = privateKey.getPublicKey();

        String keyType = privateKey.getType().toString();
        logger.debug("NSSDatabase: - key type: " + keyType);

        if (privateKey instanceof PK11RSAPrivateKey) {
            logger.debug("NSSDatabase: - size: " + privateKey.getStrength());

        } else if (privateKey instanceof PK11ECPrivateKey) {
            PK11ECPrivateKey ecPrivateKey = (PK11ECPrivateKey) privateKey;
            ECParameterSpec spec = ecPrivateKey.getParams();
            logger.debug("NSSDatabase: - curve: " + spec.getCurve());
        }

        return new KeyPair(publicKey, privateKey);
    }

    public KeyPair createRSAKeyPair(
            CryptoToken token,
            int keySize,
            Boolean temporary,
            Boolean sensitive,
            Boolean extractable,
            Usage[] usages,
            Usage[] usagesMask) throws Exception {

        logger.debug("NSSDatabase: Creating RSA key");
        logger.debug("NSSDatabase: - size: " + keySize);

        return CryptoUtil.generateRSAKeyPair(
                token,
                keySize,
                temporary,
                sensitive,
                extractable,
                usages,
                usagesMask);
    }

    public KeyPair createRSAKeyPair(
            CryptoToken token,
            int keySize,
            Usage[] usages,
            Usage[] usagesMask) throws Exception {

        logger.debug("NSSDatabase: Creating RSA key");
        logger.debug("NSSDatabase: - size: " + keySize);

        return CryptoUtil.generateRSAKeyPair(
                token,
                keySize,
                false,
                false,
                false,
                usages,
                usagesMask);
    }

    public KeyPair createRSAKeyPair(
            CryptoToken token,
            int keySize) throws Exception {

        logger.debug("NSSDatabase: Creating RSA key");
        logger.debug("NSSDatabase: - size: " + keySize);

        return CryptoUtil.generateRSAKeyPair(
                token,
                keySize,
                false,
                false,
                false,
                null,
                null);
    }

    public KeyPair createECKeyPair(
            CryptoToken token,
            String curveName,
            Boolean temporary,
            Boolean sensitive,
            Boolean extractable,
            Usage[] usages,
            Usage[] usagesMask) throws Exception {

        logger.debug("NSSDatabase: Creating EC key");
        logger.debug("NSSDatabase: - curve: " + curveName);

        return CryptoUtil.generateECCKeyPair(
                token,
                curveName,
                temporary,
                sensitive,
                extractable,
                usages,
                usagesMask);
    }

    public KeyPair createECKeyPair(
            CryptoToken token,
            String curveName,
            Usage[] usages,
            Usage[] usagesMask) throws Exception {

        logger.debug("NSSDatabase: Creating EC key");
        logger.debug("NSSDatabase: - curve: " + curveName);

        return CryptoUtil.generateECCKeyPair(
                token,
                curveName,
                null,
                null,
                null,
                usages,
                usagesMask);
    }

    public KeyPair createECKeyPair(
            CryptoToken token,
            String curveName) throws Exception {

        logger.debug("NSSDatabase: Creating EC key");
        logger.debug("NSSDatabase: - curve: " + curveName);

        return CryptoUtil.generateECCKeyPair(
                token,
                curveName,
                null,
                null,
                null,
                null,
                null);
    }

    public PKCS10 createPKCS10Request(
            KeyPair keyPair,
            String subject,
            String algorithm,
            Extensions extensions) throws Exception {

        logger.debug("NSSDatabase: Creating PKCS #10 request");
        logger.debug("NSSDatabase: - subjecct: " + subject);
        logger.debug("NSSDatabase: - algorithm: " + algorithm);

        return CryptoUtil.createCertificationRequest(
                subject,
                keyPair,
                algorithm,
                extensions);
    }

    public static int validityUnitFromString(String validityUnit) throws Exception {

        if (validityUnit.equalsIgnoreCase("year")) {
            return Calendar.YEAR;

        } else if (validityUnit.equalsIgnoreCase("month")) {
            return Calendar.MONTH;

        } else if (validityUnit.equalsIgnoreCase("day")) {
            return Calendar.DAY_OF_YEAR;

        } else if (validityUnit.equalsIgnoreCase("hour")) {
            return Calendar.HOUR_OF_DAY;

        } else if (validityUnit.equalsIgnoreCase("minute")) {
            return Calendar.MINUTE;

        } else {
            throw new Exception("Invalid validity unit: " + validityUnit);
        }
    }

    public static String validityUnitToString(int validityUnit) throws Exception {

        if (validityUnit == Calendar.YEAR) {
            return "year";

        } else if (validityUnit == Calendar.MONTH) {
            return "month";

        } else if (validityUnit == Calendar.DAY_OF_YEAR) {
            return "day";

        } else if (validityUnit == Calendar.HOUR_OF_DAY) {
            return "hour";

        } else if (validityUnit == Calendar.MINUTE) {
            return "minute";

        } else {
            throw new Exception("Invalid validity unit: " + validityUnit);
        }
    }

    public X509Certificate createCertificate(
            org.mozilla.jss.crypto.X509Certificate issuer,
            PKCS10 pkcs10,
            int validityLength,
            int validityUnit,
            String hash,
            Extensions extensions) throws Exception {

        return createCertificate(
                issuer,
                pkcs10,
                null, // serial number
                validityLength,
                validityUnit,
                hash,
                extensions);
    }

    public X509Certificate createCertificate(
            org.mozilla.jss.crypto.X509Certificate issuer,
            PKCS10 pkcs10,
            String serialNumber,
            int validityLength,
            int validityUnit,
            String hash,
            Extensions extensions) throws Exception {

        return createCertificate(
                null, // token name
                issuer,
                pkcs10,
                serialNumber,
                validityLength,
                validityUnit,
                hash,
                extensions);
    }

    public X509Certificate createCertificate(
            String tokenName,
            org.mozilla.jss.crypto.X509Certificate issuer,
            PKCS10 pkcs10,
            String serialNumber,
            int validityLength,
            int validityUnit,
            String hash,
            Extensions extensions) throws Exception {

        X500Name subjectName = pkcs10.getSubjectName();
        logger.debug("NSSDatabase: Issuing cert for " + subjectName);

        if (tokenName != null) {
            logger.debug("NSSDatabase: - token: " + tokenName);
        }

        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        X500Name issuerName;
        if (issuer == null) {
            issuerName = subjectName;
        } else {
            issuerName = new X500Name(issuer.getSubjectDN().toString());
        }

        CertificateIssuerName certIssuerName = new CertificateIssuerName(issuerName);
        logger.debug("NSSDatabase: - issuer: " + certIssuerName);

        X509Key x509Key = pkcs10.getSubjectPublicKeyInfo();
        logger.debug("NSSDatabase: - public key algorithm: " + x509Key.getAlgorithm());

        BigInteger serialNo;
        if (serialNumber == null) {
            byte[] bytes = new byte[16];
            SecureRandom random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
            random.nextBytes(bytes);
            serialNo = new BigInteger(1, bytes);
        } else {
            serialNo = new BigInteger(serialNumber);
        }
        logger.debug("NSSDatabase: - serial number: 0x" + Utils.HexEncode(serialNo.toByteArray()));

        Calendar calendar = Calendar.getInstance();
        Date notBeforeDate = calendar.getTime();
        logger.debug("NSSDatabase: - not before: " + notBeforeDate);

        calendar.add(validityUnit, validityLength);
        Date notAfterDate = calendar.getTime();
        logger.debug("NSSDatabase: - not after: " + notAfterDate);

        if (hash == null) {
            hash = "SHA256";
        }
        logger.debug("NSSDatabase: - hash algorithm: " + hash);

        String keyAlgorithm = hash + "with" + x509Key.getAlgorithm();
        logger.debug("NSSDatabase: - key algorithm: " + keyAlgorithm);

        // convert Extensions into CertificateExtensions
        CertificateExtensions certExts = new CertificateExtensions();

        if (extensions != null) {
            Enumeration<String> names = extensions.getAttributeNames();
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                Extension extension = (Extension) extensions.get(name);
                certExts.set(name, extension);
            }
        }

        X509CertInfo info = CryptoUtil.createX509CertInfo(
                x509Key,
                serialNo,
                certIssuerName,
                subjectName,
                notBeforeDate,
                notAfterDate,
                keyAlgorithm,
                certExts);

        PrivateKey privateKey = null;

        if (issuer == null) {

            logger.debug("NSSDatabase: Finding request private key");
            byte[] requestPublicKey = x509Key.getEncoded();

            CryptoStore store = token.getCryptoStore();

            for (PrivateKey privKey : store.getPrivateKeys()) {
                PK11PrivKey pk11PrivKey = (PK11PrivKey) privKey;
                logger.debug("NSSDatabase: - private key: 0x" + Utils.HexEncode(privKey.getUniqueID()));

                PK11PubKey pk11PubKey = pk11PrivKey.getPublicKey();
                byte[] publicKey = pk11PubKey.getEncoded();

                if (Arrays.equals(requestPublicKey, publicKey)) {
                    privateKey = privKey;
                    break;
                }
            }

            if (privateKey == null) {
                throw new Exception("Unable to find request private key");
            }

        } else {
            logger.debug("NSSDatabase: Finding issuer private key");
            CryptoManager cm = CryptoManager.getInstance();
            privateKey = cm.findPrivKeyByCert(issuer);
            logger.debug("NSSDatabase: - private key: " + Utils.HexEncode(privateKey.getUniqueID()));
        }

        logger.debug("NSSDatabase: Private key algorithm: " + privateKey.getAlgorithm());
        String signingAlgorithm = hash + "with" + privateKey.getAlgorithm();
        logger.debug("NSSDatabase: Signing algorithm: " + signingAlgorithm);

        return CryptoUtil.signCert(privateKey, info, signingAlgorithm);
    }

    public void delete() throws Exception {
        FileUtils.deleteDirectory(path.toFile());
    }

    public void debug(Collection<String> command) {

        if (logger.isDebugEnabled()) {

            StringBuilder sb = new StringBuilder("Command:");

            for (String c : command) {

                boolean quote = c.contains(" ");

                sb.append(' ');

                if (quote) sb.append('"');
                sb.append(c);
                if (quote) sb.append('"');
            }

            logger.debug("NSSDatabase: " + sb);
        }
    }

    public void readStdout(Process process) {
        new Thread() {
            @Override
            public void run() {
                try (InputStream is = process.getInputStream();
                        InputStreamReader isr = new InputStreamReader(is);
                        BufferedReader in = new BufferedReader(isr)) {

                    String line;
                    while ((line = in.readLine()) != null) {
                        logger.debug("NSSDatabase: " + line);
                    }

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }.start();
    }

    public void readStderr(Process process) {
        new Thread() {
            @Override
            public void run() {
                try (InputStream is = process.getErrorStream();
                        InputStreamReader isr = new InputStreamReader(is);
                        BufferedReader in = new BufferedReader(isr)) {

                    String line;
                    while ((line = in.readLine()) != null) {
                        logger.warn("NSSDatabase: " + line);
                    }

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }.start();
    }

    public void writeStdin(Process process, String input) throws Exception {
        try (OutputStream os = process.getOutputStream();
                PrintWriter out = new PrintWriter(os)) {
            out.print(input);
        }
    }
}
