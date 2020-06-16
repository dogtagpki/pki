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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.cli.CLIException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.extensions.AccessDescription;
import org.mozilla.jss.netscape.security.extensions.AuthInfoAccessExtension;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.IPasswordStore;

/**
 * @author Endi S. Dewata
 */
public class NSSDatabase {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSDatabase.class);

    FileAttribute<Set<PosixFilePermission>> FILE_PERMISSIONS =
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));

    Path path;
    IPasswordStore passwordStore;

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

    public IPasswordStore getPasswordStore() {
        return passwordStore;
    }

    public void setPasswordStore(IPasswordStore passwordStore) {
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

        logger.info("Creating NSS database in " + path);

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

        logger.info("Checking module " + name);

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

        logger.info("Installing " + name + " module with " + library);

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
            String trustAttributes) throws Exception {

        byte[] bytes = cert.getEncoded();
        CryptoManager manager = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate jssCert = manager.importCACertPackage(bytes);

        if (trustAttributes != null) CryptoUtil.setTrustFlags(jssCert, trustAttributes);

        return jssCert;
    }

    public org.mozilla.jss.crypto.X509Certificate addPEMCertificate(
            String filename,
            String trustAttributes) throws Exception {

        String pemCert = new String(Files.readAllBytes(Paths.get(filename)));
        byte[] bytes = Cert.parseCertificate(pemCert);
        X509CertImpl cert = new X509CertImpl(bytes);

        return addCertificate(cert, trustAttributes);
    }

    public void addCertificate(
            String nickname,
            X509Certificate cert,
            String trustAttributes) throws Exception {

        byte[] bytes = CertUtil.toPEM(cert).getBytes();
        Path certPath = null;

        try {
            certPath = Files.createTempFile("nss-cert-", ".crt", FILE_PERMISSIONS);
            Files.write(certPath, bytes);

            addPEMCertificate(nickname, certPath.toString(), trustAttributes);

        } finally {
            if (certPath != null) Files.delete(certPath);
        }
    }

    public void addPEMCertificate(
            String nickname,
            String filename,
            String trustAttributes) throws Exception {

        Path passwordPath = null;

        try {
            List<String> cmd = new ArrayList<>();
            cmd.add("certutil");
            cmd.add("-A");
            cmd.add("-d");
            cmd.add(path.toString());

            // TODO: Add support for HSM.
            String password = passwordStore.getPassword("internal", 0);

            if (password != null) {
                passwordPath = Files.createTempFile("nss-password-", ".txt", FILE_PERMISSIONS);
                logger.info("Storing password into " + passwordPath);

                Files.write(passwordPath, password.getBytes());

                cmd.add("-f");
                cmd.add(passwordPath.toString());
            }

            // accept PEM or PKCS #7 certificate
            cmd.add("-a");

            cmd.add("-n");
            cmd.add(nickname);

            cmd.add("-t");
            cmd.add(trustAttributes);

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

        logger.info("Adding basic constraints extension:");

        cmd.add("-2");

        // Is this a CA certificate [y/N]?
        boolean ca = (boolean) extension.get(BasicConstraintsExtension.IS_CA);
        logger.info("- CA: " + ca);
        if (ca) {
            stdin.print("y");
        }
        stdin.println();

        // Enter the path length constraint, enter to skip [<0 for unlimited path]: >
        int pathLength = (int) extension.get(BasicConstraintsExtension.PATH_LEN);
        logger.info("- path length: " + pathLength);
        stdin.print(pathLength);
        stdin.println();

        // Is this a critical extension [y/N]?
        if (extension.isCritical()) {
            logger.info("- critical");
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

        logger.info("Adding AKID extension:");

        cmd.add("-3");

        // Enter value for the authKeyID extension [y/N]?
        stdin.println("y");

        KeyIdentifier keyID = (KeyIdentifier) extension.get(AuthorityKeyIdentifierExtension.KEY_ID);
        String akid = "0x" + Utils.HexEncode(keyID.getIdentifier());
        logger.info("- AKID: " + akid);

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

        logger.info("Adding SKID extension:");

        cmd.add("--extSKID");

        KeyIdentifier keyID = (KeyIdentifier) extension.get(SubjectKeyIdentifierExtension.KEY_ID);
        String skid = "0x" + Utils.HexEncode(keyID.getIdentifier());
        logger.info("- SKID: " + skid);

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

        logger.info("Adding AIA extension:");

        cmd.add("--extAIA");

        int size = extension.numberOfAccessDescription();
        for (int i = 0; i < size; i++) {
            AccessDescription ad = extension.getAccessDescription(i);

            ObjectIdentifier method = ad.getMethod();
            if (AuthInfoAccessExtension.METHOD_CA_ISSUERS.equals(method)) {
                logger.info("- CA issuers");

                // Enter access method type for Authority Information Access extension:
                stdin.println("1");

            } else if (AuthInfoAccessExtension.METHOD_OCSP.equals(method)) {
                logger.info("- OCSP");

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
                logger.info("  - URI: " + uri);

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

        logger.info("Adding key usage extension:");

        cmd.add("--keyUsage");

        List<String> options = new ArrayList<>();

        if (extension.isCritical()) {
            logger.info("- critical");
            options.add("critical");
        }

        Boolean digitalSignature = (Boolean) extension.get(KeyUsageExtension.DIGITAL_SIGNATURE);
        if (digitalSignature) {
            logger.info("- digitalSignature");
            options.add("digitalSignature");
        }

        Boolean nonRepudiation = (Boolean) extension.get(KeyUsageExtension.NON_REPUDIATION);
        if (nonRepudiation) {
            logger.info("- nonRepudiation");
            options.add("nonRepudiation");
        }

        Boolean keyEncipherment = (Boolean) extension.get(KeyUsageExtension.KEY_ENCIPHERMENT);
        if (keyEncipherment) {
            logger.info("- keyEncipherment");
            options.add("keyEncipherment");
        }

        Boolean dataEncipherment = (Boolean) extension.get(KeyUsageExtension.DATA_ENCIPHERMENT);
        if (dataEncipherment) {
            logger.info("- dataEncipherment");
            options.add("dataEncipherment");
        }

        Boolean keyAgreement = (Boolean) extension.get(KeyUsageExtension.KEY_AGREEMENT);
        if (keyAgreement) {
            logger.info("- keyAgreement");
            options.add("keyAgreement");
        }

        Boolean certSigning = (Boolean) extension.get(KeyUsageExtension.KEY_CERTSIGN);
        if (certSigning) {
            logger.info("- certSigning");
            options.add("certSigning");
        }

        Boolean crlSigning = (Boolean) extension.get(KeyUsageExtension.CRL_SIGN);
        if (crlSigning) {
            logger.info("- crlSigning");
            options.add("crlSigning");
        }

        // TODO: Support other key usages.

        cmd.add(StringUtils.join(options, ","));
    }

    public void addExtensions(
            List<String> cmd,
            StringWriter sw,
            CertificateExtensions extensions) throws Exception {

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
            }
        }
    }

    public PKCS10 createRequest(
            String subject,
            String keyID,
            String keyType,
            String keySize,
            String curve,
            String hash,
            CertificateExtensions extensions) throws Exception {

        logger.info("Creating certificate signing request for " + subject);

        if (keyID != null) {
            logger.info("- key ID: " + keyID);
        }

        if (keyType != null) {
            logger.info("- key type: " + keyType);
        }

        if (keySize != null) {
            logger.info("- key size: " + keySize);
        }

        if (curve != null) {
            logger.info("- curve: " + curve);
        }

        Path csrPath = null;
        Path passwordPath = null;
        Path noisePath = null;

        try {
            csrPath = Files.createTempFile("nss-request-", ".csr", FILE_PERMISSIONS);

            // TODO: Use JSS to generate the request.

            List<String> cmd = new ArrayList<>();
            cmd.add("certutil");
            cmd.add("-R");
            cmd.add("-d");
            cmd.add(path.toString());

            if (passwordStore != null) {

                // TODO: Add support for HSM.
                String password = passwordStore.getPassword("internal", 0);

                if (password != null) {
                    passwordPath = Files.createTempFile("nss-password-", ".txt", FILE_PERMISSIONS);
                    logger.info("Storing password into " + passwordPath);

                    Files.write(passwordPath, password.getBytes());

                    cmd.add("-f");
                    cmd.add(passwordPath.toString());
                }
            }

            cmd.add("-s");
            cmd.add(subject);

            cmd.add("-o");
            cmd.add(csrPath.toString());

            if (keyID != null) { // use existing key

                cmd.add("-k");
                cmd.add(keyID);

            } else { // generate new key

                if (keyType != null) {
                    cmd.add("-k");
                    cmd.add(keyType.toLowerCase());
                }

                if (keySize != null) {
                    cmd.add("-g");
                    cmd.add(keySize);

                }

                if (curve != null) {
                    cmd.add("-q");
                    cmd.add(curve);
                }

                noisePath = Files.createTempFile("nss-noise-", ".bin", FILE_PERMISSIONS);
                logger.info("Storing noise into " + noisePath);

                byte[] bytes = new byte[2048];
                SecureRandom random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
                random.nextBytes(bytes);

                Files.write(noisePath, bytes);

                cmd.add("-z");
                cmd.add(noisePath.toString());
            }

            if (hash != null) {
                cmd.add("-Z");
                cmd.add(hash);
            }

            StringWriter stdin = new StringWriter();
            if (extensions != null) {
                addExtensions(cmd, stdin, extensions);
            }

            debug(cmd);
            Process p = new ProcessBuilder(cmd).start();

            readStdout(p);
            readStderr(p);

            if (extensions != null) {
                writeStdin(p, stdin.toString());
            }

            int rc = p.waitFor();

            if (rc != 0) {
                throw new CLIException("Command failed. RC: " + rc, rc);
            }

            logger.info("Loading CSR from " + csrPath);
            byte[] csrBytes = Files.readAllBytes(csrPath);
            return new PKCS10(csrBytes);

        } finally {
            if (noisePath != null) Files.delete(noisePath);
            if (passwordPath != null) Files.delete(passwordPath);
            if (csrPath != null) Files.delete(csrPath);
        }
    }

    public X509Certificate createCertificate(
            org.mozilla.jss.crypto.X509Certificate issuer,
            PKCS10 pkcs10,
            Integer monthsValid,
            CertificateExtensions extensions) throws Exception {

        Path csrPath = null;
        Path certPath = null;
        Path passwordPath = null;

        try {
            csrPath = Files.createTempFile("nss-request-", ".csr", FILE_PERMISSIONS);
            certPath = Files.createTempFile("nss-cert-", ".crt", FILE_PERMISSIONS);

            logger.info("Storing CSR into " + csrPath);
            Files.write(csrPath, pkcs10.toByteArray());

            // TODO: Use JSS to issue the certificate.

            List<String> cmd = new ArrayList<>();
            cmd.add("certutil");
            cmd.add("-C");
            cmd.add("-d");
            cmd.add(path.toString());

            if (passwordStore != null) {

                // TODO: Add support for HSM.
                String password = passwordStore.getPassword("internal", 0);

                if (password != null) {
                    passwordPath = Files.createTempFile("nss-password-", ".txt", FILE_PERMISSIONS);
                    logger.info("Storing password into " + passwordPath);

                    Files.write(passwordPath, password.getBytes());

                    cmd.add("-f");
                    cmd.add(passwordPath.toString());
                }
            }

            if (issuer == null) {
                cmd.add("-x");

            } else {
                cmd.add("-c");
                cmd.add(issuer.getNickname());
            }

            cmd.add("-i");
            cmd.add(csrPath.toString());

            cmd.add("-o");
            cmd.add(certPath.toString());

            if (monthsValid != null) {
                cmd.add("-v");
                cmd.add(monthsValid.toString());
            }

            StringWriter stdin = new StringWriter();
            if (extensions != null) {
                addExtensions(cmd, stdin, extensions);
            }

            debug(cmd);
            Process p = new ProcessBuilder(cmd).start();

            readStdout(p);
            readStderr(p);

            if (extensions != null) {
                writeStdin(p, stdin.toString());
            }

            int rc = p.waitFor();

            if (rc != 0) {
                throw new CLIException("Command failed. RC: " + rc, rc);
            }

            logger.info("Loading certificate from " + certPath);
            byte[] certBytes = Files.readAllBytes(certPath);
            return new X509CertImpl(certBytes);

        } finally {
            if (passwordPath != null) Files.delete(passwordPath);
            if (certPath != null) Files.delete(certPath);
            if (csrPath != null) Files.delete(csrPath);
        }
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

            logger.debug(sb.toString());
        }
    }

    public void readStdout(Process process) {
        new Thread() {
            public void run() {
                try (InputStream is = process.getInputStream();
                        InputStreamReader isr = new InputStreamReader(is);
                        BufferedReader in = new BufferedReader(isr)) {

                    String line;
                    while ((line = in.readLine()) != null) {
                        logger.info(line);
                    }

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }.start();
    }

    public void readStderr(Process process) {
        new Thread() {
            public void run() {
                try (InputStream is = process.getErrorStream();
                        InputStreamReader isr = new InputStreamReader(is);
                        BufferedReader in = new BufferedReader(isr)) {

                    String line;
                    while ((line = in.readLine()) != null) {
                        logger.warn(line);
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
