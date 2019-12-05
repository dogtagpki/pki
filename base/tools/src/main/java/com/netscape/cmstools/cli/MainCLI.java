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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.cli;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.ProcessingException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.common.Info;
import org.dogtagpki.common.InfoClient;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.Level;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLVersion;
import org.mozilla.jss.ssl.SSLVersionRange;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.PKIConnection;
import com.netscape.cmstools.ca.CACLI;
import com.netscape.cmstools.cert.ProxyCertCLI;
import com.netscape.cmstools.client.ClientCLI;
import com.netscape.cmstools.group.ProxyGroupCLI;
import com.netscape.cmstools.key.ProxyKeyCLI;
import com.netscape.cmstools.kra.KRACLI;
import com.netscape.cmstools.nss.NSSCLI;
import com.netscape.cmstools.ocsp.OCSPCLI;
import com.netscape.cmstools.pkcs11.PKCS11CLI;
import com.netscape.cmstools.pkcs12.PKCS12CLI;
import com.netscape.cmstools.pkcs7.PKCS7CLI;
import com.netscape.cmstools.system.SecurityDomainCLI;
import com.netscape.cmstools.tks.TKSCLI;
import com.netscape.cmstools.tps.TPSCLI;
import com.netscape.cmstools.user.ProxyUserCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class MainCLI extends CLI {

    public ClientConfig config = new ClientConfig();

    public Collection<Integer> rejectedCertStatuses = new HashSet<Integer>();
    public Collection<Integer> ignoredCertStatuses = new HashSet<Integer>();

    public boolean ignoreBanner;
    public File certDatabase;

    String output;

    boolean initialized;

    public MainCLI() throws Exception {
        super("pki", "PKI command-line interface");

        addModule(new HelpCLI(this));

        addModule(new ClientCLI(this));
        addModule(new NSSCLI(this));

        addModule(new ProxyCertCLI(this));
        addModule(new ProxyGroupCLI(this));
        addModule(new ProxyKeyCLI(this));
        addModule(new ProxyCLI(new SecurityDomainCLI(this), "ca"));
        addModule(new ProxyUserCLI(this));

        addModule(new CACLI(this));
        addModule(new KRACLI(this));
        addModule(new OCSPCLI(this));
        addModule(new TKSCLI(this));
        addModule(new TPSCLI(this));

        addModule(new PKCS7CLI(this));
        addModule(new PKCS11CLI(this));
        addModule(new PKCS12CLI(this));

        createOptions();
    }

    public File getNSSDatabase() {
        return certDatabase;
    }

    public String getFullModuleName(String moduleName) {
        return moduleName;
    }

    @Override
    public String getManPage() {
        return "pki";
    }

    public void printVersion() {
        Package pkg = MainCLI.class.getPackage();
        System.out.println("PKI Command-Line Interface " + pkg.getImplementationVersion());
    }

    public void printHelp() {

        formatter.printHelp(name + " [OPTIONS..] <command> [ARGS..]", options);
        System.out.println();

        super.printHelp();
    }

    public void createOptions() throws UnknownHostException {

        Option option = new Option("U", true, "Server URL");
        option.setArgName("uri");
        options.addOption(option);

        option = new Option("P", true, "Protocol (default: https)");
        option.setArgName("protocol");
        options.addOption(option);

        option = new Option("h", true, "Hostname (default: "+ InetAddress.getLocalHost().getCanonicalHostName() + ")");
        option.setArgName("hostname");
        options.addOption(option);

        option = new Option("p", true, "Port (default: 8443)");
        option.setArgName("port");
        options.addOption(option);

        option = new Option("t", true, "Subsystem type (deprecated)");
        option.setArgName("type");
        options.addOption(option);

        option = new Option("d", true, "NSS database location (default: ~/.dogtag/nssdb)");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("c", true, "NSS database password (mutually exclusive to -C and -f options)");
        option.setArgName("password");
        options.addOption(option);

        option = new Option("C", true, "NSS database password file (mutually exclusive to -c and -f options)");
        option.setArgName("password file");
        options.addOption(option);

        option = new Option("f", true, "NSS database password configuration (mutually exclusive to -c and -C options)");
        option.setArgName("password config");
        options.addOption(option);

        option = new Option("n", true, "Nickname for client certificate authentication (mutually exclusive to -u option)");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option("u", true, "Username for basic authentication (mutually exclusive to -n option)");
        option.setArgName("username");
        options.addOption(option);

        option = new Option("w", true, "Password for basic authentication (mutually exclusive to -W option)");
        option.setArgName("password");
        options.addOption(option);

        option = new Option("W", true, "Password file for basic authentication (mutually exclusive to -w option)");
        option.setArgName("passwordfile");
        options.addOption(option);

        option = new Option(null, "token", true, "Security token name");
        option.setArgName("token");
        options.addOption(option);

        option = new Option(null, "output", true, "Folder to store HTTP messages");
        option.setArgName("folder");
        options.addOption(option);

        option = new Option(null, "reject-cert-status", true, "Comma-separated list of rejected certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "ignore-cert-status", true, "Comma-separated list of ignored certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "ignore-banner", false, "Ignore access banner");
        options.addOption(option);

        option = new Option(null, "message-format", true, "Message format: xml (default), json");
        option.setArgName("format");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
        options.addOption(null, "version", false, "Show version number.");
    }

    public String loadPassword(String path) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            return br.readLine();
        }
    }

    public Map<String, String> loadPasswordConfig(String filename) throws Exception {

        Map<String, String> passwords = new LinkedHashMap<String, String>();

        List<String> list = Files.readAllLines(Paths.get(filename));
        String[] lines = list.toArray(new String[list.size()]);

        for (int i=0; i<lines.length; i++) {

            String line = lines[i].trim();

            if (line.isEmpty()) { // skip blanks
                continue;
            }

            if (line.startsWith("#")) { // skip comments
                continue;
            }

            int p = line.indexOf("=");
            if (p < 0) {
                throw new Exception("Missing delimiter in " + filename + ":" + (i + 1));
            }

            String token = line.substring(0, p).trim();
            String password = line.substring(p + 1).trim();

            if (token.equals("internal")) {
                passwords.put(token, password);

            } else if (token.startsWith("hardware-")) {
                token = token.substring(9);  // remove hardware- prefix
                passwords.put(token, password);

            } else {
                // skip non-token passwords
            }
        }

        return passwords;
    }

    public String promptForPassword(String prompt) throws IOException {
        char[] password = null;
        Console console = System.console();
        System.out.print(prompt);
        password = console.readPassword();
        return new String(password);
    }

    public String promptForPassword() throws IOException {
        return promptForPassword("Enter Password: ");
    }

    public static CAClient createCAClient(PKIClient client) throws Exception {

        ClientConfig config = client.getConfig();
        CAClient caClient = new CAClient(client);

        while (!caClient.exists()) {
            System.err.println("Error: CA subsystem not available");

            URL serverURI = config.getServerURL();
            String uri = serverURI.getProtocol() + "://" + serverURI.getHost() + ":" + serverURI.getPort();

            System.out.print("CA server URL [" + uri + "]: ");
            System.out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine().trim();
            if (!line.equals("")) {
                uri = line;
            }

            config = new ClientConfig(client.getConfig());
            config.setServerURL(uri);

            client = new PKIClient(config);
            caClient = new CAClient(client);
        }

        return caClient;
    }

    public void parseOptions(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(Level.INFO);
        }

        output = cmd.getOptionValue("output");

        String url = cmd.getOptionValue("U");

        String protocol = cmd.getOptionValue("P", "https");
        String hostname = cmd.getOptionValue("h", InetAddress.getLocalHost().getCanonicalHostName());
        String port = cmd.getOptionValue("p", "8443");
        String subsystem = cmd.getOptionValue("t");

        if (url == null)
            url = protocol + "://" + hostname + ":" + port;

        if (subsystem != null) {
            logger.warn("The -t option has been deprecated. Use pki " + subsystem + " command instead.");
            url = url + "/" + subsystem;
        }

        config.setServerURL(url);

        logger.info("Server URL: " + url);

        String nssDatabase = cmd.getOptionValue("d");
        String nssPassword = cmd.getOptionValue("c");
        String nssPasswordFile = cmd.getOptionValue("C");
        String nssPasswordConfig = cmd.getOptionValue("f");

        String tokenName = cmd.getOptionValue("token");
        String certNickname = cmd.getOptionValue("n");

        String username = cmd.getOptionValue("u");
        String password = cmd.getOptionValue("w");
        String passwordFile = cmd.getOptionValue("W");

        // make sure no conflicting NSS passwords
        int nssPasswordCounter = 0;
        if (nssPassword != null) nssPasswordCounter++;
        if (nssPasswordFile != null) nssPasswordCounter++;
        if (nssPasswordConfig != null) nssPasswordCounter++;

        if (nssPasswordCounter > 1) {
            throw new Exception("The -c, -C, -f options are mutually exclusive.");
        }

        // make sure no conflicting authentication methods
        if (certNickname != null && username != null) {
            throw new Exception("The -n and -u options are mutually exclusive.");
        }

        // make sure no conflicting basic authentication passwords
        if (username != null) {
            if (password != null && passwordFile != null) {
                throw new Exception("The -w and -W options are mutually exclusive.");
            }
        }

        if (nssDatabase != null) {
            // store user-provided NSS database location
            config.setNSSDatabase(new File(nssDatabase).getAbsolutePath());
        } else {
            // store default NSS database location
            config.setNSSDatabase(System.getProperty("user.home") +
                    File.separator + ".dogtag" + File.separator + "nssdb");
        }

        // store token name
        config.setTokenName(tokenName);

        // store certificate nickname
        config.setCertNickname(certNickname);

        if (nssPassword != null) {
            config.setNSSPassword(nssPassword);

        } else if (nssPasswordFile != null) {
            logger.info("Loading NSS password from " + nssPasswordFile);
            nssPassword = loadPassword(nssPasswordFile);
            config.setNSSPassword(nssPassword);

        } else if (nssPasswordConfig != null) {
            logger.info("Loading NSS password configuration from " + nssPasswordConfig);
            Map<String, String> nssPasswords = loadPasswordConfig(nssPasswordConfig);
            config.setNSSPasswords(nssPasswords);
        }

        // store user name
        config.setUsername(username);

        if (passwordFile != null) {
            logger.info("Loading user password from " + passwordFile);
            password = loadPassword(passwordFile);

        } else if (username != null && password == null) {
            // prompt for user password if required for authentication
            password = promptForPassword();
        }

        // store user password
        config.setPassword(password);

        String list = cmd.getOptionValue("reject-cert-status");
        convertCertStatusList(list, rejectedCertStatuses);

        list = cmd.getOptionValue("ignore-cert-status");
        convertCertStatusList(list, ignoredCertStatuses);

        ignoreBanner = cmd.hasOption("ignore-banner");

        this.certDatabase = new File(config.getNSSDatabase());
        logger.info("NSS database: " + this.certDatabase.getAbsolutePath());

        String messageFormat = cmd.getOptionValue("message-format");
        config.setMessageFormat(messageFormat);
        logger.info("Message format: " + messageFormat);
    }

    public ClientConfig getConfig() {
        return config;
    }

    public void convertCertStatusList(String list, Collection<Integer> statuses) throws Exception {

        if (list == null) return;

        Class<SSLCertificateApprovalCallback.ValidityStatus> clazz = SSLCertificateApprovalCallback.ValidityStatus.class;

        for (String status : list.split(",")) {
            try {
                Field field = clazz.getField(status);
                statuses.add(field.getInt(null));

            } catch (NoSuchFieldException e) {
                throw new Exception("Invalid cert status \"" + status + "\".", e);
            }
        }
    }

    public void init() throws Exception {

        if (initialized) {
            return;
        }

        NSSDatabase nssdb = new NSSDatabase(certDatabase);

        if (!nssdb.exists()) {
            // Create a default NSS database without password
            nssdb.create();
        }

        logger.info("Initializing NSS");
        CryptoManager.initialize(certDatabase.getAbsolutePath());

        CryptoManager manager;
        try {
            manager = CryptoManager.getInstance();

        } catch (NotInitializedException e) {
            // The original exception doesn't contain a message.
            throw new Exception("NSS has not been initialized", e);
        }

        // If password is specified, use password to access security token
        if (config.getNSSPassword() != null) {

            String tokenName = config.getTokenName();
            tokenName = tokenName == null ? CryptoUtil.INTERNAL_TOKEN_NAME : tokenName;

            logger.info("Logging into " + tokenName + " token");

            CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
            Password password = new Password(config.getNSSPassword().toCharArray());

            try {
                token.login(password);

            } catch (IncorrectPasswordException e) {
                // The original exception doesn't contain a message.
                throw new Exception("Incorrect password for " + tokenName + " token", e);

            } finally {
                password.clear();
            }

        } else {

            Map<String, String> passwords = config.getNSSPasswords();

            for (String tokenName : passwords.keySet()) {

                logger.info("Logging into " + tokenName + " token");

                CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
                Password password = new Password(passwords.get(tokenName).toCharArray());

                try {
                    token.login(password);

                } catch (IncorrectPasswordException e) {
                    // The original exception doesn't contain a message.
                    throw new Exception("Incorrect password for " + tokenName + " token", e);

                } finally {
                    password.clear();
                }
            }
        }

        String tokenName = config.getTokenName();
        tokenName = tokenName == null ? CryptoUtil.INTERNAL_TOKEN_NAME : tokenName;
        logger.info("Using " + tokenName + " token");

        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        manager.setThreadToken(token);

        // See default SSL configuration in /usr/share/pki/etc/pki.conf.

        String streamVersionMin = System.getenv("SSL_STREAM_VERSION_MIN");
        String streamVersionMax = System.getenv("SSL_STREAM_VERSION_MAX");

        SSLVersionRange streamRange = CryptoUtil.boundSSLStreamVersionRange(
                streamVersionMin == null ? SSLVersion.TLS_1_0 : SSLVersion.valueOf(streamVersionMin),
                streamVersionMax == null ? SSLVersion.TLS_1_2 : SSLVersion.valueOf(streamVersionMax)
        );
        CryptoUtil.setSSLStreamVersionRange(streamRange.getMinVersion(), streamRange.getMaxVersion());

        String datagramVersionMin = System.getenv("SSL_DATAGRAM_VERSION_MIN");
        String datagramVersionMax = System.getenv("SSL_DATAGRAM_VERSION_MAX");

        SSLVersionRange datagramRange = CryptoUtil.boundSSLDatagramVersionRange(
                datagramVersionMin == null ? SSLVersion.TLS_1_1 : SSLVersion.valueOf(datagramVersionMin),
                datagramVersionMax == null ? SSLVersion.TLS_1_2 : SSLVersion.valueOf(datagramVersionMax)
        );
        CryptoUtil.setSSLDatagramVersionRange(datagramRange.getMinVersion(), datagramRange.getMaxVersion());

        String defaultCiphers = System.getenv("SSL_DEFAULT_CIPHERS");
        if (defaultCiphers == null || Boolean.parseBoolean(defaultCiphers)) {
            CryptoUtil.setDefaultSSLCiphers();
        } else {
            CryptoUtil.unsetSSLCiphers();
        }

        String ciphers = System.getenv("SSL_CIPHERS");
        CryptoUtil.setSSLCiphers(ciphers);

        initialized = true;
    }

    public PKIClient getClient() throws Exception {

        if (client != null) return client;

        logger.info("Initializing PKIClient");

        client = new PKIClient(config, null);
        client.setRejectedCertStatuses(rejectedCertStatuses);
        client.setIgnoredCertStatuses(ignoredCertStatuses);

        if (output != null) {
            File file = new File(output);
            file.mkdirs();

            PKIConnection connection = client.getConnection();
            connection.setOutput(file);
        }

        if (!ignoreBanner) {

            InfoClient infoClient = new InfoClient(client);
            Info info = infoClient.getInfo();
            String banner = info.getBanner();

            if (banner != null) {

                System.out.println(banner);
                System.out.println();
                System.out.print("Do you want to proceed (y/N)? ");
                System.out.flush();

                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                String line = reader.readLine().trim();

                if (!line.equalsIgnoreCase("Y")) {
                    throw new CLIException();
                }
            }
        }

        return client;
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args, true);

        String[] cmdArgs = cmd.getArgs();

        if (cmd.hasOption("version")) {
            printVersion();
            return;
        }

        if (cmdArgs.length == 0 || cmd.hasOption("help")) {
            // Print 'pki' usage
            printHelp();
            return;
        }

        parseOptions(cmd);

        if (logger.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder("Command:");
            for (String arg : cmdArgs) {
                if (arg.contains(" ")) arg = "\"" + arg + "\"";
                sb.append(" ");
                sb.append(arg);
            }
            logger.info(sb.toString());
        }

        super.execute(cmdArgs);
    }

    public static void printMessage(String message) {
        System.out.println(StringUtils.repeat("-", message.length()));
        System.out.println(message);
        System.out.println(StringUtils.repeat("-", message.length()));
    }

    public static void handleException(Throwable t) {

        if (logger.isInfoEnabled()) {
            logger.error(t.getMessage(), t);

        } else if (t.getClass() == Exception.class) {
            // display a generic error
            logger.error(t.getMessage());

        } else if (t instanceof UnrecognizedOptionException) {
            // display only the error message
            logger.error(t.getMessage());

        } else if (t instanceof ProcessingException) {
            // display the cause of the exception
            t = t.getCause();
            logger.error(t.getClass().getSimpleName() + ": " + t.getMessage());

        } else {
            // display the actual Exception
            logger.error(t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    public static void main(String args[]) {
        try {
            MainCLI cli = new MainCLI();
            cli.execute(args);

        } catch (CLIException e) {
            String message = e.getMessage();
            if (message != null) {
                logger.error(message);
            }
            System.exit(e.getCode());

        } catch (Throwable t) {
            handleException(t);
            System.exit(-1);
        }
    }
}
