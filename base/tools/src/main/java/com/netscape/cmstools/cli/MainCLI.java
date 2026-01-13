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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.core.Response;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.MissingArgumentException;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CLIModule;
import org.dogtagpki.common.Info;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.NullPasswordCallback;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.base.ClientConnectionException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKICertificateApprovalCallback;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.acme.ACMECLI;
import com.netscape.cmstools.ca.CACLI;
import com.netscape.cmstools.client.ClientCLI;
import com.netscape.cmstools.kra.KRACLI;
import com.netscape.cmstools.nss.NSSCLI;
import com.netscape.cmstools.ocsp.OCSPCLI;
import com.netscape.cmstools.pkcs11.PKCS11CLI;
import com.netscape.cmstools.pkcs12.PKCS12CLI;
import com.netscape.cmstools.pkcs7.PKCS7CLI;
import com.netscape.cmstools.system.SecurityDomainCLI;
import com.netscape.cmstools.tks.TKSCLI;
import com.netscape.cmstools.tps.TPSCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.PlainPasswordFile;

/**
 * @author Endi S. Dewata
 */
public class MainCLI extends CLI {

    public ClientConfig config = new ClientConfig();

    NSSDatabase nssdb;
    String apiVersion;

    Collection<Integer> rejectedCertStatuses = new HashSet<>();
    Collection<Integer> ignoredCertStatuses = new HashSet<>();

    boolean ignoreBanner;
    String httpOutput;

    boolean initialized;
    boolean optionsParsed;

    public PKIClient client;

    public MainCLI() throws Exception {
        super("pki", "PKI command-line interface");

        addModule(new HelpCLI(this));

        addModule(new PasswordCLI(this));
        addModule(new ClientCLI(this));
        addModule(new NSSCLI(this));

        addModule(new InfoCLI(this));
        addModule(new SecurityDomainCLI(this));

        addModule(new ACMECLI(this));
        addModule(new CACLI(this));
        addModule(new KRACLI(this));
        addModule(new OCSPCLI(this));
        addModule(new TKSCLI(this));
        addModule(new TPSCLI(this));

        addModule(new PKCS7CLI(this));
        addModule(new PKCS11CLI(this));
        addModule(new PKCS12CLI(this));
    }

    @Override
    public ClientConfig getConfig() {
        return config;
    }

    public NSSDatabase getNSSDatabase() {
        return nssdb;
    }

    @Override
    public String getFullModuleName(String moduleName) {
        return moduleName;
    }

    @Override
    public String getManPage() {
        return "pki";
    }

    public String getAPIVersion() {
        return apiVersion;
    }

    @Override
    public void printVersion() {
        Package pkg = MainCLI.class.getPackage();
        System.out.println("PKI Command-Line Interface " + pkg.getImplementationVersion());
    }

    @Override
    public void printHelp() throws Exception {

        formatter.printHelp(name + " [OPTIONS..] <command> [ARGS..]", options);
        System.out.println();

        super.printHelp();
    }

    @Override
    public void createOptions() throws Exception {

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

        option = new Option("t", true, "DEPRECATED: Subsystem type");
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

        option = new Option(null, "api", true, "API version: v1, v2");
        option.setArgName("version");
        options.addOption(option);

        option = new Option(null, "http-output", true, "Folder to store HTTP messages");
        option.setArgName("folder");
        options.addOption(option);

        option = new Option(null, "output", true, "DEPRECATED: Folder to store HTTP messages");
        option.setArgName("folder");
        options.addOption(option);

        option = new Option(null, "skip-revocation-check", false, "Do not perform revocation check");
        options.addOption(option);

        option = new Option(null, "reject-cert-status", true, "Comma-separated list of rejected certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "ignore-cert-status", true, "Comma-separated list of ignored certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "ignore-banner", false, "Ignore access banner");
        options.addOption(option);

        option = new Option(null, "message-format", true, "Message format: json (default), xml");
        option.setArgName("format");
        options.addOption(option);

        options.addOption("e", "exit-on-error", false, "Exit on error.");

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

        Map<String, String> passwords = new LinkedHashMap<>();

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

            String name = line.substring(0, p).trim();
            String password = line.substring(p + 1).trim();

            if (name.equals("internal")) {
                logger.debug("- internal: ********");
                passwords.put(name, password);

            } else if (name.startsWith("hardware-")) {
                name = name.substring(9);  // remove hardware- prefix
                logger.debug("- " + name + ": ********");
                passwords.put(name, password);

            } else {
                logger.debug("- " + name + ": ******** (not token)");
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

    public CAClient createCAClient(PKIClient client) throws Exception {

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

            SSLCertificateApprovalCallback callback = createCertApprovalCallback();
            client = new PKIClient(config, callback);
            caClient = new CAClient(client);
        }

        return caClient;
    }

    @Override
    public CommandLine parseOptions(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args, true);

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(LogLevel.INFO);
        }

        httpOutput = cmd.getOptionValue("output");
        if (httpOutput == null) {
            httpOutput = cmd.getOptionValue("http-output");
        } else {
            logger.warn("The --output option has been deprecated. Use --http-output instead.");
        }

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

        PlainPasswordFile passwordStore = new PlainPasswordFile();

        if (nssPassword != null) {
            String token = tokenName;
            if (token == null) token = "internal";
            passwordStore.putPassword(token, nssPassword);

        } else if (nssPasswordConfig != null) {
            passwordStore.init(nssPasswordConfig);
        }

        logger.info("NSS database: " + config.getNSSDatabase());
        nssdb = new NSSDatabase(config.getNSSDatabase());
        nssdb.setPasswordStore(passwordStore);

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

        apiVersion = cmd.getOptionValue("api", "rest");

        String list = cmd.getOptionValue("reject-cert-status");
        convertCertStatusList(list, rejectedCertStatuses);

        list = cmd.getOptionValue("ignore-cert-status");
        convertCertStatusList(list, ignoredCertStatuses);

        ignoreBanner = cmd.hasOption("ignore-banner");

        String messageFormat = cmd.getOptionValue("message-format");
        config.setMessageFormat(messageFormat);
        logger.debug("Message format: " + messageFormat);

        config.setCertRevocationVerify(!cmd.hasOption("skip-revocation-check"));
        optionsParsed = true;

        exitOnError = cmd.hasOption("e");

        return cmd;
    }

    public static void convertCertStatusList(String list, Collection<Integer> statuses) throws Exception {

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

        if (!optionsParsed) {
            throw new Exception("Unable to call MainCLI.init() without first calling MainCLI.parseOptions()");
        }

        if (!nssdb.exists()) {
            // Create the NSS DB with the specified password, if one has been
            // specified.
            if (config.getNSSPassword() != null) {
                nssdb.create(config.getNSSPassword());
            } else {
                nssdb.create();
            }
        }

        logger.debug("Initializing NSS");
        CryptoManager.initialize(nssdb.getPath().toString());

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

            logger.debug("Logging into " + tokenName + " token");

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

                logger.debug("Logging into " + tokenName + " token");

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
            manager.setPasswordCallback(new NullPasswordCallback());
            Enumeration<CryptoToken> externalTokens = CryptoUtil.getExternalTokens();
            while (externalTokens!=null && externalTokens.hasMoreElements()) {
                CryptoToken extToken = externalTokens.nextElement();
                if (!extToken.isLoggedIn()) {
                    logger.info("Password for token '{}' has not been provided, it will be skipped.", extToken.getName());
                }
            }
        }

        String tokenName = config.getTokenName();
        tokenName = tokenName == null ? CryptoUtil.INTERNAL_TOKEN_NAME : tokenName;
        logger.debug("Using " + tokenName + " token");

        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        manager.setThreadToken(token);

        SSLSocket.enablePostHandshakeAuthDefault(true);

        initialized = true;
    }

    public SSLCertificateApprovalCallback createCertApprovalCallback() {

        PKICertificateApprovalCallback callback = new PKICertificateApprovalCallback();
        callback.reject(rejectedCertStatuses);
        callback.ignore(ignoredCertStatuses);

        return callback;
    }

    public static PKIClient createPKIClient(
            ClientConfig config,
            SSLCertificateApprovalCallback callback,
            String apiVersion,
            boolean ignoreBanner,
            String httpOutput) throws Exception {

        PKIClient newClient = new PKIClient(config, apiVersion, callback);

        if (httpOutput != null) {
            File file = new File(httpOutput);
            file.mkdirs();
            newClient.setOutput(file);
        }

        try {
            Info info = newClient.getInfo();

            logger.info("Server Name: " + info.getName());
            logger.info("Server Version: " + info.getVersion());

            String banner = info.getBanner();

            if (banner != null && !ignoreBanner) {

                System.err.print("""
                    %s

                    Do you want to proceed (y/N)?\s""".formatted(banner)
                );
                System.err.flush();

                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                String line = reader.readLine().trim();

                if (!line.equalsIgnoreCase("Y")) {
                    throw new CLIException();
                }
            }

        } catch (PKIException e) {
            if (e.getCode() != Response.Status.NOT_FOUND.getStatusCode()) {
                throw e;
            }
            logger.warn("Unable to get server info: " + e.getMessage());
        }

        return newClient;
    }

    public PKIClient getPKIClient() throws Exception {

        if (client != null) return client;

        logger.info("Connecting to " + config.getServerURL());

        SSLCertificateApprovalCallback callback = createCertApprovalCallback();
        client = createPKIClient(config, callback, apiVersion, ignoreBanner, httpOutput);

        return client;
    }

    @Override
    public void executeCommand(String[] args) throws Exception {

        String command = args[0];

        CLIModule module = findModule(command);
        if (module == null) {
            throw new Exception("Invalid module \"" + command + "\".");
        }

        CLI cli = module.getCLI();

        String[] cmdArgs = new String[args.length-1];
        System.arraycopy(args, 1, cmdArgs, 0, args.length-1);

        cli.execute(cmdArgs);
    }

    @Override
    public void execute(String[] args) throws Exception {

        createOptions();

        CommandLine cmd = parseOptions(args);

        String[] cmdArgs = cmd.getArgs();

        if (cmd.hasOption("version")) {
            printVersion();
            return;
        }

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmdArgs.length == 0) {
            // no args -> enter shell mode (with prompts)
            try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in))) {
                executeCommands(in, true);
            }
            return;

        } else if (cmdArgs.length == 1 && cmdArgs[0].equals("-")) {
            // "-" arg -> enter batch mode (without prompts)
            try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in))) {
                executeCommands(in, false);
            }
            return;
        }

        // run a single command

        if (logger.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder("Command:");
            for (String arg : cmdArgs) {
                if (arg.contains(" ")) arg = "\"" + arg + "\"";
                sb.append(" ");
                sb.append(arg);
            }
            logger.debug(sb.toString());
        }

        executeCommand(cmdArgs);
    }

    public static void printMessage(String message) {
        System.out.println(StringUtils.repeat("-", message.length()));
        System.out.println(message);
        System.out.println(StringUtils.repeat("-", message.length()));
    }

    @Override
    public void handleException(Throwable t) {

        if (logger.isInfoEnabled()) {
            t.printStackTrace(System.err);

        } else if (t.getClass() == Exception.class) {
            // display a generic error
            System.err.println("ERROR: " + t.getMessage());

        } else if (t instanceof UnrecognizedOptionException || t instanceof MissingArgumentException) {
            // display only the error message
            System.err.println(t.getMessage());

        } else if (t instanceof ProcessingException || t instanceof ClientConnectionException) {
            // display the cause of the exception (if available)
            Throwable e = t.getCause();
            if (e == null) e = t;
            System.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());

        } else if (t instanceof PKIException) {
            System.err.println(t.getClass().getSimpleName() + ": " + t.getMessage());

        } else {
            t.printStackTrace(System.err);
        }
    }

    public static void main(String args[]) throws Exception {
        MainCLI cli = new MainCLI();
        try {
            cli.execute(args);

        } catch (CLIException e) {
            String message = e.getMessage();
            if (message != null) {
                System.err.println("ERROR: " + message);
            }
            System.exit(e.getCode());

        } catch (Throwable t) {
            cli.handleException(t);
            System.exit(-1);
        }
    }
}
