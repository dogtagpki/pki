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
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

import javax.ws.rs.ProcessingException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.common.Info;
import org.dogtagpki.common.InfoClient;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.PKIConnection;
import com.netscape.cmstools.ca.CACLI;
import com.netscape.cmstools.ca.CACertCLI;
import com.netscape.cmstools.client.ClientCLI;
import com.netscape.cmstools.group.GroupCLI;
import com.netscape.cmstools.key.KeyCLI;
import com.netscape.cmstools.kra.KRACLI;
import com.netscape.cmstools.ocsp.OCSPCLI;
import com.netscape.cmstools.pkcs12.PKCS12CLI;
import com.netscape.cmstools.pkcs7.PKCS7CLI;
import com.netscape.cmstools.system.SecurityDomainCLI;
import com.netscape.cmstools.tks.TKSCLI;
import com.netscape.cmstools.tps.TPSCLI;
import com.netscape.cmstools.user.UserCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.crypto.CryptoUtil.SSLVersion;

/**
 * @author Endi S. Dewata
 */
public class MainCLI extends CLI {

    /**
     * These commands should not be executed after CryptoManager.initialize()
     * since they may modify the NSS database or execute external commands
     * using the same NSS database.
     */
    public final static Collection<String> RESTRICTED_COMMANDS = Arrays.asList(
            "client-init",
            "client-cert-import",
            "client-cert-mod",
            "client-cert-request",
            "client-cert-show"
    );

    public ClientConfig config = new ClientConfig();

    public Collection<Integer> rejectedCertStatuses = new HashSet<Integer>();
    public Collection<Integer> ignoredCertStatuses = new HashSet<Integer>();

    public boolean ignoreBanner;
    public File certDatabase;

    String output;

    public MainCLI() throws Exception {
        super("pki", "PKI command-line interface");

        addModule(new HelpCLI(this));

        addModule(new ClientCLI(this));

        addModule(new ProxyCLI(new CACertCLI(this), "ca"));
        addModule(new ProxyCLI(new GroupCLI(this), "ca"));
        addModule(new ProxyCLI(new KeyCLI(this), "kra"));
        addModule(new ProxyCLI(new SecurityDomainCLI(this), "ca"));
        addModule(new ProxyCLI(new UserCLI(this), "ca"));

        addModule(new CACLI(this));
        addModule(new KRACLI(this));
        addModule(new OCSPCLI(this));
        addModule(new TKSCLI(this));
        addModule(new TPSCLI(this));

        addModule(new PKCS7CLI(this));
        addModule(new PKCS12CLI(this));

        createOptions();
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

        int leftPadding = 1;
        int rightPadding = 25;

        System.out.println("Commands:");

        for (CLI module : modules.values()) {
            String label = module.getFullName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1)
                padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(module.getDescription());
        }
    }

    public void createOptions() throws UnknownHostException {

        Option option = new Option("U", true, "Server URI");
        option.setArgName("uri");
        options.addOption(option);

        option = new Option("P", true, "Protocol (default: http)");
        option.setArgName("protocol");
        options.addOption(option);

        option = new Option("h", true, "Hostname (default: "+ InetAddress.getLocalHost().getCanonicalHostName() + ")");
        option.setArgName("hostname");
        options.addOption(option);

        option = new Option("p", true, "Port (default: 8080)");
        option.setArgName("port");
        options.addOption(option);

        option = new Option("t", true, "Subsystem type (deprecated)");
        option.setArgName("type");
        options.addOption(option);

        option = new Option("d", true, "Client security database location (default: ~/.dogtag/nssdb)");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("c", true, "Client security database password (mutually exclusive to the '-C' option; requires the '-n' client authentication option)");
        option.setArgName("certpassword");
        options.addOption(option);

        option = new Option("C", true, "Client-side password file (mutually exclusive to the '-c' option; requires the '-n' client authentication option)");
        option.setArgName("certpasswordfile");
        options.addOption(option);

        option = new Option("n", true, "Client certificate nickname (signifies client authentication which is mutually exclusive to '-u' basic authentication option)");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option("u", true, "Username (signifies basic authentication which is mutually exclusive to '-n' client authentication option)");
        option.setArgName("username");
        options.addOption(option);

        option = new Option("w", true, "Password (mutually exclusive to the '-W' option; requires the '-u' basic authentication option)");
        option.setArgName("password");
        options.addOption(option);

        option = new Option("W", true, "Client-side password file (mutually exclusive to the '-w' option; requires the '-u' basic authentication option)");
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
        options.addOption(null, "help", false, "Show help message.");
        options.addOption(null, "version", false, "Show version number.");
    }

    public String[] loadPassword(String pwfile) throws Exception {

        String[] tokenPassword = { null, null };
        String delimiter = "=";

        try (BufferedReader br = new BufferedReader(new FileReader(pwfile))) {

            String line = br.readLine();

            if (line == null) {
                throw new Exception("File '" + pwfile + "' is empty!");
            }

            if (line.isEmpty()) {
                throw new Exception("File '" + pwfile + "' does not define a token or a password!");
            }

            if (line.contains(delimiter)) {
                // Process 'token=password' format:
                //
                //     Token:     tokenPassword[0]
                //     Password:  tokenPassword[1]
                //
                tokenPassword = line.split(delimiter, 2);

                // Always trim leading/trailing whitespace from 'token'
                tokenPassword[0] = tokenPassword[0].trim();

                // Check for undefined 'token'
                if (tokenPassword[0].isEmpty()) {
                    // Set default 'token'
                    tokenPassword[0] = CryptoUtil.INTERNAL_TOKEN_NAME;
                }

                // Check for undefined 'password'
                if (tokenPassword[1].isEmpty()) {
                    throw new Exception("File '" + pwfile + "' does not define a password!");
                }

            } else {
                // Set default 'token'
                tokenPassword[0] = CryptoUtil.INTERNAL_TOKEN_NAME;

                // Set simple 'password' (do not trim leading/trailing whitespace)
                tokenPassword[1] = line;
            }
        }

        return tokenPassword;
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

            URI serverURI = config.getServerURI();
            String uri = serverURI.getScheme() + "://" + serverURI.getHost() + ":" + serverURI.getPort();

            System.out.print("CA server URI [" + uri + "]: ");
            System.out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine().trim();
            if (!line.equals("")) {
                uri = line;
            }

            config = new ClientConfig(client.getConfig());
            config.setServerURI(uri);

            client = new PKIClient(config);
            caClient = new CAClient(client);
        }

        return caClient;
    }

    public void parseOptions(CommandLine cmd) throws Exception {

        verbose = cmd.hasOption("v");
        output = cmd.getOptionValue("output");

        String uri = cmd.getOptionValue("U");

        String protocol = cmd.getOptionValue("P", "http");
        String hostname = cmd.getOptionValue("h", InetAddress.getLocalHost().getCanonicalHostName());
        String port = cmd.getOptionValue("p", "8080");
        String subsystem = cmd.getOptionValue("t");

        if (uri == null)
            uri = protocol + "://" + hostname + ":" + port;

        if (subsystem != null) {
            System.err.println("WARNING: The -t option has been deprecated. Use pki " + subsystem + " command instead.");
            uri = uri + "/" + subsystem;
        }

        config.setServerURI(uri);

        if (verbose) System.out.println("Server URI: "+uri);

        String certDatabase = cmd.getOptionValue("d");
        String certNickname = cmd.getOptionValue("n");
        String certPassword = cmd.getOptionValue("c");
        String certPasswordFile = cmd.getOptionValue("C");
        String tokenName = cmd.getOptionValue("token");

        String username = cmd.getOptionValue("u");
        String password = cmd.getOptionValue("w");
        String passwordFile = cmd.getOptionValue("W");
        String[] tokenPasswordPair = { null, null };

        // check authentication parameters
        if (certNickname != null && username != null) {
            throw new Exception("The '-n' and '-u' options are mutually exclusive.");

        } else if (certNickname != null) { // client certificate authentication

            if (certPasswordFile != null && certPassword != null) {
                throw new Exception("The '-C' and '-c' options are mutually exclusive.");
            }

        } else if (username != null) { // basic authentication

            if (passwordFile != null && password != null) {
                throw new Exception("The '-W' and '-w' options are mutually exclusive.");
            }
        }

        if (certDatabase != null) {
            // store user-provided security database location
            config.setCertDatabase(new File(certDatabase).getAbsolutePath());
        } else {
            // store default security database location
            config.setCertDatabase(System.getProperty("user.home") +
                    File.separator + ".dogtag" + File.separator + "nssdb");
        }

        // store token name
        config.setTokenName(tokenName);

        // store certificate nickname
        config.setCertNickname(certNickname);

        if (certPasswordFile != null) {
            if (verbose) System.out.println("Loading NSS password from " + certPasswordFile);
            tokenPasswordPair = loadPassword(certPasswordFile);
            // XXX TBD set client security database token

            certPassword = tokenPasswordPair[1];
        }

        // store security database password
        config.setCertPassword(certPassword);

        // store user name
        config.setUsername(username);

        if (passwordFile != null) {
            if (verbose) System.out.println("Loading user password from " + passwordFile);
            tokenPasswordPair = loadPassword(passwordFile);
            // XXX TBD set user token

            password = tokenPasswordPair[1];

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

        this.certDatabase = new File(config.getCertDatabase());
        if (verbose) System.out.println("Client security database: "+this.certDatabase.getAbsolutePath());

        String messageFormat = cmd.getOptionValue("message-format");
        config.setMessageFormat(messageFormat);
        if (verbose) System.out.println("Message format: " + messageFormat);
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

        // Create security database if it doesn't exist
        if (!certDatabase.exists()) {

            if (verbose) System.out.println("Creating security database");

            certDatabase.mkdirs();

            String[] commands = {
                    "/usr/bin/certutil", "-N",
                    "-d", certDatabase.getAbsolutePath(),
                    "--empty-password"
            };

            try {
                runExternal(commands);
            } catch (Exception e) {
                throw new Exception("Unable to create security database", e);
            }
        }

        // Main program should initialize security database
        if (verbose) System.out.println("Initializing security database");
        CryptoManager.initialize(certDatabase.getAbsolutePath());

        // If password is specified, use password to access security token
        if (config.getCertPassword() != null) {

            try {
                CryptoManager manager = CryptoManager.getInstance();

                String tokenName = config.getTokenName();
                if (verbose) System.out.println("Getting " + (tokenName == null ? "internal" : tokenName) + " token");

                CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
                manager.setThreadToken(token);

                if (verbose) System.out.println("Logging into " + token.getName());

                Password password = new Password(config.getCertPassword().toCharArray());
                token.login(password);

            } catch (NotInitializedException e) {
                // The original exception doesn't contain a message.
                throw new Exception("Client security database does not exist.", e);

            } catch (IncorrectPasswordException e) {
                // The original exception doesn't contain a message.
                throw new Exception("Incorrect client security database password.", e);
            }

        }

        // See default SSL configuration in /usr/share/pki/etc/pki.conf.

        String streamVersionMin = System.getenv("SSL_STREAM_VERSION_MIN");
        String streamVersionMax = System.getenv("SSL_STREAM_VERSION_MAX");

        CryptoUtil.setSSLStreamVersionRange(
                streamVersionMin == null ? SSLVersion.TLS_1_0 : SSLVersion.valueOf(streamVersionMin),
                streamVersionMax == null ? SSLVersion.TLS_1_2 : SSLVersion.valueOf(streamVersionMax)
        );

        String datagramVersionMin = System.getenv("SSL_DATAGRAM_VERSION_MIN");
        String datagramVersionMax = System.getenv("SSL_DATAGRAM_VERSION_MAX");

        CryptoUtil.setSSLDatagramVersionRange(
                datagramVersionMin == null ? SSLVersion.TLS_1_1 : SSLVersion.valueOf(datagramVersionMin),
                datagramVersionMax == null ? SSLVersion.TLS_1_2 : SSLVersion.valueOf(datagramVersionMax)
        );

        String defaultCiphers = System.getenv("SSL_DEFAULT_CIPHERS");
        if (defaultCiphers == null || Boolean.parseBoolean(defaultCiphers)) {
            CryptoUtil.setDefaultSSLCiphers();
        } else {
            CryptoUtil.unsetSSLCiphers();
        }

        String ciphers = System.getenv("SSL_CIPHERS");
        CryptoUtil.setSSLCiphers(ciphers);
    }

    public PKIClient getClient() throws Exception {

        if (client != null) return client;

        if (verbose) {
            System.out.println("Initializing PKIClient");
        }

        client = new PKIClient(config, null);
        client.setVerbose(verbose);

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

        if (verbose) {
            System.out.print("Command:");
            for (String arg : cmdArgs) {
                if (arg.contains(" ")) arg = "\""+arg+"\"";
                System.out.print(" "+arg);
            }
            System.out.println();
        }

        // Do not call CryptoManager.initialize() on some commands
        // because otherwise the database will be locked.
        String command = cmdArgs[0];
        if (!RESTRICTED_COMMANDS.contains(command)) {
            init();
        }

        super.execute(cmdArgs);
    }

    public static void printMessage(String message) {
        System.out.println(StringUtils.repeat("-", message.length()));
        System.out.println(message);
        System.out.println(StringUtils.repeat("-", message.length()));
    }

    public static void handleException(Throwable t) {

        if (verbose) {
            t.printStackTrace(System.err);

        } else if (t.getClass() == Exception.class) {
            // display a generic error
            System.err.println("Error: " + t.getMessage());

        } else if (t.getClass() == UnrecognizedOptionException.class) {
            // display only the error message
            System.err.println(t.getMessage());

        } else if (t instanceof ProcessingException) {
            // display the cause of the exception
            t = t.getCause();
            System.err.println(t.getClass().getSimpleName() + ": " + t.getMessage());

        } else {
            // display the actual Exception
            System.err.println(t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    public static void main(String args[]) {
        try {
            MainCLI cli = new MainCLI();
            cli.execute(args);

        } catch (CLIException e) {
            String message = e.getMessage();
            if (message != null) {
                System.err.println(message);
            }
            System.exit(e.getCode());

        } catch (Throwable t) {
            handleException(t);
            System.exit(-1);
        }
    }
}
