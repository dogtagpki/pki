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
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashSet;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.PKIConnection;
import com.netscape.cmstools.cert.CertCLI;
import com.netscape.cmstools.client.ClientCLI;
import com.netscape.cmstools.group.GroupCLI;
import com.netscape.cmstools.key.KeyCLI;
import com.netscape.cmstools.system.SecurityDomainCLI;
import com.netscape.cmstools.user.UserCLI;

/**
 * @author Endi S. Dewata
 */
public class MainCLI extends CLI {

    public ClientConfig config = new ClientConfig();

    public Collection<Integer> rejectedCertStatuses = new HashSet<Integer>();
    public Collection<Integer> ignoredCertStatuses = new HashSet<Integer>();

    public File certDatabase;

    String output;

    public MainCLI() throws Exception {
        super("pki", "PKI command-line interface");

        addModule(new HelpCLI(this));

        addModule(new ClientCLI(this));

        addModule(new ProxyCLI(new CertCLI(this), "ca"));
        addModule(new ProxyCLI(new GroupCLI(this), "ca"));
        addModule(new ProxyCLI(new KeyCLI(this), "kra"));
        addModule(new ProxyCLI(new SecurityDomainCLI(this), "ca"));
        addModule(new ProxyCLI(new UserCLI(this), "ca"));

        addModule(new CACLI(this));
        addModule(new KRACLI(this));
        addModule(new OCSPCLI(this));
        addModule(new TKSCLI(this));
        addModule(new TPSCLI(this));

        createOptions();
    }

    public String getFullModuleName(String moduleName) {
        return moduleName;
    }

    public void printVersion() {
        Package pkg = MainCLI.class.getPackage();
        System.out.println("PKI Command-Line Interface "+pkg.getImplementationVersion());
    }

    public void printHelp() {

        formatter.printHelp(name+" [OPTIONS..] <command> [ARGS..]", options);
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

        option = new Option("t", true, "Subsystem type");
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

        option = new Option(null, "output", true, "Folder to store HTTP messages");
        option.setArgName("folder");
        options.addOption(option);

        option = new Option(null, "reject-cert-status", true, "Comma-separated list of rejected certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "ignore-cert-status", true, "Comma-separated list of ignored certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "message-format", true, "Message format: xml (default), json");
        option.setArgName("format");
        options.addOption(option);

        options.addOption("v", false, "Verbose");
        options.addOption(null, "help", false, "Help");
        options.addOption(null, "version", false, "Version");
    }

    public String[] readPlaintextPasswordFromFile(String pwfile) throws IOException {
        String[] tokenPassword = { null, null };
        BufferedReader br = null;
        String delimiter = "=";

        try {
            br = new BufferedReader(new FileReader(pwfile));

            String line = br.readLine();
            if (line != null) {
                if (line.isEmpty()) {
                    System.err.println("Error:  File '" + pwfile + "' does not define a token or a password!");
                    System.exit(-1);
                } else if (line.contains(delimiter)) {
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
                        tokenPassword[0] = "internal";
                    }

                    // Check for undefined 'password'
                    if (tokenPassword[1].isEmpty()) {
                        System.err.println("Error:  File '" + pwfile + "' does not define a password!");
                        System.exit(-1);
                    }
                } else {
                    // Set default 'token'
                    tokenPassword[0] = "internal";

                    // Set simple 'password' (do not trim leading/trailing whitespace)
                    tokenPassword[1] = line;
                }
            } else {
                // Case of an empty password file
                System.err.println("Error:  File '" + pwfile + "' is empty!");
                System.exit(-1);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(-1);
        } finally {
            if (br != null) {
                br.close();
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

        if (subsystem != null)
            uri = uri + "/" + subsystem;

        config.setServerURI(uri);

        if (verbose) System.out.println("Server URI: "+uri);

        String certDatabase = cmd.getOptionValue("d");
        String certNickname = cmd.getOptionValue("n");
        String certPassword = cmd.getOptionValue("c");
        String certPasswordFile = cmd.getOptionValue("C");
        String username = cmd.getOptionValue("u");
        String password = cmd.getOptionValue("w");
        String passwordFile = cmd.getOptionValue("W");
        String[] tokenPasswordPair = { null, null };

        // check authentication parameters
        if (certNickname != null && username != null) {
            System.err.println("Error: The '-n' and '-u' options are mutually exclusive.");
            System.exit(-1);

        } else if (certNickname != null) { // client certificate authentication

            if (certPasswordFile != null && certPassword != null) {
                System.err.println("Error: The '-C' and '-c' options are mutually exclusive.");
                System.exit(-1);

            } else if (certPasswordFile == null && certPassword == null) {
                System.err.println("Error: Missing security database password.");
                System.exit(-1);
            }

        } else if (username != null) { // basic authentication

            if (passwordFile != null && password != null) {
                System.err.println("Error: The '-W' and '-w' options are mutually exclusive.");
                System.exit(-1);

            } else if (passwordFile == null && password == null) {
                System.err.println("Error: Missing user password.");
                System.exit(-1);
            }
        }

        // store security database path
        if (certDatabase != null)
            config.setCertDatabase(new File(certDatabase).getAbsolutePath());

        // store certificate nickname
        config.setCertNickname(certNickname);

        if (certPasswordFile != null) {
            // read client security database password from specified file
            tokenPasswordPair = readPlaintextPasswordFromFile(certPasswordFile);
            // XXX TBD set client security database token

            certPassword = tokenPasswordPair[1];

        } else if (certNickname != null && certPassword == null) {
            // prompt for security database password if required for authentication
            //
            // NOTE:  This overrides the password callback provided
            //        by JSS for NSS security database authentication.
            //
            try {
                certPassword = promptForPassword("Enter Client Security Database Password: ");

            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                System.exit(-1);
            }
        }

        // store security database password
        config.setCertPassword(certPassword);

        // store user name
        config.setUsername(username);

        if (passwordFile != null) {
            // read user password from specified file
            tokenPasswordPair = readPlaintextPasswordFromFile(passwordFile);
            // XXX TBD set user token

            password = tokenPasswordPair[1];

        } else if (username != null && password == null) {
            // prompt for user password if required for authentication
            try {
                password = promptForPassword();

            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                System.exit(-1);
            }
        }

        // store user password
        config.setPassword(password);

        String list = cmd.getOptionValue("reject-cert-status");
        convertCertStatusList(list, rejectedCertStatuses);

        list = cmd.getOptionValue("ignore-cert-status");
        convertCertStatusList(list, ignoredCertStatuses);

        if (config.getCertDatabase() == null) {
            // Use default client security database
            this.certDatabase = new File(
                    System.getProperty("user.home") + File.separator +
                    ".dogtag" + File.separator + "nssdb");

        } else {
            // Use existing client security database
            this.certDatabase = new File(config.getCertDatabase());
        }

        if (verbose) System.out.println("Client security database: "+this.certDatabase.getAbsolutePath());

        String messageFormat = cmd.getOptionValue("message-format");
        config.setMessageFormat(messageFormat);
        if (verbose) System.out.println("Message format: " + messageFormat);
    }

    public void convertCertStatusList(String list, Collection<Integer> statuses) throws Exception {

        if (list == null) return;

        Class<SSLCertificateApprovalCallback.ValidityStatus> clazz = SSLCertificateApprovalCallback.ValidityStatus.class;

        for (String status : list.split(",")) {
            try {
                Field field = clazz.getField(status);
                statuses.add(field.getInt(null));

            } catch (NoSuchFieldException e) {
                throw new Error("Invalid cert status \"" + status + "\".", e);
            }
        }
    }

    public void init() throws Exception {

        // Main program should initialize client security database
        if (certDatabase.exists()) {
            CryptoManager.initialize(certDatabase.getAbsolutePath());
        }

        // If password is specified, use password to access client security database
        if (config.getCertPassword() != null) {
            try {
                CryptoManager manager = CryptoManager.getInstance();
                CryptoToken token = manager.getInternalKeyStorageToken();
                Password password = new Password(config.getCertPassword().toCharArray());
                token.login(password);

            } catch (NotInitializedException e) {
                // The original exception doesn't contain a message.
                throw new Error("Client security database does not exist.");

            } catch (IncorrectPasswordException e) {
                // The original exception doesn't contain a message.
                throw new IncorrectPasswordException("Incorrect client security database password.");
            }

        }

        client = new PKIClient(config, null);
        client.setVerbose(verbose);

        PKIConnection connection = client.getConnection();
        connection.setRejectedCertStatuses(rejectedCertStatuses);
        connection.setIgnoredCertStatuses(ignoredCertStatuses);

        if (output != null) {
            File file = new File(output);
            file.mkdirs();
            connection.setOutput(file);
        }
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd;
        try {
            cmd = parser.parse(options, args, true);
        } catch (Exception e) {
            throw new Error(e.getMessage(), e);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmd.hasOption("version")) {
            printVersion();
            System.exit(0);
        }

        if (cmdArgs.length == 0 || cmd.hasOption("help")) {
            // Print 'pki' usage
            printHelp();
            System.exit(0);
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

        // Do not call CryptoManager.initialize() on client-init
        // because otherwise the database will be locked.
        String command = cmdArgs[0];
        if (!command.equals("client-init") && !command.equals("client-cert-import")) {
            init();
        }

        super.execute(cmdArgs);
    }

    public static void printMessage(String message) {
        System.out.println(StringUtils.repeat("-", message.length()));
        System.out.println(message);
        System.out.println(StringUtils.repeat("-", message.length()));
    }

    public static void main(String args[]) {
        try {
            MainCLI cli = new MainCLI();
            cli.execute(args);

        } catch (Throwable t) {
            if (verbose) {
                t.printStackTrace(System.err);
            } else {
                System.err.println(t.getClass().getSimpleName()+": "+t.getMessage());
            }
            System.exit(-1);
        }
    }
}
