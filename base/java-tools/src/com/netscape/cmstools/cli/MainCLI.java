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

import java.io.File;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashSet;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
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

        addModule(new CACLI(this));
        addModule(new KRACLI(this));
        addModule(new OCSPCLI(this));
        addModule(new TKSCLI(this));
        addModule(new TPSCLI(this));

        addModule(new ClientCLI(this));

        addModule(new ProxyCLI(new CertCLI(this), "ca"));
        addModule(new ProxyCLI(new GroupCLI(this), "ca"));
        addModule(new ProxyCLI(new KeyCLI(this), "kra"));
        addModule(new ProxyCLI(new SecurityDomainCLI(this), "ca"));
        addModule(new ProxyCLI(new UserCLI(this), "ca"));
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

        System.out.println("Subsystems:");

        for (CLI module : modules.values()) {
            if (!(module instanceof SubsystemCLI)) continue;

            String label = module.getFullName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1)
                padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(module.getDescription());
        }

        System.out.println();
        System.out.println("Commands:");

        for (CLI module : modules.values()) {
            if (module instanceof SubsystemCLI) continue;

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

    public void createOptions(Options options) throws UnknownHostException {

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

        option = new Option("d", true, "Security database location (default: ~/.dogtag/nssdb)");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("c", true, "Security database password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option("n", true, "Certificate nickname");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option("u", true, "Username");
        option.setArgName("username");
        options.addOption(option);

        option = new Option("w", true, "Password");
        option.setArgName("password");
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

        options.addOption("v", false, "Verbose");
        options.addOption(null, "help", false, "Help");
        options.addOption(null, "version", false, "Version");
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
        String username = cmd.getOptionValue("u");
        String password = cmd.getOptionValue("w");

        // convert into absolute path
        if (certDatabase != null)
            config.setCertDatabase(new File(certDatabase).getAbsolutePath());

        if (certNickname != null)
            config.setCertNickname(certNickname);

        if (certPassword != null)
            config.setCertPassword(certPassword);

        if (username != null)
            config.setUsername(username);

        if (password != null)
            config.setPassword(password);

        String list = cmd.getOptionValue("reject-cert-status");
        convertCertStatusList(list, rejectedCertStatuses);

        list = cmd.getOptionValue("ignore-cert-status");
        convertCertStatusList(list, ignoredCertStatuses);

        if (config.getCertDatabase() == null) {
            // Use default security database
            this.certDatabase = new File(
                    System.getProperty("user.home") + File.separator +
                    ".dogtag" + File.separator + "nssdb");

        } else {
            // Use existing security database
            this.certDatabase = new File(config.getCertDatabase());
        }

        if (verbose) System.out.println("Security database: "+this.certDatabase.getAbsolutePath());
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

        // Main program should initialize security database
        if (certDatabase.exists()) {
            CryptoManager.initialize(certDatabase.getAbsolutePath());
        }

        // If password is specified, use password to access security database
        if (config.getCertPassword() != null) {
            try {
                CryptoManager manager = CryptoManager.getInstance();
                CryptoToken token = manager.getInternalKeyStorageToken();
                Password password = new Password(config.getCertPassword().toCharArray());
                token.login(password);

            } catch (NotInitializedException e) {
                // The original exception doesn't contain a message.
                throw new Error("Security database does not exist.");

            } catch (IncorrectPasswordException e) {
                // The original exception doesn't contain a message.
                throw new IncorrectPasswordException("Incorrect security database password.");
            }

        }

        client = new PKIClient(config);
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

        createOptions(options);

        CommandLine cmd;
        try {
            cmd = parser.parse(options, args, true);
        } catch (Exception e) {
            throw new Error(e.getMessage(), e);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmd.hasOption("version")) {
            printVersion();
            System.exit(1);
        }

        if (cmdArgs.length == 0 || cmd.hasOption("help")) {
            printHelp();
            System.exit(1);
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
            System.exit(1);
        }
    }
}
