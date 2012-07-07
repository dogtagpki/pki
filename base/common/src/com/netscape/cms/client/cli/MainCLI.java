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

package com.netscape.cms.client.cli;

import java.io.File;
import java.net.URISyntaxException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;

import com.netscape.cms.client.cert.CertCLI;
import com.netscape.cms.client.group.GroupCLI;
import com.netscape.cms.client.user.UserCLI;

/**
 * @author Endi S. Dewata
 */
public class MainCLI extends CLI {

    public ClientConfig config = new ClientConfig();

    public MainCLI() throws Exception {
        super("pki", "PKI command-line interface");

        addModule(new CertCLI(this));
        addModule(new GroupCLI(this));
        addModule(new UserCLI(this));
    }

    public void printHelp() {

        formatter.printHelp(name+" [OPTIONS..] <command> [ARGS..]", options);

        System.out.println();
        System.out.println("Commands:");

        int leftPadding = 1;
        int rightPadding = 18;

        for (CLI plugin : modules.values()) {
            String label = plugin.getName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1) padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(plugin.getDescription());
        }
    }

    public void printHelpCommand(String pluginName) {
        CLI plugin = getModule(pluginName);
        plugin.printHelp();
    }

    public void createOptions(Options options) {

        Option option = new Option("U", true, "Server URI");
        option.setArgName("uri");
        options.addOption(option);

        option = new Option("P", true, "Protocol (default: http)");
        option.setArgName("protocol");
        options.addOption(option);

        option = new Option("h", true, "Hostname (default: localhost)");
        option.setArgName("hostname");
        options.addOption(option);

        option = new Option("p", true, "Port (default: 9180)");
        option.setArgName("port");
        options.addOption(option);

        option = new Option("t", true, "Subsystem type (default: ca)");
        option.setArgName("type");
        options.addOption(option);

        option = new Option("d", true, "Certificate database");
        option.setArgName("database");
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

        options.addOption("v", false, "Verbose");
        options.addOption(null, "help", false, "Help");
    }

    public void parseOptions(CommandLine cmd) throws URISyntaxException {

        String uri = cmd.getOptionValue("U");

        String protocol = cmd.getOptionValue("P", "http");
        String hostname = cmd.getOptionValue("h", "localhost");
        String port = cmd.getOptionValue("p", "8080");
        String type = cmd.getOptionValue("t", "ca");

        if (uri == null)
            uri = protocol + "://" + hostname + ":" + port + "/" + type;

        config.setServerURI(uri);

        String certDatabase = cmd.getOptionValue("d");
        String certNickname = cmd.getOptionValue("n");
        String username = cmd.getOptionValue("u");
        String password = cmd.getOptionValue("w");

        // convert into absolute path
        if (certDatabase != null)
            config.setCertDatabase(new File(certDatabase).getAbsolutePath());

        if (certNickname != null)
            config.setCertNickname(certNickname);

        if (username != null)
            config.setUsername(username);

        if (password != null)
            config.setPassword(password);
    }

    public void execute(String[] args) throws Exception {

        CLI module;
        String[] moduleArgs;

        try {
            createOptions(options);

            CommandLine cmd;
            try {
                cmd = parser.parse(options, args, true);
            } catch (Exception e) {
                throw new Error(e.getMessage(), e);
            }

            String[] cmdArgs = cmd.getArgs();

            if (cmdArgs.length == 0 || cmd.hasOption("help")) {
                printHelp();
                System.exit(1);
            }

            verbose = cmd.hasOption("v");

            if (verbose) {
                System.out.print("Command:");
                for (String arg : cmdArgs) {
                    if (arg.contains(" ")) arg = "\""+arg+"\"";
                    System.out.print(" "+arg);
                }
                System.out.println();
            }

            parseOptions(cmd);

            String command = cmdArgs[0];
            String moduleName;
            String moduleCommand;

            // If a command contains a '-' sign it will be
            // split into module name and module command.
            // Otherwise it's a single command.
            int i = command.indexOf('-');
            if (i >= 0) { // <module name>-<module command>
                moduleName = command.substring(0, i);
                moduleCommand = command.substring(i+1);

            } else { // <command>
                moduleName = command;
                moduleCommand = null;
            }

            // get command module
            module = getModule(moduleName);
            if (module == null)
                throw new Error("Invalid command \"" + command + "\".");

            // prepare module arguments
            if (moduleCommand != null) {
                moduleArgs = new String[cmdArgs.length];
                moduleArgs[0] = moduleCommand;
                System.arraycopy(cmdArgs, 1, moduleArgs, 1, cmdArgs.length-1);

            } else {
                moduleArgs = new String[cmdArgs.length-1];
                System.arraycopy(cmdArgs, 1, moduleArgs, 0, cmdArgs.length-1);
            }

        } catch (Throwable t) {
            if (verbose) {
                t.printStackTrace(System.err);
            } else {
                System.err.println(t.getClass().getSimpleName()+": "+t.getMessage());
            }
            printHelp();
            System.exit(1);
            return;
        }

        // execute module command
        try {
            if (verbose) System.out.println("Server URI: "+config.getServerURI());

            // initialize certificate database if specified
            if (config.getCertDatabase() != null) {

                if (verbose) System.out.println("Certificate database: "+config.getCertDatabase());
                CryptoManager.initialize(config.getCertDatabase());

                if (config.getPassword() != null) {
                    try {
                        CryptoManager manager = CryptoManager.getInstance();
                        CryptoToken token = manager.getInternalKeyStorageToken();
                        Password password = new Password(config.getPassword().toCharArray());
                        token.login(password);

                    } catch (IncorrectPasswordException e) {
                        throw new Error("Incorrect certificate database password.", e);
                    }
                }
            }

            // execute module command
            module.execute(moduleArgs);

        } catch (Throwable t) {
            if (verbose) {
                t.printStackTrace(System.err);
            } else {
                System.err.println(t.getClass().getSimpleName()+": "+t.getMessage());
            }
            System.exit(1);
        }
    }

    public static void printMessage(String message) {
        System.out.println(StringUtils.repeat("-", message.length()));
        System.out.println(message);
        System.out.println(StringUtils.repeat("-", message.length()));
    }

    public static void main(String args[]) throws Exception {
        MainCLI cli = new MainCLI();
        cli.execute(args);
    }
}
