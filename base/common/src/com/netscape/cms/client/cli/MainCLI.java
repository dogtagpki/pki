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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;

import com.netscape.cms.client.user.UserCLI;

/**
 * @author Endi S. Dewata
 */
public class MainCLI extends CLI {

    public String protocol;
    public String hostname;
    public String port;
    public String type;

    public String certDBDirectory;
    public String certDBPassword;
    public String certNickname;

    public String url;

    public MainCLI() throws Exception {
        super("pki", "PKI command-line interface");

        addModule(new UserCLI(this));
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getCertDBDirectory() {
        return certDBDirectory;
    }

    public void setCertDBDirectory(String certDBDirectory) {
        this.certDBDirectory = certDBDirectory;
    }

    public String getCertDBPassword() {
        return certDBPassword;
    }

    public void setCertDBPassword(String certDBPassword) {
        this.certDBPassword = certDBPassword;
    }

    public String getCertNickname() {
        return certNickname;
    }

    public void setCertNickname(String certNickname) {
        this.certNickname = certNickname;
    }

    public void printHelp() {

        formatter.printHelp(getName()+" [OPTIONS..] <command> [ARGS..]", options);

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

    public void execute(String[] args) throws Exception {

        Option option = new Option("U", true, "URL");
        option.setArgName("url");
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

        option = new Option("d", true, "Certificate database directory");
        option.setArgName("directory");
        options.addOption(option);

        option = new Option("w", true, "Certificate database password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option("n", true, "Certificate nickname");
        option.setArgName("cert");
        options.addOption(option);

        options.addOption("v", false, "Verbose");
        options.addOption(null, "help", false, "Help");

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args, true);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmd.hasOption("help") || cmdArgs.length == 0) {
            printHelp();
            System.exit(1);
        }

        verbose = cmd.hasOption("v");

        url = cmd.getOptionValue("U");
        protocol = cmd.getOptionValue("P", "http");
        hostname = cmd.getOptionValue("h", "localhost");
        port = cmd.getOptionValue("p", "9180");
        type = cmd.getOptionValue("t", "ca");

        if (url == null) {
            url = protocol + "://" + hostname + ":" + port + "/" + type;
        }

        if (verbose) System.out.println("Server URL: "+url);

        certDBDirectory = cmd.getOptionValue("d");
        certDBPassword = cmd.getOptionValue("w");
        certNickname = cmd.getOptionValue("n");

        if (certDBDirectory != null && certDBPassword != null) {

            if (verbose) System.out.println("Certificate DB: "+certDBDirectory);

            try {
                CryptoManager.initialize(certDBDirectory);
            } catch (AlreadyInitializedException e) {
                // ignore
            }

            CryptoManager manager = CryptoManager.getInstance();
            CryptoToken token = manager.getInternalKeyStorageToken();
            Password password = new Password(certDBPassword.toCharArray());

            try {
                token.login(password);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                if (!token.isLoggedIn()) {
                    token.initPassword(password, password);
                }
            }
        }

        if (verbose) {
            System.out.print("Command:");
            for (String arg : cmdArgs) {
                System.out.print(" "+arg);
            }
            System.out.println();
        }

        // command-line args: <command> [command args...]
        if (cmdArgs.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = cmdArgs[0];

        String moduleName;
        String moduleCommand;

        // parse command: <module name>-<module command>
        int i = command.indexOf('-');
        if (i >= 0) {
            moduleName = command.substring(0, i);
            moduleCommand = command.substring(i+1);
        } else {
            moduleName = command;
            moduleCommand = null;
        }

        // get command module
        CLI module = getModule(moduleName);
        if (module == null) {
            System.err.println("Error: Invalid command \"" + command + "\"");
            printHelp();
            System.exit(1);
        }

        // prepare module arguments
        String[] moduleArgs = new String[cmdArgs.length];
        moduleArgs[0] = moduleCommand;
        System.arraycopy(cmdArgs, 1, moduleArgs, 1, cmdArgs.length-1);

        // execute module command
        try {
            module.execute(moduleArgs);

        } catch (Throwable t) {
            if (verbose) {
                t.printStackTrace();
            } else {
                System.err.println(t.getClass().getSimpleName()+": "+t.getMessage());
            }
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
