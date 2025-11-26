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

package org.dogtagpki.server.cli;

import javax.ws.rs.ProcessingException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CLIModule;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PKIServerCLI extends CLI {

    public static Logger logger = LoggerFactory.getLogger(PKIServerCLI.class);

    public PKIServerCLI() throws Exception {
        super("pki-server", "PKI server management commands");

        addModule("ca", "org.dogtagpki.server.ca.cli.CACLI");
        addModule("kra", "org.dogtagpki.server.kra.cli.KRACLI");
        addModule("ocsp", "org.dogtagpki.server.ocsp.cli.OCSPCLI");
        addModule("tks", "org.dogtagpki.server.tks.cli.TKSCLI");
        addModule("tps", "org.dogtagpki.server.tps.cli.TPSCLI");
        addModule("acme", "org.dogtagpki.server.acme.cli.ACMECLI");
    }

    @Override
    public String getFullModuleName(String moduleName) {
        return moduleName;
    }

    @Override
    public void createOptions() throws Exception {

        Option option = new Option("d", true, "NSS database location");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("f", true, "NSS database password configuration");
        option.setArgName("password config");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    @Override
    public void printHelp() throws Exception {

        formatter.printHelp(name + " [OPTIONS..] <command> [ARGS..]", options);
        System.out.println();

        super.printHelp();
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

        CommandLine cmd = parser.parse(options, args, true);

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(LogLevel.INFO);
        }

        String[] cmdArgs = cmd.getArgs();
        logger.debug("Command: " + String.join(" ", cmdArgs));

        executeCommand(cmdArgs);
    }

    @Override
    public void handleException(Throwable t) {

        if (logger.isInfoEnabled()) {
            t.printStackTrace(System.err);

        } else if (t.getClass() == Exception.class) {
            // display a generic error
            System.err.println("ERROR: " + t.getMessage());

        } else if (t instanceof UnrecognizedOptionException) {
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

    public static void main(String[] args) throws Exception {
        PKIServerCLI cli = new PKIServerCLI();
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
