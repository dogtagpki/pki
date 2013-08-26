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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.tps.connection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Arrays;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.tps.connection.ConnectionClient;
import com.netscape.certsrv.tps.connection.ConnectionData;
import com.netscape.certsrv.tps.connection.ConnectionInfo;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class ConnectionCLI extends CLI {

    public ConnectionClient connectionClient;

    public ConnectionCLI(CLI parent) {
        super("connection", "Connection management commands", parent);

        addModule(new ConnectionAddCLI(this));
        addModule(new ConnectionFindCLI(this));
        addModule(new ConnectionModifyCLI(this));
        addModule(new ConnectionRemoveCLI(this));
        addModule(new ConnectionShowCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        connectionClient = (ConnectionClient)parent.getClient("connection");

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String[] commandArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command == null) {
            printHelp();
            System.exit(1);
        }

        CLI module = getModule(command);
        if (module != null) {
            module.execute(commandArgs);

        } else {
            System.err.println("Error: Invalid command \"" + command + "\"");
            printHelp();
            System.exit(1);
        }
    }

    public static void printConnectionInfo(ConnectionInfo connectionInfo) {
        System.out.println("  Connection ID: " + connectionInfo.getID());
        if (connectionInfo.getStatus() != null) System.out.println("  Status: " + connectionInfo.getStatus());

        Link link = connectionInfo.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }

    public static void printConnectionData(ConnectionData connectionData) throws IOException {
        System.out.println("  Connection ID: " + connectionData.getID());
        if (connectionData.getStatus() != null) System.out.println("  Status: " + connectionData.getStatus());

        System.out.println("  Contents:");
        String contents = connectionData.getContents();
        if (contents != null) {
            BufferedReader in = new BufferedReader(new StringReader(contents));
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println("    " + line);
            }
        }

        Link link = connectionData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
