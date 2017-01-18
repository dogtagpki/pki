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

package com.netscape.cmstools.key;

import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfoCollection;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class KeyRequestFindCLI extends CLI {

    public KeyCLI keyCLI;

    public KeyRequestFindCLI(KeyCLI keyCLI) {
        super("request-find", "Find key requests", keyCLI);
        this.keyCLI = keyCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "status", true, "Request status");
        option.setArgName("status");
        options.addOption(option);

        option = new Option(null, "type", true, "Request type");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "client", true, "Client ID");
        option.setArgName("client ID");
        options.addOption(option);

        option = new Option(null, "maxResults", true, "Maximum results");
        option.setArgName("max results");
        options.addOption(option);

        option = new Option(null, "maxTime", true, "Maximum time");
        option.setArgName("max time");
        options.addOption(option);

        option = new Option(null, "start", true, "Page to start");
        option.setArgName("starting page");
        options.addOption(option);

        option = new Option(null, "pageSize", true, "Page size");
        option.setArgName("page size");
        options.addOption(option);

        option = new Option(null, "realm", true, "Authorization Realm");
        option.setArgName("realm");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String status = cmd.getOptionValue("status");
        String type = cmd.getOptionValue("type");
        String clientKeyID = cmd.getOptionValue("client");
        String realm = cmd.getOptionValue("realm");

        String s = cmd.getOptionValue("start");
        RequestId start = s == null ? null : new RequestId(s);

        s = cmd.getOptionValue("pageSize");
        Integer pageSize = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("maxResults");
        Integer maxResults = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("maxTime");
        Integer maxTime = s == null ? null : Integer.valueOf(s);

        KeyRequestInfoCollection keys = keyCLI.keyClient.listRequests(
                status, type, clientKeyID, start, pageSize, maxResults, maxTime, realm);

        MainCLI.printMessage(keys.getTotal() + " entries matched");
        if (keys.getTotal() == 0) return;

        Collection<KeyRequestInfo> entries = keys.getEntries();
        boolean first = true;

        for (KeyRequestInfo info : entries) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            KeyCLI.printKeyRequestInfo(info);
        }

        MainCLI.printMessage("Number of entries returned " + entries.size());
    }
}
