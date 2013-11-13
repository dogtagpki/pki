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

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfos;
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
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void execute(String[] args) {

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

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String status = cmd.getOptionValue("status");
        String type = cmd.getOptionValue("type");
        String clientID = cmd.getOptionValue("client");

        String s = cmd.getOptionValue("start");
        RequestId start = s == null ? null : new RequestId(s);

        s = cmd.getOptionValue("pageSize");
        Integer pageSize = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("maxResults");
        Integer maxResults = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("maxTime");
        Integer maxTime = s == null ? null : Integer.valueOf(s);

        KeyRequestInfos keys = keyCLI.keyClient.findKeyRequests(
                status, type, clientID, start, pageSize, maxResults, maxTime);

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
