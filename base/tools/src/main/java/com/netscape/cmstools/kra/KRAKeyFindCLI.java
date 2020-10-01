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

package com.netscape.cmstools.kra;

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.certsrv.key.KeyInfoCollection;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class KRAKeyFindCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAKeyFindCLI.class);

    public KRAKeyCLI keyCLI;

    public KRAKeyFindCLI(KRAKeyCLI keyCLI) {
        super("find", "Find keys", keyCLI);
        this.keyCLI = keyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "clientKeyID", true, "Unique client key identifier");
        option.setArgName("client key ID");
        options.addOption(option);

        option = new Option(null, "status", true, "Status: active, inactive");
        option.setArgName("status");
        options.addOption(option);

        option = new Option(null, "maxResults", true, "Maximum results");
        option.setArgName("max results");
        options.addOption(option);

        option = new Option(null, "maxTime", true, "Maximum time");
        option.setArgName("max time");
        options.addOption(option);

        option = new Option(null, "start", true, "Page start");
        option.setArgName("start");
        options.addOption(option);

        option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
        options.addOption(option);

        option = new Option(null, "realm", true, "Realm");
        option.setArgName("realm");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json");
        option.setArgName("format");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String clientKeyID = cmd.getOptionValue("clientKeyID");
        String status = cmd.getOptionValue("status");
        String realm = cmd.getOptionValue("realm");
        String outputFormat = cmd.getOptionValue("output-format", "text");

        String s = cmd.getOptionValue("maxResults");
        Integer maxResults = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("maxTime");
        Integer maxTime = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        KeyClient keyClient = keyCLI.getKeyClient();
        KeyInfoCollection keys = keyClient.listKeys(clientKeyID, status, maxResults, maxTime, start, size, realm);

        if ("json".equalsIgnoreCase(outputFormat)) {
            System.out.println(keys.toJSON());

        } else if ("text".equalsIgnoreCase(outputFormat)) {
            Collection<KeyInfo> entries = keys.getEntries();

            MainCLI.printMessage(entries.size() + " key(s) matched");

            boolean first = true;

            for (KeyInfo info : entries) {

                if (first) {
                    first = false;
                } else {
                    System.out.println();
                }

                KRAKeyCLI.printKeyInfo(info);
            }

            MainCLI.printMessage("Number of entries returned " + entries.size());

        } else {
            throw new Exception("Unsupported format: " + outputFormat);
        }
    }
}
