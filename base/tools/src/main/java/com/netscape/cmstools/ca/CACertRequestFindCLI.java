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

package com.netscape.cmstools.ca;

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Ade Lee
 */
public class CACertRequestFindCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertRequestFindCLI.class);

    public CACertRequestCLI certRequestCLI;

    public CACertRequestFindCLI(CACertRequestCLI certRequestCLI) {
        super("find", "Find certificate requests", certRequestCLI);
        this.certRequestCLI = certRequestCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = null;

        // request state
        option = new Option(null, "status", true, "Request status (pending, cancelled, rejected, complete, all)");
        option.setArgName("status");
        options.addOption(option);

        // request type
        option = new Option(null, "type", true, "Request type (enrollment, renewal, revocation, all)");
        option.setArgName("type");
        options.addOption(option);

        //pagination options
        option = new Option(null, "start", true, "Page start");
        option.setArgName("start");
        options.addOption(option);

        option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
        options.addOption(option);

        //search limits
        option = new Option(null, "maxResults", true, "Maximum number of results");
        option.setArgName("maxResults");
        options.addOption(option);

        option = new Option(null, "timeout", true, "Search timeout");
        option.setArgName("maxTime");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String start = cmd.getOptionValue("start");

        String s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("maxResults");
        Integer maxResults = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("maxTime");
        Integer maxTime = s == null ? null : Integer.valueOf(s);

        String requestState = cmd.getOptionValue("status");
        if (requestState != null && requestState.equals("all")) requestState = null;

        String requestType = cmd.getOptionValue("type");
        if (requestType != null && requestType.equals("all")) requestType = null;

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CACertClient certClient = certRequestCLI.getCertClient(client);
        CertRequestInfos response = certClient.listRequests(requestState, requestType, start, size, maxResults, maxTime);

        Integer total = response.getTotal();
        if (total != null) {
            MainCLI.printMessage(total + " entries matched");
            if (total == 0) return;
        }

        Collection<CertRequestInfo> entries = response.getEntries();
        boolean first = true;

        for (CertRequestInfo certRequest : entries) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            CACertRequestCLI.printCertRequestInfo(certRequest);
        }

        MainCLI.printMessage("Number of entries returned " + entries.size());
    }
}
