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

package com.netscape.cmstools.cert;

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Ade Lee
 */
public class CertRequestFindCLI extends CLI {

    public CertCLI certCLI;

    public CertRequestFindCLI(CertCLI certCLI) {
        super("request-find", "Find certificate requests", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        addOptions();

        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        if (cmd.hasOption("help")) {
            printHelp();
            System.exit(-1);
        }

        String s = cmd.getOptionValue("start");
        RequestId start = s == null ? null : new RequestId(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("maxResults");
        Integer maxResults = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("maxTime");
        Integer maxTime = s == null ? null : Integer.valueOf(s);

        String requestState = cmd.getOptionValue("status");
        if (requestState != null && requestState.equals("all")) requestState = null;

        String requestType = cmd.getOptionValue("type");
        if (requestType != null && requestType.equals("all")) requestType = null;

        CertRequestInfos response = certCLI.certClient.certRequestClient.listRequests(requestState, requestType, start, size, maxResults, maxTime);

        MainCLI.printMessage(response.getTotal() + " entries matched");
        if (response.getTotal() == 0) return;

        Collection<CertRequestInfo> entries = response.getEntries();
        boolean first = true;

        for (CertRequestInfo certRequest : entries) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            CertCLI.printCertRequestInfo(certRequest);
        }

        MainCLI.printMessage("Number of entries returned " + entries.size());
    }

    public void addOptions() {

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

        //help
        options.addOption(null, "help", false, "Show help options");
    }
}
