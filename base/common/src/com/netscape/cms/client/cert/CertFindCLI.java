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

package com.netscape.cms.client.cert;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.cms.client.cli.CLI;
import com.netscape.cms.client.cli.MainCLI;
import com.netscape.cms.servlet.cert.model.CertDataInfo;
import com.netscape.cms.servlet.cert.model.CertDataInfos;

/**
 * @author Endi S. Dewata
 */
public class CertFindCLI extends CLI {

    public CertCLI parent;

    public CertFindCLI(CertCLI parent) {
        super("find", "Find certificates");
        this.parent = parent;
    }

    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {

        Option option = new Option(null, "status", true, "Certificate status");
        option.setArgName("status");
        options.addOption(option);

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }

        String status = cmd.getOptionValue("status");
        CertDataInfos certs = parent.client.findCerts(status);

        MainCLI.printMessage(certs.getCertInfos().size() + " certificate(s) matched");

        boolean first = true;

        for (CertDataInfo cert : certs.getCertInfos()) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            CertCLI.printCertInfo(cert);
        }

        MainCLI.printMessage("Number of entries returned " + certs.getCertInfos().size());
    }
}
