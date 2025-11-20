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

package com.netscape.cmstools.selftests;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.lang3.StringUtils;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.selftests.SelfTestResult;
import com.netscape.certsrv.selftests.SelfTestResults;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class SelfTestRunCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SelfTestRunCLI.class);

    public SelfTestCLI selfTestCLI;

    public SelfTestRunCLI(SelfTestCLI selfTestCLI) {
        super("run", "Run selftests", selfTestCLI);
        this.selfTestCLI = selfTestCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [selftests...] [OPTIONS...]", options);
    }

    public static void printSelfTestResult(SelfTestResult result) {
        System.out.println("  Selftest ID: " + result.getID());

        String status = result.getStatus();
        System.out.println("  Status: " + status);

        String output = result.getOutput();
        if (StringUtils.isNotEmpty(output)) {
            System.out.println("  Output:");
            System.out.println(output);
        }
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = selfTestCLI.subsystemCLI.getSubsystemClient(client);
        SelfTestClient selfTestClient = new SelfTestClient(subsystemClient);
        SelfTestResults results;

        if (cmdArgs.length == 0) {
            results = selfTestClient.runSelfTests();

        } else {

            results = new SelfTestResults();

            for (String selfTestID : cmdArgs) {
                SelfTestResult result = selfTestClient.runSelfTest(selfTestID);
                results.addEntry(result);;
            }
        }

        boolean first = true;

        for (SelfTestResult result : results.getEntries()) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            printSelfTestResult(result);
        }

        MainCLI.printMessage("Selftests completed");
    }
}
