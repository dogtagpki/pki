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

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.selftests.SelfTestResult;
import com.netscape.certsrv.selftests.SelfTestResults;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class SelfTestRunCLI extends CLI {

    public SelfTestCLI selfTestCLI;

    public SelfTestRunCLI(SelfTestCLI selfTestCLI) {
        super("run", "Run selftests", selfTestCLI);
        this.selfTestCLI = selfTestCLI;
    }

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

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        SelfTestClient selfTestClient = selfTestCLI.getSelfTestClient();
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
