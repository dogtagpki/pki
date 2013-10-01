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

import java.io.IOException;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.selftests.SelfTestData;
import com.netscape.cmstools.cli.CLI;
/**
 * @author Endi S. Dewata
 */
public class SelfTestCLI extends CLI {

    public SelfTestClient selfTestClient;

    public SelfTestCLI(CLI parent) {
        super("selftest", "Selftest management commands", parent);

        addModule(new SelfTestFindCLI(this));
        addModule(new SelfTestRunCLI(this));
        addModule(new SelfTestShowCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        selfTestClient = (SelfTestClient)parent.getClient("selftest");

        super.execute(args);
    }

    public static void printSelfTestData(SelfTestData selfTestData) throws IOException {
        System.out.println("  SelfTest ID: " + selfTestData.getID());
        if (selfTestData.isEnabledAtStartup() != null) System.out.println("  Enabled at startup: " + selfTestData.isEnabledAtStartup());
        if (selfTestData.isCriticalAtStartup() != null) System.out.println("  Critical at startup: " + selfTestData.isCriticalAtStartup());
        if (selfTestData.isEnabledOnDemand() != null) System.out.println("  Enabled on demand: " + selfTestData.isEnabledOnDemand());
        if (selfTestData.isCriticalOnDemand() != null) System.out.println("  Critical on demand: " + selfTestData.isCriticalOnDemand());

        Link link = selfTestData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
