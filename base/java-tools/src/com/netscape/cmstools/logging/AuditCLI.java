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

package com.netscape.cmstools.logging;

import java.io.IOException;
import java.util.Map;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.logging.AuditClient;
import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.cmstools.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class AuditCLI extends CLI {

    public AuditClient auditClient;

    public AuditCLI(CLI parent) {
        super("audit", "Audit management commands", parent);

        addModule(new AuditModifyCLI(this));
        addModule(new AuditShowCLI(this));
    }

    public void execute(String[] args) throws Exception {

        client = parent.getClient();
        auditClient = (AuditClient)parent.getClient("audit");

        super.execute(args);
    }

    public static void printAuditConfig(AuditConfig auditConfig) throws IOException {

        if (auditConfig.getEnabled() != null) System.out.println("  Enabled: " + auditConfig.getEnabled());
        if (auditConfig.getSigned() != null) System.out.println("  Signed: " + auditConfig.getSigned());
        if (auditConfig.getInterval() != null) System.out.println("  Interval (seconds): " + auditConfig.getInterval());
        if (auditConfig.getBufferSize() != null) System.out.println("  Buffer size (bytes): " + auditConfig.getBufferSize());

        System.out.println("  Events:");
        Map<String, Boolean> events = auditConfig.getOptionalEvents();
        for (String name : events.keySet()) {
            Boolean value = events.get(name);
            System.out.println("    " + name + ": " + value);
        }

        Link link = auditConfig.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
