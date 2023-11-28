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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ca.cli;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.SubsystemDBAccessCLI;
import org.dogtagpki.server.cli.SubsystemDBEmptyCLI;
import org.dogtagpki.server.cli.SubsystemDBIndexCLI;
import org.dogtagpki.server.cli.SubsystemDBInfoCLI;
import org.dogtagpki.server.cli.SubsystemDBInitCLI;
import org.dogtagpki.server.cli.SubsystemDBRemoveCLI;
import org.dogtagpki.server.cli.SubsystemDBReplicationCLI;
import org.dogtagpki.server.cli.SubsystemDBVLVCLI;

/**
 * @author Endi S. Dewata
 */
public class CADBCLI extends CLI {

    public CADBCLI(CLI parent) {
        super("db", "CA database management commands", parent);

        addModule(new SubsystemDBInfoCLI(this));
        addModule(new SubsystemDBInitCLI(this));
        addModule(new SubsystemDBEmptyCLI(this));
        addModule(new SubsystemDBRemoveCLI(this));
        addModule(new CADBUpgradeCLI(this));

        addModule(new SubsystemDBAccessCLI(this));
        addModule(new SubsystemDBIndexCLI(this));
        addModule(new SubsystemDBReplicationCLI(this));
        addModule(new SubsystemDBVLVCLI(this));
    }
}
