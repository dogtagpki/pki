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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.group;

import org.dogtagpki.cli.CLI;

import com.netscape.cmstools.cli.ProxyCLI;

/**
 * @deprecated pki group has been deprecated. Use pki &lt;subsystem&gt;-group instead.
 */
@Deprecated
public class ProxyGroupCLI extends ProxyCLI {

    public ProxyGroupCLI(CLI parent) {
        super(new GroupCLI(parent), "ca");
    }

    public void execute(String[] args) throws Exception {
        System.err.println("WARNING: pki group has been deprecated. Use pki <subsystem>-group instead.");
        super.execute(args);
    }
}
