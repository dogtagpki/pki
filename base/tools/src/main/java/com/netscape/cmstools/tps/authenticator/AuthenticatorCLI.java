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

package com.netscape.cmstools.tps.authenticator;

import java.io.IOException;
import java.util.Map;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.tps.authenticator.AuthenticatorData;
import com.netscape.cmstools.tps.TPSCLI;

/**
 * @author Endi S. Dewata
 */
public class AuthenticatorCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthenticatorCLI.class);

    public TPSCLI tpsCLI;

    public AuthenticatorCLI(TPSCLI tpsCLI) {
        super("authenticator", "Authenticator management commands", tpsCLI);
        this.tpsCLI = tpsCLI;

        addModule(new AuthenticatorAddCLI(this));
        addModule(new AuthenticatorFindCLI(this));
        addModule(new AuthenticatorModifyCLI(this));
        addModule(new AuthenticatorRemoveCLI(this));
        addModule(new AuthenticatorShowCLI(this));
    }

    public static void printAuthenticatorData(AuthenticatorData authenticatorData, boolean showProperties) throws IOException {
        System.out.println("  Authenticator ID: " + authenticatorData.getID());
        if (authenticatorData.getStatus() != null) System.out.println("  Status: " + authenticatorData.getStatus());

        if (showProperties) {
            System.out.println("  Properties:");
            Map<String, String> properties = authenticatorData.getProperties();
            if (properties != null) {
                for (String name : properties.keySet()) {
                    String value = properties.get(name);
                    System.out.println("    " + name + ": " + value);
                }
            }
        }
    }
}
