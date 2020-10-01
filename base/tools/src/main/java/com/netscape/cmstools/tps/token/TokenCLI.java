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

package com.netscape.cmstools.tps.token;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CLI;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.tps.token.TokenClient;
import com.netscape.certsrv.tps.token.TokenData;
import com.netscape.certsrv.tps.token.TokenData.TokenStatusData;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.cmstools.tps.TPSCLI;

/**
 * @author Endi S. Dewata
 */
public class TokenCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TokenCLI.class);

    public TPSCLI tpsCLI;
    public TokenClient tokenClient;

    public TokenCLI(TPSCLI tpsCLI) {
        super("token", "Token management commands", tpsCLI);
        this.tpsCLI = tpsCLI;

        addModule(new TokenAddCLI(this));
        addModule(new TokenFindCLI(this));
        addModule(new TokenModifyCLI(this));
        addModule(new TokenRemoveCLI(this));
        addModule(new TokenShowCLI(this));
    }

    public TokenClient getTokenClient() throws Exception {

        if (tokenClient != null) return tokenClient;

        PKIClient client = getClient();
        tokenClient = (TokenClient)parent.getClient("token");

        return tokenClient;
    }

    public static void printToken(TokenData token) {
        System.out.println("  Token ID: " + token.getID());
        if (token.getUserID() != null) System.out.println("  User ID: " + token.getUserID());
        if (token.getType() != null) System.out.println("  Type: " + token.getType());

        TokenStatusData status = token.getStatus();
        if (status != null) System.out.println("  Status: " + status.name);

        Collection<TokenStatusData> nextStates = token.getNextStates();
        if (nextStates != null) {
            Collection<TokenStatus> names = new ArrayList<TokenStatus>();
            for (TokenStatusData nextState : nextStates) {
                names.add(nextState.name);
            }
            System.out.println("  Next States: " + StringUtils.join(names, ", "));
        }

        if (token.getAppletID() != null) System.out.println("  Applet ID: " + token.getAppletID());
        if (token.getKeyInfo() != null) System.out.println("  Key Info: " + token.getKeyInfo());
        if (token.getPolicy() != null) System.out.println("  Policy: " + token.getPolicy());
        if (token.getCreateTimestamp() != null) System.out.println("  Date Created: " + token.getCreateTimestamp());
        if (token.getModifyTimestamp() != null) System.out.println("  Date Modified: " + token.getModifyTimestamp());

        Link link = token.getLink();
        logger.info("Link: " + (link == null ? null : link.getHref()));
    }
}
