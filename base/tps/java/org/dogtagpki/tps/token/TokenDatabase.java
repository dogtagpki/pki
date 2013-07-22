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

package org.dogtagpki.tps.token;

import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This class implements in-memory token database. In the future this
 * will be replaced with LDAP database.
 *
 * @author Endi S. Dewata
 */
public class TokenDatabase {

    public final static int DEFAULT_SIZE = 20;

    Map<String, TokenRecord> tokens = new LinkedHashMap<String, TokenRecord>();

    public Collection<TokenRecord> getTokens() throws Exception {
        return tokens.values();
    }

    public TokenRecord getToken(String tokenID) throws Exception {
        if (!tokens.containsKey(tokenID)) {
            throw new Exception("Token "+ tokenID + " does not exist.");
        }
        return tokens.get(tokenID);
    }

    public void addToken(TokenRecord tokenRecord) throws Exception {
        if (tokens.containsKey(tokenRecord.getID())) {
            throw new Exception("Token "+ tokenRecord.getID() + " already exists.");
        }

        tokenRecord.setStatus("ENABLED");
        tokenRecord.setCreateTimestamp(new Date());

        tokens.put(tokenRecord.getID(), tokenRecord);
    }

    public void updateToken(String tokenID, TokenRecord tokenRecord) throws Exception {
        if (!tokens.containsKey(tokenRecord.getID())) {
            throw new Exception("Token "+ tokenRecord.getID() + " does not exist.");
        }

        tokenRecord.setModifyTimestamp(new Date());

        tokens.put(tokenRecord.getID(), tokenRecord);
    }

    public void removeToken(String tokenID) throws Exception {
        if (!tokens.containsKey(tokenID)) {
            throw new Exception("Token "+ tokenID + " does not exist.");
        }
        tokens.remove(tokenID);
    }
}
