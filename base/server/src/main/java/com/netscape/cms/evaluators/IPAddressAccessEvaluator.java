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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.evaluators;

import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.evaluators.AccessEvaluator;
import com.netscape.cmscore.apps.CMS;

/**
 * A class represents a IP address acls evaluator.
 */
public class IPAddressAccessEvaluator extends AccessEvaluator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(IPAddressAccessEvaluator.class);

    /**
     * Class constructor.
     */
    public IPAddressAccessEvaluator() {
        this.type = "ipaddress";
        this.description = "IP Address evaluator";
    }

    /**
     * initialization. nothing for now.
     */
    @Override
    public void init() {
    }

    @Override
    public String[] getSupportedOperators() {
        String[] s = new String[2];

        s[0] = "=";
        s[1] = "!=";
        return s;
    }

    /**
     * Gets the IP address from session context
     *
     * @param authToken authentication token
     * @param type must be "ipaddress"
     * @param op must be "=" or "!="
     * @param value the ipaddress
     */
    @Override
    public boolean evaluate(AuthToken authToken, String type, String op, String value) {

        return evaluate(type, op, value);
    }

    /**
     * evaluates uid in SessionContext to see if it has membership in
     * group value
     *
     * @param type must be "group"
     * @param op must be "="
     * @param value the group name
     * @return true if SessionContext uid belongs to the group value,
     *         false otherwise
     */
    @Override
    public boolean evaluate(String type, String op, String value) {

        SessionContext mSC = SessionContext.getContext();

        value = Utils.stripQuotes(value);
        String ipaddress = (String) mSC.get(SessionContext.IPADDRESS);

        if (type.equals(this.type)) {
            if (ipaddress == null) {
                logger.warn("IPAddressAccessEvaluator: " + CMS.getLogMessage("EVALUATOR_IPADDRESS_NULL"));
                return false;
            }
            boolean ipMatches = ipaddress.matches(value);
            return op.equals("=") ? ipMatches : !ipMatches;

        }

        return false;
    }
}
