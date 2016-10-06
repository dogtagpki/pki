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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps;

import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.tps.main.TPSException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;

/*
 * TPSTokenPolicy - handles token enrollment related policies
 *
 * @author cfu
 */
public class TPSTokenPolicy {
    private TPSSubsystem tps;
    private static final String DEFAULT_POLICY_SET_STRING =
            "RE_ENROLL=YES;RENEW=NO;FORCE_FORMAT=NO;PIN_RESET=NO;RESET_PIN_RESET_TO_NO=NO";
    private boolean re_enroll = true;
    private boolean renew = false;
    private boolean renew_keep_old_enc_certs = true;
    private boolean force_format = false;
    private boolean pin_reset = true;
    private boolean reset_pin_reset_to_no = false;

    public TPSTokenPolicy (TPSSubsystem tps) throws TPSException {
        if (tps == null) {
            String msg = "TPSTokenPolicy.TPSTokenPolicy: tps cannnot be null";
            CMS.debug(msg);
            throw new TPSException(msg);
        }
        this.tps = tps;
        // init from config first
        String policySetString = getDefaultPolicySetString();
        parsePolicySetString(policySetString);

    }

    public String getDefaultPolicySetString() {
        IConfigStore configStore = CMS.getConfigStore();
        String configName = "tokendb.defaultPolicy";
        String policySetString;
        try {
            policySetString = configStore.getString(configName);
        } catch (EPropertyNotFound e) {
            policySetString = DEFAULT_POLICY_SET_STRING;
        } catch (EBaseException e) {
            policySetString = DEFAULT_POLICY_SET_STRING;
        }

        return policySetString;
    }

    public void parsePolicySetString (String policySetString) {
        if (policySetString == null)
            return; // take the default

        String[] policySet = policySetString.split(";");
        for (String policyString : policySet) {
            String[] policy = policyString.split("=");
            if (policy[0].equalsIgnoreCase("RE_ENROLL"))
                re_enroll = getBool(policy[1], true);
            else if (policy[0].equalsIgnoreCase("RENEW"))
                renew = getBool(policy[1], false);
            else if (policy[0].equalsIgnoreCase("FORCE_FORMAT"))
                force_format = getBool(policy[1], false);
            else if (policy[0].equalsIgnoreCase("PIN_RESET"))
                pin_reset = getBool(policy[1], false);
            else if (policy[0].equalsIgnoreCase("RESET_PIN_RESET_TO_NO"))
                reset_pin_reset_to_no = getBool(policy[1], false);
            else if (policy[0].equalsIgnoreCase("RENEW_KEEP_OLD_ENC_CERTS"))
                renew_keep_old_enc_certs = getBool(policy[1],true);
            //else no change, just take the default;
        }
    }

/*
 * getBool translates string to boolean:
 * true: "YES", "yes", "TRUE", "true"
 * false: "NO", "no", "FALSE", "false"
 *
 * if tring is null or Anything othrer than the above, defaultbool is returned
 */
    private boolean getBool(String string, boolean defaultBool) {
        if (string == null)
            return defaultBool;

        if (string.equalsIgnoreCase("YES") ||
                string.equalsIgnoreCase("true")) {
            return true;
        } else if (string.equalsIgnoreCase("NO") ||
                string.equalsIgnoreCase("false")) {
            return false;
        }

        return defaultBool;
    }

    private void getUpdatedPolicy(String cuid) {
        // note: default policy already initialized in the constructor
        TokenRecord tokenRecord = null;
        String policySetString = null;
        try {
            tokenRecord = tps.tdb.tdbGetTokenEntry(cuid);
        } catch (Exception e) {
            // just take the default;
            return;
        }

        policySetString = tokenRecord.getPolicy();
        parsePolicySetString(policySetString);
    }

    public boolean isAllowedTokenPinReset(String cuid) {
        getUpdatedPolicy(cuid);

        return reset_pin_reset_to_no;
    }

    public boolean isAllowedPinReset(String cuid) {
        getUpdatedPolicy(cuid);

        return pin_reset;
    }

    public boolean isForceTokenFormat(String cuid) {
        getUpdatedPolicy(cuid);

        return force_format;
    }

    public boolean isAllowdTokenReenroll(String cuid) {
        getUpdatedPolicy(cuid);

        return re_enroll;
    }

    public boolean isAllowdRenewSaveOldEncCerts(String cuid) {
        getUpdatedPolicy(cuid);
        return renew_keep_old_enc_certs;
    }

    public boolean isAllowdTokenRenew(String cuid) {
        getUpdatedPolicy(cuid);

        return renew;
    }
}