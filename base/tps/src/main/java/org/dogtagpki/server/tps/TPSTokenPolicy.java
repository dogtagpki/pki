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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;

/*
 * TPSTokenPolicy - handles token enrollment related policies
 *
 * @author cfu
 */
public class TPSTokenPolicy {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSTokenPolicy.class);

    private TPSSubsystem tps;
    private static final String DEFAULT_POLICY_SET_STRING =
            "RE_ENROLL=YES;RENEW=NO;FORCE_FORMAT=NO;PIN_RESET=NO;RESET_PIN_RESET_TO_NO=NO";
    private boolean re_enroll = true;
    private boolean renew = false;
    private boolean renew_keep_old_enc_certs = true;
    private boolean force_format = false;
    private boolean pin_reset = true;
    private boolean reset_pin_reset_to_no = false;
    private String cuid = null;

    // Construct with a single token in mind. Load the token's config from
    // the db after the default. All operations will then be on this token.
    public TPSTokenPolicy (TPSSubsystem tps, String cuid) throws TPSException {
        if (tps == null) {
            String msg = "TPSTokenPolicy.TPSTokenPolicy: tps cannnot be null";
            logger.error(msg);
            throw new TPSException(msg);
        }
        if (cuid == null) {
            String msg = "TPSTokenPolicy.TPSTokenPolicy: cuid cannnot be null";
            logger.error(msg);
            throw new TPSException(msg);
        }
        this.tps = tps;
        // Get the CS.cfg defaults first
        String policySetString = getDefaultPolicySetString();
        parsePolicySetString(policySetString);

        this.cuid = cuid;
        //Read from the token db once and write at the end if needed
        getUpdatedPolicy();
    }

    public String getDefaultPolicySetString() {
        TPSEngine engine = TPSEngine.getInstance();
        TPSEngineConfig configStore = engine.getConfig();
        TokenDBConfig tdbConfig = configStore.getTokenDBConfig();
        String policySetString;
        try {
            policySetString = tdbConfig.getString("defaultPolicy");
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

    /* Take the current state of the policyt variables, create a new policy string,
     * and write the new value for the provided token cuid.
     */
    public void updatePolicySet()  throws TPSException {

        String method = "TPSTokenPolicy.updatePolicySet: ";
        String msg = method +  "Can't update token policy string to database.";

        TokenRecord tokenRecord = null;
        try {
            tokenRecord = tps.tdb.tdbGetTokenEntry(this.cuid);
        } catch (Exception e) {
            throw new TPSException(e.toString() + " " + msg);
        }

        String newPolicy = "";

        newPolicy += "RE_ENROLL=" + getFromBool(re_enroll);
        newPolicy += ";RENEW=" + getFromBool(renew);
        newPolicy += ";FORCE_FORMAT=" + getFromBool(force_format);
        newPolicy += ";PIN_RESET=" + getFromBool(pin_reset);
        newPolicy += ";RESET_PIN_RESET_TO_NO=" + getFromBool(reset_pin_reset_to_no);
        newPolicy += ";RENEW_KEEP_OLD_ENC_CERTS=" + getFromBool(renew_keep_old_enc_certs);

        logger.debug("{}newPolicy: {}", method, newPolicy);
        tokenRecord.setPolicy(newPolicy);
        try {
            tps.tdb.tdbUpdateTokenEntry(tokenRecord);
        } catch(Exception e) {
            throw new TPSException(e.toString() + " " + msg);
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

    private String getFromBool(boolean value) {
        return value ? "YES" : "NO";
    }

    private void getUpdatedPolicy() {
        // note: default policy already initialized in the constructor
        TokenRecord tokenRecord = null;
        String policySetString = null;
        try {
            tokenRecord = tps.tdb.tdbGetTokenEntry(this.cuid);
        } catch (Exception e) {
            // just take the default;
            return;
        }

        policySetString = tokenRecord.getPolicy();
        parsePolicySetString(policySetString);
    }

    // Note we only want to allow one cuid to be operated upon
    // by this class, since we are going to allow values to be changed
    // as well as written.

    public boolean isAllowedTokenPinReset() {
        return reset_pin_reset_to_no;
    }

    // Add better named version to get the value
    // reset_pin_reset_to_no

    public boolean isAllowedResetPinResetToNo() {
        return reset_pin_reset_to_no;
    }

    public boolean isAllowedPinReset() {
        return pin_reset;
    }

    public boolean isForceTokenFormat() {
        return force_format;
    }

    public boolean isAllowdTokenReenroll() {
        return re_enroll;
    }

    public boolean isAllowdRenewSaveOldEncCerts() {
        return renew_keep_old_enc_certs;
    }

    public boolean isAllowdTokenRenew() {
        return renew;
    }

    public void setAllowedTokenPinReset(boolean value) {
        reset_pin_reset_to_no = value;
    }

    public void setAllowedResetPinResetToNo(boolean value) {
        reset_pin_reset_to_no = value;
    }

    public void setAllowedPinReset(boolean value) {
        pin_reset = value;
    }

    public void setForceTokenFormat(boolean value) {
        force_format = value;
    }

    public void setAllowdTokenReenroll(boolean value) {
        re_enroll = value;
    }

    public void setAllowdRenewSaveOldEncCerts(boolean value) {
        renew_keep_old_enc_certs = value;
    }

    public void setAllowdTokenRenew(boolean value) {
        renew = value;
    }

}
