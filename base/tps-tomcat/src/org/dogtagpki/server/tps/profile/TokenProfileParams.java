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
package org.dogtagpki.server.tps.profile;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.netscape.certsrv.apps.CMS;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.EndOp.TPSStatus;

/**
 * A class represents profile params information.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class TokenProfileParams {

    public static final String PROFILE_PARAM_MAJOR_VERSION = "pp_major_version";
    public static final String PROFILE_PARAM_MINOR_VERSION = "pp_minor_version";
    public static final String PROFILE_PARAM_CUID = "pp_cuid";
    public static final String PROFILE_PARAM_MSN = "pp_msn";
    public static final String PROFILE_PARAM_EXT_TOKEN_TYPE = "pp_ext_tokenType";
    public static final String PROFILE_PARAM_EXT_TOKEN_ATR = "pp_ext_tokenATR";

    private HashMap<String, String> content = new HashMap<String, String>();

    /**
     * Constructs a meta information.
     * <P>
     */
    public TokenProfileParams() {
    }

    /**
     * Returns a short string describing this certificate attribute.
     * <P>
     *
     * @return information about this certificate attribute.
     */
    public String toString() {
        StringBuffer sb = new StringBuffer("[\n" + "  Meta information:\n");

        for (Map.Entry<String, String> entry : content.entrySet()) {
            String key = entry.getKey();

            sb.append("  " + key + " : " + entry.getValue() + "\n");
        }
        sb.append("]\n");
        return sb.toString();
    }

    /**
     * Gets a String attribute value.
     * <P>
     *
     * @param name the name of the attribute to return.
     */
    public String getString(String name)
           throws TPSException {
        String val = content.get(name);
        if (val == null) {
            CMS.debug("TokenProfileParams.getString: param null:"+ name);
            throw new TPSException (
                    "TokenProfileParams.getString: param null:"+ name,
                    TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND);
        }
        return val;
    }

    /**
     * Gets an int attribute value.
     * <P>
     *
     * @param name the name of the attribute to return.
     */
    public int getInt(String name)
           throws TPSException {
        String val = content.get(name);
        if (val == null) {
            CMS.debug("TokenProfileParams.getInt: param null:"+ name);
            throw new TPSException (
                    "TokenProfileParams.getInt: param null:"+ name,
                    TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND);
        }
        try {
            int intVal = Integer.parseInt(val);
            return intVal;
        } catch (NumberFormatException e) {
            CMS.debug("TokenProfileParams.getInt: param "+ name + "=" + val + e);
            throw new TPSException (
                    "TokenProfileParams.getInt: param major_version:"+ e,
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }
    }

    /**
     * Sets an attribute value.
     *
     * @param name the name of the attribute
     * @param val the attribute value.
     */
    public void set(String name, String val) {
        content.put(name, val);
    }

    /**
     * Deletes an attribute value from this AttrSet.
     * <P>
     *
     * @param name the name of the attribute to delete.
     */
    public void delete(String name) {
        content.remove(name);
    }

    /**
     * Returns an enumeration of the names of the attributes existing within
     * this attribute.
     * <P>
     *
     * @return an enumeration of the attribute names.
     */
    public Set<String> getElements() {
        return content.keySet();
    }
}
