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
package org.dogtagpki.server.tps.mapping;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.apps.CMS;

/**
 * A class represents filter mapping params information.
 * <P>
 *
 * @author cfu
 */
public class FilterMappingParams {

    public static final String FILTER_PARAM_MAJOR_VERSION = "fp_major_version";
    public static final String FILTER_PARAM_MINOR_VERSION = "fp_minor_version";
    public static final String FILTER_PARAM_CUID = "fp_cuid";
    public static final String FILTER_PARAM_MSN = "fp_msn";
    public static final String FILTER_PARAM_EXT_TOKEN_TYPE = "fp_ext_tokenType";
    public static final String FILTER_PARAM_EXT_TOKEN_ATR = "fp_ext_tokenATR";

    private HashMap<String, String> content = new HashMap<String, String>();

    /**
     * Constructs a meta information.
     * <P>
     */
    public FilterMappingParams() {
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
            CMS.debug("FilterMappingParams.getString: param null:"+ name);
            throw new TPSException (
                    "FilterMappingParams.getString: param null:"+ name,
                    TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_PARAMS_NOT_FOUND);
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
            CMS.debug("FilterMappingParams.getInt: param null:"+ name);
            throw new TPSException (
                    "FilterMappingParams.getInt: param null:"+ name,
                    TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_PARAMS_NOT_FOUND);
        }
        try {
            int intVal = Integer.parseInt(val);
            return intVal;
        } catch (NumberFormatException e) {
            CMS.debug("FilterMappingParams.getInt: param "+ name + "=" + val + e);
            throw new TPSException (
                    "FilterMappingParams.getInt: param major_version:"+ e,
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
