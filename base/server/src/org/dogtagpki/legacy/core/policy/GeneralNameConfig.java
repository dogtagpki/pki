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
package org.dogtagpki.legacy.core.policy;

import java.util.Enumeration;
import java.util.Vector;

import org.dogtagpki.legacy.policy.IGeneralNameConfig;
import org.mozilla.jss.netscape.security.x509.GeneralName;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

/**
 * convenience class for policies use.
 */
public class GeneralNameConfig implements IGeneralNameConfig {
    public String mName = null;
    public String mNameDot = null;
    public IConfigStore mConfig = null;
    public String mGenNameChoice = null;
    public boolean mIsValueConfigured = true;
    public String mValue = null; // used only if isValueConfigured
    public GeneralName mGeneralName = null; // used only if isValueConfiged.
    public boolean mIsPolicyEnabled = true;

    public String mNameDotChoice = null;
    public String mNameDotValue = null;

    public GeneralNameConfig(
            String name,
            IConfigStore config,
            boolean isValueConfigured,
            boolean isPolicyEnabled)
            throws EBaseException {
        mIsValueConfigured = isValueConfigured;
        mIsPolicyEnabled = isPolicyEnabled;
        mName = name;
        if (mName != null && mName.length() > 0) {
            mNameDot = mName + GeneralNameUtil.DOT;
            mNameDotChoice = mNameDot + GeneralNameUtil.PROP_GENNAME_CHOICE;
            mNameDotValue = mNameDot + GeneralNameUtil.PROP_GENNAME_VALUE;
        } else {
            mNameDot = "";
            mNameDotChoice = GeneralNameUtil.PROP_GENNAME_CHOICE;
            mNameDotValue = GeneralNameUtil.PROP_GENNAME_VALUE;
        }
        mConfig = config;

        // necessary to expand/shrink # general names from console.
        if (mConfig.size() == 0) {
            config.putString(mNameDotChoice, "");
            if (mIsValueConfigured)
                config.putString(mNameDotValue, "");
        }

        String choice = null;

        if (mIsPolicyEnabled) {
            choice = mConfig.getString(GeneralNameUtil.PROP_GENNAME_CHOICE);
            mGenNameChoice = GeneralNameUtil.check_GeneralNameChoice(choice);
        } else {
            choice = mConfig.getString(GeneralNameUtil.PROP_GENNAME_CHOICE, "");
            if (choice.length() > 0 && !choice.equals("null")) {
                mGenNameChoice = GeneralNameUtil.check_GeneralNameChoice(choice);
            }
        }
        if (mIsValueConfigured) {
            if (mIsPolicyEnabled) {
                mValue = mConfig.getString(GeneralNameUtil.PROP_GENNAME_VALUE);
                mGeneralName = formGeneralName(mGenNameChoice, mValue);
            } else {
                mValue = mConfig.getString(GeneralNameUtil.PROP_GENNAME_VALUE, "");
                if (mValue != null && mValue.length() > 0)
                    mGeneralName = formGeneralName(mGenNameChoice, mValue);
            }
        }
    }

    /**
     * Form a general name from the value string.
     */
    public GeneralName formGeneralName(String value)
            throws EBaseException {
        return formGeneralName(mGenNameChoice, value);
    }

    public GeneralName formGeneralName(String choice, String value)
            throws EBaseException {
        return GeneralNameUtil.form_GeneralName(choice, value);
    }

    /**
     * @return a vector of General names from a value that can be
     *         either a Vector of strings, string array or just a string.
     *         Returned Vector can be null if value is not of expected type.
     */
    public Vector<GeneralName> formGeneralNames(Object value)
            throws EBaseException {
        Vector<GeneralName> gns = new Vector<GeneralName>();
        GeneralName gn = null;

        if (value instanceof String) {
            if (((String) (value = ((String) value).trim())).length() > 0) {
                gn = formGeneralName(mGenNameChoice, (String) value);
                gns.addElement(gn);
            }
        } else if (value instanceof String[]) {
            String[] vals = (String[]) value;

            for (int i = 0; i < vals.length; i++) {
                String val = vals[i].trim();

                if (val != null && val.length() > 0) {
                    gn = formGeneralName(mGenNameChoice, val);
                    gns.addElement(gn);
                }
            }
        } else if (value instanceof Vector) {
            Vector<?> vals = (Vector<?>) value;

            for (Enumeration<?> n = vals.elements(); n.hasMoreElements();) {
                Object val = n.nextElement();

                if (val != null && (val instanceof String) &&
                        ((String) (val = ((String) val).trim())).length() > 0) {
                    gn = formGeneralName(mGenNameChoice, (String) val);
                    gns.addElement(gn);
                }
            }
        }
        return gns;
    }

    public String getName() {
        return mName;
    }

    public IConfigStore getConfig() {
        return mConfig;
    }

    public String getGenNameChoice() {
        return mGenNameChoice;
    }

    public String getValue() {
        return mValue;
    }

    /*
     public GeneralNameInterface getGeneralName() {
     return mGeneralName;
     }

     */
    public boolean isValueConfigured() {
        return mIsValueConfigured;
    }

    /**
     * Get default params
     */

    public static void getDefaultParams(
            String name, boolean isValueConfigured, Vector<String> params) {
        String nameDot = "";

        if (name != null)
            nameDot = name + ".";
        GeneralNameUtil.logger.trace("GeneralnameConfig getDefaultParams");
        params.addElement(nameDot + GeneralNameUtil.PROP_GENNAME_CHOICE + "=");
        if (isValueConfigured)
            params.addElement(nameDot + GeneralNameUtil.PROP_GENNAME_VALUE + "=");
    }

    /**
     * Get instance params
     */
    public void getInstanceParams(Vector<String> params) {
        String value = (mValue == null) ? "" : mValue;
        String choice = (mGenNameChoice == null) ? "" : mGenNameChoice;

        params.addElement(mNameDotChoice + "=" + choice);
        if (mIsValueConfigured)
            params.addElement(mNameDotValue + "=" + value);
    }

    /**
     * Get extended plugin info
     */
    public static void getExtendedPluginInfo(
            String name, boolean isValueConfigured, Vector<String> info) {
        String nameDot = "";

        if (name != null && name.length() > 0)
            nameDot = name + ".";
        info.addElement(
                nameDot + GeneralNameUtil.PROP_GENNAME_CHOICE + ";" + GeneralNameUtil.GENNAME_CHOICE_INFO);
        if (isValueConfigured)
            info.addElement(
                    nameDot + GeneralNameUtil.PROP_GENNAME_VALUE + ";" + GeneralNameUtil.GENNAME_VALUE_INFO);
    }
}
