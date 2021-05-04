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

import java.util.Vector;

import org.dogtagpki.legacy.policy.ISubjAltNameConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.apps.CMS;

public class SubjAltNameGN extends GeneralNameConfig implements ISubjAltNameConfig {
    static final String REQUEST_ATTR_INFO =
            "string;Request attribute name. " +
                    "The value of the request attribute will be used to form a " +
                    "General Name in the Subject Alternative Name extension.";

    static final String PROP_REQUEST_ATTR = "requestAttr";

    String mRequestAttr = null;
    String mPfx = null;
    String mAttr = null;

    public SubjAltNameGN(
            String name, IConfigStore config, boolean isPolicyEnabled)
            throws EBaseException {
        super(name, config, false, isPolicyEnabled);

        mRequestAttr = mConfig.getString(PROP_REQUEST_ATTR, null);
        if (mRequestAttr == null) {
            mConfig.putString(mNameDot + PROP_REQUEST_ATTR, "");
            mRequestAttr = "";
        }
        if (isPolicyEnabled && mRequestAttr.length() == 0) {
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                        mConfig.getName() + "." + PROP_REQUEST_ATTR));
        }
        int x = mRequestAttr.indexOf('.');

        if (x == -1)
            mAttr = mRequestAttr;
        else {
            mPfx = mRequestAttr.substring(0, x).trim();
            mAttr = mRequestAttr.substring(x + 1).trim();
        }
    }

    public String getPfx() {
        return mPfx;
    }

    public String getAttr() {
        return mAttr;
    }

    public void getInstanceParams(Vector<String> params) {
        params.addElement(mNameDot + PROP_REQUEST_ATTR + "=" + mRequestAttr);
        super.getInstanceParams(params);
    }

    public static void getDefaultParams(String name, Vector<String> params) {
        String nameDot = "";

        if (name != null && name.length() > 0)
            nameDot = name + ".";
        params.addElement(nameDot + PROP_REQUEST_ATTR + "=");
        GeneralNameConfig.getDefaultParams(name, false, params);
    }

    public static void getExtendedPluginInfo(String name, Vector<String> params) {
        String nameDot = "";

        if (name != null && name.length() > 0)
            nameDot = name + ".";
        params.addElement(nameDot + PROP_REQUEST_ATTR + ";" + REQUEST_ATTR_INFO);
        GeneralNameConfig.getExtendedPluginInfo(name, false, params);
    }
}
