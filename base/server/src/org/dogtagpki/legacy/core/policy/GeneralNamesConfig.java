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

import org.dogtagpki.legacy.core.policy.GeneralNameUtil.GeneralNameConfig;
import org.dogtagpki.legacy.policy.IGeneralNamesConfig;
import org.mozilla.jss.netscape.security.x509.GeneralNames;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.apps.CMS;

public class GeneralNamesConfig implements IGeneralNamesConfig {
    public String mName = null; // substore name of config if any.
    public GeneralNameConfig[] mGenNameConfigs = null;
    public IConfigStore mConfig = null;
    public boolean mIsValueConfigured = true;
    public boolean mIsPolicyEnabled = true;
    public int mDefNumGenNames = GeneralNameUtil.DEF_NUM_GENERALNAMES;
    public GeneralNames mGeneralNames = null;

    private String mNameDotGeneralName = mName + GeneralNameUtil.DOT + GeneralNameUtil.PROP_GENERALNAME;

    public GeneralNamesConfig(
            String name,
            IConfigStore config,
            boolean isValueConfigured,
            boolean isPolicyEnabled)
            throws EBaseException {
        mIsValueConfigured = isValueConfigured;
        mIsPolicyEnabled = isPolicyEnabled;
        mName = name;
        if (mName != null)
            mNameDotGeneralName = mName + GeneralNameUtil.DOT + GeneralNameUtil.PROP_GENERALNAME;
        else
            mNameDotGeneralName = GeneralNameUtil.PROP_GENERALNAME;
        mConfig = config;

        int numGNs = mConfig.getInteger(GeneralNameUtil.PROP_NUM_GENERALNAMES);

        if (numGNs < 0) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                            new String[] {
                                    GeneralNameUtil.PROP_NUM_GENERALNAMES + "=" + numGNs,
                                    "value must be greater than or equal to 0." }
                            ));
        }
        mGenNameConfigs = new GeneralNameConfig[numGNs];
        for (int i = 0; i < numGNs; i++) {
            String storeName = mNameDotGeneralName + i;

            mGenNameConfigs[i] =
                    newGeneralNameConfig(
                            storeName, mConfig.getSubStore(storeName),
                            mIsValueConfigured, mIsPolicyEnabled);
        }

        if (mIsValueConfigured && mIsPolicyEnabled) {
            mGeneralNames = new GeneralNames();
            for (int j = 0; j < numGNs; j++) {
                mGeneralNames.addElement(mGenNameConfigs[j].mGeneralName);
            }
        }
    }

    public GeneralNames getGeneralNames() {
        return mGeneralNames;
    }

    protected GeneralNameConfig newGeneralNameConfig(
            String name, IConfigStore config,
            boolean isValueConfigured, boolean isPolicyEnabled)
            throws EBaseException {
        return new GeneralNameConfig(
                name, config, isValueConfigured, isPolicyEnabled);
    }

    public GeneralNameConfig[] getGenNameConfig() {
        return mGenNameConfigs.clone();
    }

    public int getNumGeneralNames() {
        return mGenNameConfigs.length;
    }

    public IConfigStore getConfig() {
        return mConfig;
    }

    public String getName() {
        return mName;
    }

    public boolean isValueConfigured() {
        return mIsValueConfigured;
    }

    public void setDefNumGenNames(int defNum) {
        mDefNumGenNames = defNum;
    }

    public int getDefNumGenNames() {
        return mDefNumGenNames;
    }

    /**
     * adds params to default
     */
    public static void getDefaultParams(
            String name, boolean isValueConfigured, Vector<String> params) {
        String nameDot = "";

        if (name != null)
            nameDot = name + GeneralNameUtil.DOT;
        params.addElement(
                nameDot + GeneralNameUtil.PROP_NUM_GENERALNAMES + '=' + GeneralNameUtil.DEF_NUM_GENERALNAMES);
        for (int i = 0; i < GeneralNameUtil.DEF_NUM_GENERALNAMES; i++) {
            GeneralNameConfig.getDefaultParams(
                    nameDot + GeneralNameUtil.PROP_GENERALNAME + i, isValueConfigured, params);
        }
    }

    /**
     * Get instance params.
     */
    public void getInstanceParams(Vector<String> params) {
        params.addElement(
                GeneralNameUtil.PROP_NUM_GENERALNAMES + '=' + mGenNameConfigs.length);
        for (int i = 0; i < mGenNameConfigs.length; i++) {
            mGenNameConfigs[i].getInstanceParams(params);
        }
    }

    /**
     * Get extended plugin info.
     */
    public static void getExtendedPluginInfo(
            String name, boolean isValueConfigured, Vector<String> info) {
        String nameDot = "";

        if (name != null && name.length() > 0)
            nameDot = name + ".";
        info.addElement(GeneralNameUtil.PROP_NUM_GENERALNAMES + ";" + GeneralNameUtil.NUM_GENERALNAMES_INFO);
        for (int i = 0; i < GeneralNameUtil.DEF_NUM_GENERALNAMES; i++) {
            GeneralNameConfig.getExtendedPluginInfo(
                    nameDot + GeneralNameUtil.PROP_GENERALNAME + i, isValueConfigured, info);
        }
    }

}
