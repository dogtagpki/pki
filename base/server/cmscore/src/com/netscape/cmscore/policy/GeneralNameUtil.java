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
package com.netscape.cmscore.policy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.DNSName;
import netscape.security.x509.EDIPartyName;
import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNameInterface;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.IPAddressName;
import netscape.security.x509.InvalidIPAddressException;
import netscape.security.x509.OIDName;
import netscape.security.x509.RFC822Name;
import netscape.security.x509.URIName;
import netscape.security.x509.X500Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.policy.IGeneralNameAsConstraintsConfig;
import com.netscape.certsrv.policy.IGeneralNameConfig;
import com.netscape.certsrv.policy.IGeneralNameUtil;
import com.netscape.certsrv.policy.IGeneralNamesAsConstraintsConfig;
import com.netscape.certsrv.policy.IGeneralNamesConfig;
import com.netscape.certsrv.policy.ISubjAltNameConfig;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.util.Utils;

/**
 * Class that can be used to form general names from configuration file.
 * Used by policies and extension commands.
 * @deprecated
 */
public class GeneralNameUtil implements IGeneralNameUtil {

    private static final String DOT = ".";

    /**
     * GeneralName can be used in the context of Constraints. Examples
     * are NameConstraints, CertificateScopeOfUse extensions. In such
     * cases, IPAddress may contain netmask component.
     */
    static public GeneralName
            form_GeneralNameAsConstraints(String generalNameChoice, String value)
                    throws EBaseException {
        try {
            if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_IPADDRESS)) {
                StringTokenizer st = new StringTokenizer(value, ",");
                String ip = st.nextToken();
                String netmask = null;

                if (st.hasMoreTokens()) {
                    netmask = st.nextToken();
                }
                return new GeneralName(new IPAddressName(ip, netmask));
            } else {
                return form_GeneralName(generalNameChoice, value);
            }
        } catch (InvalidIPAddressException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_IP_ADDR", value));
        }
    }

    /**
     * Form a General Name from a General Name choice and value.
     * The General Name choice must be one of the General Name Choice Strings
     * defined in this class.
     *
     * @param generalNameChoice General Name choice. Must be one of the General
     *            Name choices defined in this class.
     * @param value String value of the general name to form.
     */
    static public GeneralName
            form_GeneralName(String generalNameChoice, String value)
                    throws EBaseException {
        GeneralNameInterface generalNameI = null;
        DerValue derVal = null;
        GeneralName generalName = null;

        try {
            if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_OTHERNAME)) {
                byte[] val = Utils.base64decode(value);

                derVal = new DerValue(new ByteArrayInputStream(val));
                Debug.trace("otherName formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_RFC822NAME)) {
                generalNameI = new RFC822Name(value);
                Debug.trace("rfc822Name formed ");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_DNSNAME)) {
                generalNameI = new DNSName(value);
                Debug.trace("dnsName formed");
            }/**
             * not supported -- no sun class
             * else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_X400ADDRESS)) {
             * }
             **/
            else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_DIRECTORYNAME)) {
                generalNameI = new X500Name(value);
                Debug.trace("X500Name formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_EDIPARTYNAME)) {
                generalNameI = new EDIPartyName(value);
                Debug.trace("ediPartyName formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_URL)) {
                generalNameI = new URIName(value);
                Debug.trace("url formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_IPADDRESS)) {
                generalNameI = new IPAddressName(value);
                Debug.trace("ipaddress formed");
            } else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_REGISTEREDID)) {
                ObjectIdentifier oid;

                try {
                    oid = new ObjectIdentifier(value);
                } catch (Exception e) {
                    throw new EBaseException(
                            CMS.getUserMessage("CMS_BASE_INVALID_VALUE_FOR_TYPE",
                                    generalNameChoice,
                                    "value must be a valid OID in the form n.n.n.n"));
                }
                generalNameI = new OIDName(oid);
                Debug.trace("oidname formed");
            } else {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                                new String[] {
                                        PROP_GENNAME_CHOICE,
                                        "value must be one of: " +
                                                GENNAME_CHOICE_OTHERNAME + ", " +
                                                GENNAME_CHOICE_RFC822NAME + ", " +
                                                GENNAME_CHOICE_DNSNAME + ", " +

                                                /* GENNAME_CHOICE_X400ADDRESS +", "+ */
                                                GENNAME_CHOICE_DIRECTORYNAME + ", " +
                                                GENNAME_CHOICE_EDIPARTYNAME + ", " +
                                                GENNAME_CHOICE_URL + ", " +
                                                GENNAME_CHOICE_IPADDRESS + ", or " +
                                                GENNAME_CHOICE_REGISTEREDID + "."
                            }
                                ));
            }
        } catch (IOException e) {
            Debug.printStackTrace(e);
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_VALUE_FOR_TYPE",
                            generalNameChoice, e.toString()));
        } catch (InvalidIPAddressException e) {
            Debug.printStackTrace(e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_IP_ADDR", value));
        } catch (RuntimeException e) {
            Debug.printStackTrace(e);
            throw e;
        }

        try {
            if (generalNameI != null)
                generalName = new GeneralName(generalNameI);
            else
                generalName = new GeneralName(derVal);
            Debug.trace("general name formed");
            return generalName;
        } catch (IOException e) {
            Debug.printStackTrace(e);
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", "Could not form GeneralName. Error: " + e));
        }
    }

    /**
     * Checks if given string is a valid General Name choice and returns
     * the actual string that can be passed into form_GeneralName().
     *
     * @param generalNameChoice a General Name choice string.
     * @return one of General Name choices defined in this class that can be
     *         passed into form_GeneralName().
     */
    static public String check_GeneralNameChoice(String generalNameChoice)
            throws EBaseException {
        String theGeneralNameChoice = null;

        if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_OTHERNAME))
            theGeneralNameChoice = GENNAME_CHOICE_OTHERNAME;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_RFC822NAME))
            theGeneralNameChoice = GENNAME_CHOICE_RFC822NAME;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_DNSNAME))
            theGeneralNameChoice = GENNAME_CHOICE_DNSNAME;

        /* X400Address not supported.
         else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_X400ADDRESS))
         theGeneralNameChoice = GENNAME_CHOICE_X400ADDRESS;
         */
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_DIRECTORYNAME))
            theGeneralNameChoice = GENNAME_CHOICE_DIRECTORYNAME;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_EDIPARTYNAME))
            theGeneralNameChoice = GENNAME_CHOICE_EDIPARTYNAME;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_URL))
            theGeneralNameChoice = GENNAME_CHOICE_URL;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_IPADDRESS))
            theGeneralNameChoice = GENNAME_CHOICE_IPADDRESS;
        else if (generalNameChoice.equalsIgnoreCase(GENNAME_CHOICE_REGISTEREDID))
            theGeneralNameChoice = GENNAME_CHOICE_REGISTEREDID;
        else {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                            new String[] {
                                    PROP_GENNAME_CHOICE + "=" + generalNameChoice,
                                    "value must be one of: " +
                                            GENNAME_CHOICE_OTHERNAME + ", " +
                                            GENNAME_CHOICE_RFC822NAME + ", " +
                                            GENNAME_CHOICE_DNSNAME + ", " +

                                            /* GENNAME_CHOICE_X400ADDRESS +", "+ */
                                            GENNAME_CHOICE_DIRECTORYNAME + ", " +
                                            GENNAME_CHOICE_EDIPARTYNAME + ", " +
                                            GENNAME_CHOICE_URL + ", " +
                                            GENNAME_CHOICE_IPADDRESS + ", " +
                                            GENNAME_CHOICE_REGISTEREDID + "."
                        }
                            ));
        }
        return theGeneralNameChoice;
    }

    static public class GeneralNamesConfig implements IGeneralNamesConfig {
        public String mName = null; // substore name of config if any.
        public GeneralNameConfig[] mGenNameConfigs = null;
        public IConfigStore mConfig = null;
        public boolean mIsValueConfigured = true;
        public boolean mIsPolicyEnabled = true;
        public int mDefNumGenNames = DEF_NUM_GENERALNAMES;
        public GeneralNames mGeneralNames = null;

        private String mNameDotGeneralName = mName + DOT + PROP_GENERALNAME;

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
                mNameDotGeneralName = mName + DOT + PROP_GENERALNAME;
            else
                mNameDotGeneralName = PROP_GENERALNAME;
            mConfig = config;

            int numGNs = mConfig.getInteger(PROP_NUM_GENERALNAMES);

            if (numGNs < 0) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                                new String[] {
                                        PROP_NUM_GENERALNAMES + "=" + numGNs,
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
                nameDot = name + DOT;
            params.addElement(
                    nameDot + PROP_NUM_GENERALNAMES + '=' + DEF_NUM_GENERALNAMES);
            for (int i = 0; i < DEF_NUM_GENERALNAMES; i++) {
                GeneralNameConfig.getDefaultParams(
                        nameDot + PROP_GENERALNAME + i, isValueConfigured, params);
            }
        }

        /**
         * Get instance params.
         */
        public void getInstanceParams(Vector<String> params) {
            params.addElement(
                    PROP_NUM_GENERALNAMES + '=' + mGenNameConfigs.length);
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
            info.addElement(PROP_NUM_GENERALNAMES + ";" + NUM_GENERALNAMES_INFO);
            for (int i = 0; i < DEF_NUM_GENERALNAMES; i++) {
                GeneralNameConfig.getExtendedPluginInfo(
                        nameDot + PROP_GENERALNAME + i, isValueConfigured, info);
            }
        }

    }

    static public class GeneralNamesAsConstraintsConfig extends GeneralNamesConfig implements
            IGeneralNamesAsConstraintsConfig {
        public GeneralNamesAsConstraintsConfig(
                String name,
                IConfigStore config,
                boolean isValueConfigured,
                boolean isPolicyEnabled)
                throws EBaseException {
            super(name, config, isValueConfigured, isPolicyEnabled);
        }

        protected GeneralNameConfig newGeneralNameConfig(
                String name, IConfigStore config,
                boolean isValueConfigured, boolean isPolicyEnabled)
                throws EBaseException {
            return new GeneralNameAsConstraintsConfig(name, config,
                    isValueConfigured, isPolicyEnabled);
        }
    }

    /**
     * convenience class for policies use.
     */
    static public class GeneralNameConfig implements IGeneralNameConfig {
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
                mNameDot = mName + DOT;
                mNameDotChoice = mNameDot + PROP_GENNAME_CHOICE;
                mNameDotValue = mNameDot + PROP_GENNAME_VALUE;
            } else {
                mNameDot = "";
                mNameDotChoice = PROP_GENNAME_CHOICE;
                mNameDotValue = PROP_GENNAME_VALUE;
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
                choice = mConfig.getString(PROP_GENNAME_CHOICE);
                mGenNameChoice = check_GeneralNameChoice(choice);
            } else {
                choice = mConfig.getString(PROP_GENNAME_CHOICE, "");
                if (choice.length() > 0 && !choice.equals("null")) {
                    mGenNameChoice = check_GeneralNameChoice(choice);
                }
            }
            if (mIsValueConfigured) {
                if (mIsPolicyEnabled) {
                    mValue = mConfig.getString(PROP_GENNAME_VALUE);
                    mGeneralName = formGeneralName(mGenNameChoice, mValue);
                } else {
                    mValue = mConfig.getString(PROP_GENNAME_VALUE, "");
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
            return form_GeneralName(choice, value);
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
            Debug.trace("GeneralnameConfig getDefaultParams");
            params.addElement(nameDot + PROP_GENNAME_CHOICE + "=");
            if (isValueConfigured)
                params.addElement(nameDot + PROP_GENNAME_VALUE + "=");
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
                    nameDot + PROP_GENNAME_CHOICE + ";" + GENNAME_CHOICE_INFO);
            if (isValueConfigured)
                info.addElement(
                        nameDot + PROP_GENNAME_VALUE + ";" + GENNAME_VALUE_INFO);
        }
    }

    /**
     * convenience class for policies use.
     */
    static public class GeneralNameAsConstraintsConfig extends GeneralNameConfig implements
            IGeneralNameAsConstraintsConfig {

        public GeneralNameAsConstraintsConfig(
                String name,
                IConfigStore config,
                boolean isValueConfigured,
                boolean isPolicyEnabled)
                throws EBaseException {
            super(name, config, isValueConfigured, isPolicyEnabled);
        }

        public GeneralName getGeneralName() {
            return mGeneralName;
        }

        /**
         * Form a general name from the value string.
         */
        public GeneralName formGeneralName(String choice, String value)
                throws EBaseException {
            return form_GeneralNameAsConstraints(choice, value);
        }
    }

    public static class SubjAltNameGN extends GeneralNameUtil.GeneralNameConfig implements ISubjAltNameConfig {
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
            GeneralNameUtil.GeneralNameConfig.getDefaultParams(name, false, params);
        }

        public static void getExtendedPluginInfo(String name, Vector<String> params) {
            String nameDot = "";

            if (name != null && name.length() > 0)
                nameDot = name + ".";
            params.addElement(nameDot + PROP_REQUEST_ATTR + ";" + REQUEST_ATTR_INFO);
            GeneralNameUtil.GeneralNameConfig.getExtendedPluginInfo(name, false, params);
        }
    }
}
