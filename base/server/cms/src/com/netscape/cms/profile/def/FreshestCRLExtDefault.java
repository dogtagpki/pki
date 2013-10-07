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
package com.netscape.cms.profile.def;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CRLDistributionPoint;
import netscape.security.x509.FreshestCRLExtension;
import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.GeneralNamesException;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates Freshest CRL extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class FreshestCRLExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "freshestCRLCritical";
    public static final String CONFIG_NUM_POINTS = "freshestCRLPointNum";
    public static final String CONFIG_POINT_TYPE = "freshestCRLPointType_";
    public static final String CONFIG_POINT_NAME = "freshestCRLPointName_";
    public static final String CONFIG_ISSUER_TYPE = "freshestCRLPointIssuerType_";
    public static final String CONFIG_ISSUER_NAME = "freshestCRLPointIssuerName_";
    public static final String CONFIG_ENABLE = "freshestCRLPointEnable_";

    public static final String VAL_CRITICAL = "freshestCRLCritical";
    public static final String VAL_CRL_DISTRIBUTION_POINTS =
            "freshestCRLPointsValue";

    private static final String POINT_TYPE = "Point Type";
    private static final String POINT_NAME = "Point Name";
    private static final String ISSUER_TYPE = "Issuer Type";
    private static final String ISSUER_NAME = "Issuer Name";
    private static final String ENABLE = "Enable";

    private static final int DEF_NUM_POINTS = 1;
    private static final int MAX_NUM_POINTS = 100;

    public FreshestCRLExtDefault() {
        super();
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
        refreshConfigAndValueNames();
    }

    protected int getNumPoints() {
        int num = DEF_NUM_POINTS;
        String val = getConfig(CONFIG_NUM_POINTS);

        if (val != null) {
            try {
                num = Integer.parseInt(val);
            } catch (NumberFormatException e) {
                // ignore
            }
        }

        if (num >= MAX_NUM_POINTS)
            num = DEF_NUM_POINTS;

        return num;
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        int num = 0;
        if (name.equals(CONFIG_NUM_POINTS)) {
            try {
                num = Integer.parseInt(value);

                if (num >= MAX_NUM_POINTS || num < 0) {
                    throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_POINTS));
                }

            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_POINTS));
            }
        }
        super.setConfig(name, value);
    }

    public Enumeration<String> getConfigNames() {
        refreshConfigAndValueNames();
        return super.getConfigNames();
    }

    protected void refreshConfigAndValueNames() {
        //refesh our config name list

        super.refreshConfigAndValueNames();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_CRL_DISTRIBUTION_POINTS);

        addConfigName(CONFIG_CRITICAL);
        int num = getNumPoints();

        addConfigName(CONFIG_NUM_POINTS);
        for (int i = 0; i < num; i++) {
            addConfigName(CONFIG_POINT_TYPE + i);
            addConfigName(CONFIG_POINT_NAME + i);
            addConfigName(CONFIG_ISSUER_TYPE + i);
            addConfigName(CONFIG_ISSUER_NAME + i);
            addConfigName(CONFIG_ENABLE + i);
        }

    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.startsWith(CONFIG_POINT_TYPE)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_POINT_TYPE"));
        } else if (name.startsWith(CONFIG_POINT_NAME)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_POINT_NAME"));
        } else if (name.startsWith(CONFIG_ISSUER_TYPE)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_ISSUER_TYPE"));
        } else if (name.startsWith(CONFIG_ISSUER_NAME)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_ISSUER_NAME"));
        } else if (name.startsWith(CONFIG_ENABLE)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_ENABLE"));
        } else if (name.startsWith(CONFIG_NUM_POINTS)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NUM_DIST_POINTS"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_CRL_DISTRIBUTION_POINTS)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRL_DISTRIBUTION_POINTS"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            FreshestCRLExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext = (FreshestCRLExtension)
                        getExtension(FreshestCRLExtension.OID,
                                info);

            if (ext == null) {
                populate(locale, info);
            }

            if (name.equals(VAL_CRITICAL)) {
                ext = (FreshestCRLExtension)
                        getExtension(FreshestCRLExtension.OID,
                                info);
                boolean val = Boolean.valueOf(value).booleanValue();

                ext.setCritical(val);
            } else if (name.equals(VAL_CRL_DISTRIBUTION_POINTS)) {
                ext = (FreshestCRLExtension)
                        getExtension(FreshestCRLExtension.OID,
                                info);

                Vector<NameValuePairs> v = parseRecords(value);
                int size = v.size();

                boolean critical = ext.isCritical();
                int i = 0;

                for (; i < size; i++) {
                    NameValuePairs nvps = v.elementAt(i);
                    String pointType = null;
                    String pointValue = null;
                    String issuerType = null;
                    String issuerValue = null;
                    String enable = null;
                    CRLDistributionPoint cdp = new CRLDistributionPoint();

                    for (String name1 : nvps.keySet()) {

                        if (name1.equals(POINT_TYPE)) {
                            pointType = nvps.get(name1);
                        } else if (name1.equals(POINT_NAME)) {
                            pointValue = nvps.get(name1);
                        } else if (name1.equals(ISSUER_TYPE)) {
                            issuerType = nvps.get(name1);
                        } else if (name1.equals(ISSUER_NAME)) {
                            issuerValue = nvps.get(name1);
                        } else if (name1.equals(ENABLE)) {
                            enable = nvps.get(name1);
                        }
                    }

                    if (enable != null && enable.equals("true")) {
                        if (pointType != null)
                            addCRLPoint(locale, cdp, pointType, pointValue);
                        if (issuerType != null)
                            addIssuer(locale, cdp, issuerType, issuerValue);

                        // this is the first distribution point
                        if (i == 0) {
                            ext = new FreshestCRLExtension(cdp);
                            ext.setCritical(critical);
                        } else {
                            ext.addPoint(cdp);
                        }
                    }
                }
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(PKIXExtensions.FreshestCRL_Id.toString(),
                    ext, info);
        } catch (EProfileException e) {
            CMS.debug("FreshestCRLExtDefault: setValue " +
                    e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    private void addCRLPoint(Locale locale, CRLDistributionPoint cdp, String type,
            String value) throws EPropertyException {
        try {
            if (value == null || value.length() == 0)
                return;

            if (isGeneralNameType(type)) {
                GeneralNames gen = new GeneralNames();

                gen.addElement(parseGeneralName(type, value));
                cdp.setFullName(gen);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", type));
            }
        } catch (IOException e) {
            CMS.debug("FreshestCRLExtDefault: addCRLPoint " +
                    e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", type));
        } catch (GeneralNamesException e) {
            CMS.debug("FreshestCRLExtDefault: addCRLPoint " +
                    e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", type));
        }
    }

    private void addIssuer(Locale locale, CRLDistributionPoint cdp, String type,
            String value) throws EPropertyException {
        if (value == null || value.length() == 0)
            return;
        try {
            if (isGeneralNameType(type)) {
                GeneralNames gen = new GeneralNames();

                gen.addElement(parseGeneralName(type, value));
                cdp.setCRLIssuer(gen);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", type));
            }
        } catch (IOException e) {
            CMS.debug("FreshestCRLExtDefault: addIssuer " +
                    e.toString());
        } catch (GeneralNamesException e) {
            CMS.debug("FreshestCRLExtDefault: addIssuer " +
                    e.toString());
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        FreshestCRLExtension ext = null;

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        ext = (FreshestCRLExtension)
                    getExtension(FreshestCRLExtension.OID,
                            info);
        if (ext == null) {
            try {
                populate(locale, info);

            } catch (EProfileException e) {
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            }

        }

        if (name.equals(VAL_CRITICAL)) {
            ext = (FreshestCRLExtension)
                    getExtension(FreshestCRLExtension.OID,
                            info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_CRL_DISTRIBUTION_POINTS)) {
            ext = (FreshestCRLExtension)
                    getExtension(FreshestCRLExtension.OID,
                            info);

            if (ext == null)
                return "";

            Vector<NameValuePairs> recs = new Vector<NameValuePairs>();
            int num = getNumPoints();
            for (int i = 0; i < num; i++) {
                NameValuePairs pairs = null;

                if (i < ext.getNumPoints()) {
                    CRLDistributionPoint p = ext.getPointAt(i);
                    GeneralNames gns = p.getFullName();

                    pairs = buildGeneralNames(gns, p);
                } else {
                    pairs = buildEmptyGeneralNames();
                }
                recs.addElement(pairs);
            }

            return buildRecords(recs);
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    protected NameValuePairs buildEmptyGeneralNames() {
        NameValuePairs pairs = new NameValuePairs();

        pairs.put(POINT_TYPE, "");
        pairs.put(POINT_NAME, "");
        pairs.put(ISSUER_TYPE, "");
        pairs.put(ISSUER_NAME, "");
        pairs.put(ENABLE, "false");
        return pairs;
    }

    protected NameValuePairs buildGeneralNames(GeneralNames gns, CRLDistributionPoint p)
            throws EPropertyException {

        NameValuePairs pairs = new NameValuePairs();

        boolean hasFullName = false;

        pairs.put(ENABLE, "true");
        if (gns == null) {
            pairs.put(POINT_TYPE, "");
            pairs.put(POINT_NAME, "");
        } else {
            GeneralName gn = (GeneralName) gns.elementAt(0);

            if (gn != null) {
                hasFullName = true;

                pairs.put(POINT_TYPE, getGeneralNameType(gn));
                pairs.put(POINT_NAME, getGeneralNameValue(gn));
            }
        }

        if (!hasFullName) {
            pairs.put(POINT_TYPE, GN_DIRECTORY_NAME);
            pairs.put(POINT_NAME, "");
        }

        gns = p.getCRLIssuer();

        if (gns == null) {
            pairs.put(ISSUER_TYPE, GN_DIRECTORY_NAME);
            pairs.put(ISSUER_NAME, "");
        } else {
            GeneralName gn = (GeneralName) gns.elementAt(0);

            if (gn != null) {
                hasFullName = true;

                pairs.put(ISSUER_TYPE, getGeneralNameType(gn));
                pairs.put(ISSUER_NAME, getGeneralNameValue(gn));
            }
        }
        return pairs;
    }

    public String getText(Locale locale) {
        StringBuffer sb = new StringBuffer();
        int num = getNumPoints();

        for (int i = 0; i < num; i++) {
            sb.append("Record #");
            sb.append(i);
            sb.append("{");
            sb.append(POINT_TYPE + ":");
            sb.append(getConfig(CONFIG_POINT_TYPE + i));
            sb.append(",");
            sb.append(POINT_NAME + ":");
            sb.append(getConfig(CONFIG_POINT_NAME + i));
            sb.append(",");
            sb.append(ISSUER_TYPE + ":");
            sb.append(getConfig(CONFIG_ISSUER_TYPE + i));
            sb.append(",");
            sb.append(ISSUER_NAME + ":");
            sb.append(getConfig(CONFIG_ISSUER_NAME + i));
            sb.append(",");
            sb.append(ENABLE + ":");
            sb.append(getConfig(CONFIG_ENABLE + i));
            sb.append("}");
        }
        return CMS.getUserMessage(locale,
                "CMS_PROFILE_DEF_FRESHEST_CRL_EXT",
                getConfig(CONFIG_CRITICAL),
                sb.toString());
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        FreshestCRLExtension ext = createExtension(request);

        if (ext == null)
            return;
        addExtension(FreshestCRLExtension.OID, ext, info);
    }

    public FreshestCRLExtension createExtension(IRequest request) {
        FreshestCRLExtension ext = new FreshestCRLExtension();
        int num = 0;

        try {
            boolean critical = getConfigBoolean(CONFIG_CRITICAL);
            ext.setCritical(critical);

            num = getNumPoints();
            for (int i = 0; i < num; i++) {
                CRLDistributionPoint cdp = new CRLDistributionPoint();

                String enable = getConfig(CONFIG_ENABLE + i);
                String pointType = getConfig(CONFIG_POINT_TYPE + i);
                String pointName = getConfig(CONFIG_POINT_NAME + i);
                String issuerType = getConfig(CONFIG_ISSUER_TYPE + i);
                String issuerName = getConfig(CONFIG_ISSUER_NAME + i);

                if (enable != null && enable.equals("true")) {
                    if (pointType != null)
                        addCRLPoint(getLocale(request), cdp, pointType, pointName);
                    if (issuerType != null)
                        addIssuer(getLocale(request), cdp, issuerType, issuerName);

                    ext.addPoint(cdp);
                }
            }
        } catch (Exception e) {
            CMS.debug("FreshestCRLExtDefault: createExtension " +
                    e.toString());
        }

        return ext;
    }

    /**
     * Populates the request with this policy default.
     */
    private void populate(Locale locale, X509CertInfo info)
            throws EProfileException {
        FreshestCRLExtension ext = createExtension(locale);

        if (ext == null)
            return;
        addExtension(FreshestCRLExtension.OID, ext, info);
    }

    public FreshestCRLExtension createExtension(Locale locale) {
        FreshestCRLExtension ext = new FreshestCRLExtension();
        int num = 0;

        try {
            boolean critical = getConfigBoolean(CONFIG_CRITICAL);
            ext.setCritical(critical);

            num = getNumPoints();
            for (int i = 0; i < num; i++) {
                CRLDistributionPoint cdp = new CRLDistributionPoint();

                String enable = getConfig(CONFIG_ENABLE + i);
                String pointType = getConfig(CONFIG_POINT_TYPE + i);
                String pointName = getConfig(CONFIG_POINT_NAME + i);
                String issuerType = getConfig(CONFIG_ISSUER_TYPE + i);
                String issuerName = getConfig(CONFIG_ISSUER_NAME + i);

                if (enable != null && enable.equals("true")) {
                    if (pointType != null)
                        addCRLPoint(locale, cdp, pointType, pointName);
                    if (issuerType != null)
                        addIssuer(locale, cdp, issuerType, issuerName);

                    ext.addPoint(cdp);
                }
            }
        } catch (Exception e) {
            CMS.debug("FreshestCRLExtDefault: createExtension " +
                    e.toString());
        }

        return ext;
    }
}
