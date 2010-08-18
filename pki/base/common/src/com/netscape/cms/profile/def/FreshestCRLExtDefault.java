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


import java.io.*;
import java.security.cert.*;
import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;

import netscape.security.x509.*;
import netscape.security.extensions.*;
import netscape.security.util.*;
import com.netscape.cms.profile.common.*;


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

    private static final int DEF_NUM_POINTS = 5;

    public FreshestCRLExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_CRL_DISTRIBUTION_POINTS);

        addConfigName(CONFIG_CRITICAL);
        int num = getNumPoints();

        for (int i = 0; i < num; i++) {
            addConfigName(CONFIG_POINT_TYPE + i);
            addConfigName(CONFIG_POINT_NAME + i);
            addConfigName(CONFIG_ISSUER_TYPE + i);
            addConfigName(CONFIG_ISSUER_NAME + i);
            addConfigName(CONFIG_ENABLE + i);
        }
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);

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
        return num;
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

            if(ext == null)  {
                populate(locale,info);
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

                Vector v = parseRecords(value);
                int size = v.size();
              
                boolean critical = ext.isCritical();
                int i = 0;

                for (; i < size; i++) {
                    NameValuePairs nvps = (NameValuePairs) v.elementAt(i);
                    Enumeration names = nvps.getNames();
                    String pointType = null;
                    String pointValue = null;
                    String issuerType = null;
                    String issuerValue = null;
                    String enable = null;
                    CRLDistributionPoint cdp = new CRLDistributionPoint();

                    while (names.hasMoreElements()) {
                        String name1 = (String) names.nextElement();

                        if (name1.equals(POINT_TYPE)) {
                            pointType = nvps.getValue(name1);
                        } else if (name1.equals(POINT_NAME)) {
                            pointValue = nvps.getValue(name1);
                        } else if (name1.equals(ISSUER_TYPE)) {
                            issuerType = nvps.getValue(name1);
                        } else if (name1.equals(ISSUER_NAME)) {
                            issuerValue = nvps.getValue(name1);
                        } else if (name1.equals(ENABLE)) {
                            enable = nvps.getValue(name1);
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

                gen.addElement(parseGeneralName(type,value));
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

                gen.addElement(parseGeneralName(type,value));
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

        if(ext == null)
        {
            try {
                populate(locale,info);

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

            StringBuffer sb = new StringBuffer();

            Vector recs = new Vector();
            int num = getNumPoints();

            for (int i = 0; i < num; i++) {
                NameValuePairs pairs = null;

                if (i < ext.getNumPoints()) {
                    CRLDistributionPoint p = ext.getPointAt(i); 
                    GeneralNames gns = p.getFullName();

                    pairs = buildGeneralNames(gns, p);
                    recs.addElement(pairs);
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

        pairs.add(POINT_TYPE, "");
        pairs.add(POINT_NAME, "");
        pairs.add(ISSUER_TYPE, "");
        pairs.add(ISSUER_NAME, "");
        pairs.add(ENABLE, "false");
        return pairs;
    }

    protected NameValuePairs buildGeneralNames(GeneralNames gns, CRLDistributionPoint p)
        throws EPropertyException {

        NameValuePairs pairs = new NameValuePairs();

        RDN rdn = null;
        boolean hasFullName = false;

        pairs.add(ENABLE, "true");
        if (gns == null) {
            pairs.add(POINT_TYPE, "");
            pairs.add(POINT_NAME, "");
        } else {
            GeneralName gn = (GeneralName) gns.elementAt(0);

            if (gn != null) {
                hasFullName = true;
                int type = gn.getType();

                pairs.add(POINT_TYPE, getGeneralNameType(gn));
                pairs.add(POINT_NAME, getGeneralNameValue(gn));
            }
        }

        if (!hasFullName) {
            pairs.add(POINT_TYPE, GN_DIRECTORY_NAME);
            pairs.add(POINT_NAME, "");
        }

        gns = p.getCRLIssuer();

        if (gns == null) {
            pairs.add(ISSUER_TYPE, GN_DIRECTORY_NAME);
            pairs.add(ISSUER_NAME, "");
        } else {
            GeneralName gn = (GeneralName) gns.elementAt(0);

            if (gn != null) {
                hasFullName = true;
                int type = gn.getType();

                pairs.add(ISSUER_TYPE, getGeneralNameType(gn));
                pairs.add(ISSUER_NAME, getGeneralNameValue(gn));
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
