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
import java.util.StringTokenizer;

import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNameInterface;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.IssuerAlternativeNameExtension;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates a issuer alternative name extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class IssuerAltNameExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "issuerAltNameExtCritical";
    public static final String CONFIG_TYPE = "issuerAltExtType";
    public static final String CONFIG_PATTERN = "issuerAltExtPattern";

    public static final String VAL_CRITICAL = "issuerAltNameExtCritical";
    public static final String VAL_GENERAL_NAMES = "issuerAltNames";

    public IssuerAltNameExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_GENERAL_NAMES);

        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_TYPE);
        addConfigName(CONFIG_PATTERN);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(CONFIG_TYPE)) {
            return new Descriptor(IDescriptor.CHOICE,
                    "RFC822Name,DNSName,DirectoryName,EDIPartyName,URIName,IPAddress,OIDName",
                    "RFC822Name",
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_ISSUER_ALT_NAME_TYPE"));
        } else if (name.equals(CONFIG_PATTERN)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_ISSUER_ALT_NAME_PATTERN"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_GENERAL_NAMES)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_GENERAL_NAMES"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            IssuerAlternativeNameExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext =
                        (IssuerAlternativeNameExtension)
                        getExtension(PKIXExtensions.IssuerAlternativeName_Id.toString(), info);

            if (ext == null) {
                try {
                    populate(null, info);

                } catch (EProfileException e) {
                    throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
                }

            }

            if (name.equals(VAL_CRITICAL)) {
                ext =
                        (IssuerAlternativeNameExtension)
                        getExtension(PKIXExtensions.IssuerAlternativeName_Id.toString(), info);

                if (ext == null) {
                    // it is ok, the extension is never populated or delted
                    return;
                }
                boolean critical = Boolean.valueOf(value).booleanValue();

                ext.setCritical(critical);
            } else if (name.equals(VAL_GENERAL_NAMES)) {
                ext =
                        (IssuerAlternativeNameExtension)
                        getExtension(PKIXExtensions.IssuerAlternativeName_Id.toString(), info);

                if (ext == null) {
                    // it is ok, the extension is never populated or delted
                    return;
                }
                if (value.equals("")) {
                    // if value is empty, do not add this extension
                    deleteExtension(PKIXExtensions.IssuerAlternativeName_Id.toString(), info);
                    return;
                }
                GeneralNames gn = new GeneralNames();
                StringTokenizer st = new StringTokenizer(value, "\r\n");

                while (st.hasMoreTokens()) {
                    String gname = st.nextToken();

                    GeneralNameInterface n = parseGeneralName(gname);
                    if (n != null) {
                        gn.addElement(n);
                    }
                }
                ext.set(IssuerAlternativeNameExtension.ISSUER_NAME, gn);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
            replaceExtension(
                    PKIXExtensions.IssuerAlternativeName_Id.toString(),
                    ext, info);
        } catch (IOException e) {
            CMS.debug("IssuerAltNameExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } catch (EProfileException e) {
            CMS.debug("IssuerAltNameExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        try {
            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            IssuerAlternativeNameExtension ext =
                    (IssuerAlternativeNameExtension)
                    getExtension(PKIXExtensions.IssuerAlternativeName_Id.toString(), info);

            if (ext == null) {

                try {
                    populate(null, info);

                } catch (EProfileException e) {
                    throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
                }

            }

            if (name.equals(VAL_CRITICAL)) {
                ext =
                        (IssuerAlternativeNameExtension)
                        getExtension(PKIXExtensions.IssuerAlternativeName_Id.toString(), info);

                if (ext == null) {
                    return null;
                }
                if (ext.isCritical()) {
                    return "true";
                } else {
                    return "false";
                }
            } else if (name.equals(VAL_GENERAL_NAMES)) {
                ext =
                        (IssuerAlternativeNameExtension)
                        getExtension(PKIXExtensions.IssuerAlternativeName_Id.toString(), info);
                if (ext == null) {
                    return "";
                }

                GeneralNames names = (GeneralNames)
                        ext.get(IssuerAlternativeNameExtension.ISSUER_NAME);
                StringBuffer sb = new StringBuffer();
                Enumeration<GeneralNameInterface> e = names.elements();

                while (e.hasMoreElements()) {
                    GeneralName gn = (GeneralName) e.nextElement();

                    if (!sb.toString().equals("")) {
                        sb.append("\r\n");
                    }
                    sb.append(toGeneralNameString(gn));
                }
                return sb.toString();
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } catch (IOException e) {
            CMS.debug("IssuerAltNameExtDefault: getValue " +
                    e.toString());
        }
        return null;
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_PATTERN),
                getConfig(CONFIG_TYPE)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_ISSUER_ALT_NAME_EXT", params);
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        IssuerAlternativeNameExtension ext = null;

        try {
            ext = createExtension(request);

        } catch (IOException e) {
            CMS.debug("IssuerAltNameExtDefault: populate " + e.toString());
        }
        addExtension(PKIXExtensions.IssuerAlternativeName_Id.toString(),
                ext, info);
    }

    public IssuerAlternativeNameExtension createExtension(IRequest request)
            throws IOException {
        IssuerAlternativeNameExtension ext = null;

        try {
            ext = new IssuerAlternativeNameExtension();
        } catch (Exception e) {
            CMS.debug(e.toString());
            throw new IOException(e.toString());
        }
        boolean critical = Boolean.valueOf(
                getConfig(CONFIG_CRITICAL)).booleanValue();
        String pattern = getConfig(CONFIG_PATTERN);

        if (!pattern.equals("")) {
            GeneralNames gn = new GeneralNames();

            String gname = "";

            if (request != null) {
                gname = mapPattern(request, pattern);
            }

            gn.addElement(parseGeneralName(
                    getConfig(CONFIG_TYPE) + ":" + gname));
            ext.set(IssuerAlternativeNameExtension.ISSUER_NAME, gn);
        }
        ext.setCritical(critical);
        return ext;
    }
}
