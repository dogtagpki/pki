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
import java.util.Locale;

import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.x509.NSCCommentExtension;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements an enrollment default policy
 * that populates a Netscape comment extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class NSCCommentExtDefault extends EnrollExtDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSCCommentExtDefault.class);

    public static final String CONFIG_CRITICAL = "nscCommentCritical";
    public static final String CONFIG_COMMENT = "nscCommentContent";

    public static final String VAL_CRITICAL = "nscCommentCritical";
    public static final String VAL_COMMENT = "nscCommentContent";

    public NSCCommentExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_COMMENT);

        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_COMMENT);
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(CONFIG_COMMENT)) {
            return new Descriptor(IDescriptor.STRING, null,
                    "Comment Here...",
                    CMS.getUserMessage(locale, "CMS_PROFILE_COMMENT"));
        } else {
            return null;
        }
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_COMMENT)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_COMMENT"));
        } else {
            return null;
        }
    }

    @Override
    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            NSCCommentExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ObjectIdentifier oid = NSCCommentExtension.OID;

            ext = (NSCCommentExtension)
                        getExtension(oid.toString(), info);

            if (ext == null) {
                populate(null, info);
            }

            if (name.equals(VAL_CRITICAL)) {

                ext = (NSCCommentExtension)
                        getExtension(oid.toString(), info);
                boolean val = Boolean.valueOf(value).booleanValue();

                if (ext == null) {
                    return;
                }
                ext.setCritical(val);
            } else if (name.equals(VAL_COMMENT)) {

                ext = (NSCCommentExtension)
                        getExtension(oid.toString(), info);

                if (ext == null) {
                    return;
                }
                boolean critical = ext.isCritical();

                if (value == null || value.equals(""))
                    ext = new NSCCommentExtension(critical, "");
                //                    throw new EPropertyException(name+" cannot be empty");
                else
                    ext = new NSCCommentExtension(critical, value);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(ext.getExtensionId().toString(), ext, info);
        } catch (IOException e) {
            logger.warn("NSCCommentExtDefault: setValue " + e.getMessage(), e);
        } catch (EProfileException e) {
            logger.warn("NSCCommentExtDefault: setValue " + e.getMessage(), e);
        }
    }

    @Override
    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        NSCCommentExtension ext = null;

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        ObjectIdentifier oid = NSCCommentExtension.OID;

        ext = (NSCCommentExtension)
                    getExtension(oid.toString(), info);

        if (ext == null) {
            try {
                populate(null, info);

            } catch (EProfileException e) {
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            }

        }

        if (name.equals(VAL_CRITICAL)) {

            ext = (NSCCommentExtension)
                    getExtension(oid.toString(), info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_COMMENT)) {

            ext = (NSCCommentExtension)
                    getExtension(oid.toString(), info);

            if (ext == null)
                return "";

            String comment = ext.getComment();

            if (comment == null)
                comment = "";

            return comment;
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    @Override
    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_COMMENT)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_NS_COMMENT_EXT", params);
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        NSCCommentExtension ext = createExtension();

        addExtension(ext.getExtensionId().toString(), ext, info);
    }

    public NSCCommentExtension createExtension() {
        NSCCommentExtension ext = null;

        try {
            boolean critical = getConfigBoolean(CONFIG_CRITICAL);
            String comment = getConfig(CONFIG_COMMENT);

            if (comment == null || comment.equals(""))
                ext = new NSCCommentExtension(critical, "");
            else
                ext = new NSCCommentExtension(critical, comment);
        } catch (Exception e) {
            logger.warn("NSCCommentExtension: createExtension " + e.getMessage(), e);
        }
        return ext;
    }
}
