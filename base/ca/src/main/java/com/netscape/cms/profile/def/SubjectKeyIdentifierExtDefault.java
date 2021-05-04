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

import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This class implements an enrollment default policy
 * that populates a subject key identifier extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class SubjectKeyIdentifierExtDefault extends EnrollExtDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SubjectKeyIdentifierExtDefault.class);

    public static final String CONFIG_CRITICAL = "critical";
    public static final String CONFIG_USE_SKI_IF_IN_REQUEST = "useSKIFromCertRequest";

    public static final String VAL_CRITICAL = "critical";
    public static final String VAL_KEY_ID = "keyid";
    public static final String CONFIG_MD = "messageDigest";
    public static final String VAL_MD = "messageDigest";
    public static final String DEF_CONFIG_MDS = "SHA-1,SHA-256,SHA-384,SHA-512";
    public static final String MD_LABEL="Message digest";
    public static final String USE_SKI_LABEL="Use SKI From Cert Request";
    public static final String VAL_USE_SKI_IF_IN_REQUEST = "useSKIFromCertRequest";

    public SubjectKeyIdentifierExtDefault() {
        super();

        logger.debug("SubjectKeyIdentifierExtDefault: adding config name. " + CONFIG_MD);
        addConfigName(CONFIG_MD);
        addConfigName(CONFIG_USE_SKI_IF_IN_REQUEST);
        logger.debug("SubjectKeyIdentifierExtDefault: done adding config name. " + CONFIG_MD);
        addValueName(VAL_CRITICAL);
        addValueName(VAL_KEY_ID);

        addValueName(VAL_MD);
        addValueName(VAL_USE_SKI_IF_IN_REQUEST);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) { /* testms */
        if (name.equals(CONFIG_MD)) {
            return new Descriptor(IDescriptor.CHOICE, DEF_CONFIG_MDS,
                    "SHA-1",
                    MD_LABEL);
        } else if (name.equals(CONFIG_USE_SKI_IF_IN_REQUEST)) {
            return new Descriptor(IDescriptor.BOOLEAN,null,"false",USE_SKI_LABEL);
        }
        else {
            return null;
        }
    }


    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_KEY_ID)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_ID"));
        } else if (name.equals(VAL_MD)) {
           return new Descriptor(IDescriptor.STRING,
                   IDescriptor.READONLY,
                   null,
                   MD_LABEL);
        } else if (name.equals(VAL_USE_SKI_IF_IN_REQUEST)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale,  "CMS_PROFILE_USE_SKI_IN_CSR"));
        }
        else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_CRITICAL)) {
            // read-only; do nothing
        } else if (name.equals(VAL_KEY_ID)) {
            // read-only; do nothing
        } else if (name.equals(VAL_MD)) {
            // read-only; do nothing
            logger.debug("value: " + value );
        } else if (name.equals(VAL_USE_SKI_IF_IN_REQUEST)) {
            logger.debug("value: " + value );

        }
        else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        SubjectKeyIdentifierExtension ext =
                (SubjectKeyIdentifierExtension) getExtension(
                        PKIXExtensions.SubjectKey_Id.toString(), info);

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
                    (SubjectKeyIdentifierExtension) getExtension(
                            PKIXExtensions.SubjectKey_Id.toString(), info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_KEY_ID)) {
            ext =
                    (SubjectKeyIdentifierExtension) getExtension(
                            PKIXExtensions.SubjectKey_Id.toString(), info);

            if (ext == null) {
                return null;
            }
            KeyIdentifier kid = null;

            try {
                kid = (KeyIdentifier)
                        ext.get(SubjectKeyIdentifierExtension.KEY_ID);
            } catch (IOException e) {
                logger.error("SubjectKeyIdentifierExtDefault::getValue() key ID is null: " + e.getMessage(), e);
                throw new EPropertyException(CMS.getUserMessage(locale,
                                                                  "CMS_INVALID_PROPERTY",
                                                                  name));
            }
            return toHexString(kid.getIdentifier());
        } else if (name.equals(VAL_MD)) {
            String alg = getConfig(CONFIG_MD);

            if (alg == null || alg.length() == 0) {
                alg = "SHA-1";
            }
            return alg;
        } else if (name.equals(VAL_USE_SKI_IF_IN_REQUEST)) {
            return getConfig(CONFIG_USE_SKI_IF_IN_REQUEST,"false");
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                    locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_SUBJECT_KEY_ID_EXT");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {

        // See if we have a SKI extenrion in the request already

        CertificateExtensions extensions = null;

        extensions = request.getExtDataInCertExts(EnrollProfile.REQUEST_EXTENSIONS);

        SubjectKeyIdentifierExtension ext = createExtension(info, extensions);

        addExtension(PKIXExtensions.SubjectKey_Id.toString(), ext, info);
    }

    public SubjectKeyIdentifierExtension createExtension(X509CertInfo info, CertificateExtensions extensions) {

        //Check to see if we care if the cert request contains a SKI extension
        boolean useSKIFromRequest = Boolean.valueOf(getConfig(CONFIG_USE_SKI_IF_IN_REQUEST, "false")).booleanValue();
        org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension keyIdExt = null;

        if (extensions != null && useSKIFromRequest) {
            try {
                keyIdExt = (org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension) extensions
                        .get(SubjectKeyIdentifierExtension.NAME);
            } catch (IOException e1) {
                keyIdExt = null;
            }
        }

        KeyIdentifier kid = null;

        //If we already have a SKI in the request use it.
        if (keyIdExt != null) {
            try {
                kid = (KeyIdentifier) keyIdExt.get(SubjectKeyIdentifierExtension.KEY_ID);
            } catch (IOException e) {
                kid = null;
            }

            //If grabbing it from the CSR somehow fails, go ahead and try to create a new one.

            if(kid == null) {
                kid = getKeyIdentifier(info);
            }

        } else {
            //Construct our own SKI as previously normal procedure.
            kid = getKeyIdentifier(info);
        }

        if (kid == null) {
            logger.error("SubjectKeyIdentifierExtDefault: KeyIdentifier not found");
            return null;
        }
        SubjectKeyIdentifierExtension ext = null;

        //Always use the criticality called for in the profile, possibly over riding anything
        //present in the SKI optionally within the request.

        boolean critical = Boolean.valueOf(getConfig(CONFIG_CRITICAL)).booleanValue();

        try {
            ext = new SubjectKeyIdentifierExtension(critical, kid.getIdentifier());
        } catch (IOException e) {
            logger.warn("SubjectKeyIdentifierExtDefault: createExtension " + e.getMessage(), e);
        }
        return ext;
    }

    public KeyIdentifier getKeyIdentifier(X509CertInfo info) {
        String method = "SubjectKeyIdentifierExtDefault: getKeyIdentifier: ";
        try {

            String configHashAlg = getConfig(CONFIG_MD);

            logger.debug(method + " configured hash alg: " + configHashAlg);
            CertificateX509Key infokey = (CertificateX509Key)
                    info.get(X509CertInfo.KEY);
            X509Key key = (X509Key) infokey.get(CertificateX509Key.KEY);

            // "SHA-1" is default for CryptoUtil.generateKeyIdentifier.
            // you could specify different algorithm with the alg parameter
            // like this:
            //byte[] hash = CryptoUtil.generateKeyIdentifier(key.getKey(), "SHA-256");

            byte[] hash = null;

            if (configHashAlg != null && configHashAlg.length() != 0) {
                logger.debug(method + " generating hash with alg: " + configHashAlg);
                hash = CryptoUtil.generateKeyIdentifier(key.getKey(), configHashAlg);
            } else {
                logger.debug(method + " generating hash with default alg: SHA-1");
                hash = CryptoUtil.generateKeyIdentifier(key.getKey());
            }

            if (hash == null) {
                logger.error(method + "CryptoUtil.generateKeyIdentifier returns null");
                return null;
            }
            return new KeyIdentifier(hash);
        } catch (Exception e) {
            logger.warn(method + e.getMessage(), e);
        }
        return null;
    }
}
