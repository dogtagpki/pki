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
package com.netscape.ca;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.extensions.AuthInfoAccessExtension;
import netscape.security.x509.AuthorityKeyIdentifierExtension;
import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLNumberExtension;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.DeltaCRLIndicatorExtension;
import netscape.security.x509.Extension;
import netscape.security.x509.FreshestCRLExtension;
import netscape.security.x509.HoldInstructionExtension;
import netscape.security.x509.InvalidityDateExtension;
import netscape.security.x509.IssuerAlternativeNameExtension;
import netscape.security.x509.IssuingDistributionPointExtension;
import netscape.security.x509.OIDMap;
import netscape.security.x509.PKIXExtensions;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotDefined;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ca.ICMSCRLExtension;
import com.netscape.certsrv.ca.ICMSCRLExtensions;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.crl.CMSIssuingDistributionPointExtension;
import com.netscape.cmscore.base.SubsystemRegistry;

public class CMSCRLExtensions implements ICMSCRLExtensions {
    public static final String PROP_ENABLE = "enable";
    public static final String PROP_EXTENSION = "extension";
    public static final String PROP_CLASS = "class";
    public static final String PROP_TYPE = "type";
    public static final String PROP_CRITICAL = "critical";
    public static final String PROP_CRL_EXT = "CRLExtension";
    public static final String PROP_CRL_ENTRY_EXT = "CRLEntryExtension";

    private ICRLIssuingPoint mCRLIssuingPoint = null;

    private IConfigStore mConfig = null;
    private IConfigStore mCRLExtConfig = null;

    private Vector<String> mCRLExtensionNames = new Vector<String>();
    private Vector<String> mCRLEntryExtensionNames = new Vector<String>();
    private Vector<String> mEnabledCRLExtensions = new Vector<String>();
    private Vector<String> mCriticalCRLExtensions = new Vector<String>();
    private Hashtable<String, String> mCRLExtensionClassNames = new Hashtable<String, String>();
    private Hashtable<String, String> mCRLExtensionIDs = new Hashtable<String, String>();

    private static final Vector<String> mDefaultCRLExtensionNames = new Vector<String>();
    private static final Vector<String> mDefaultCRLEntryExtensionNames = new Vector<String>();
    private static final Vector<String> mDefaultEnabledCRLExtensions = new Vector<String>();
    private static final Vector<String> mDefaultCriticalCRLExtensions = new Vector<String>();
    private static final Hashtable<String, String> mDefaultCRLExtensionClassNames = new Hashtable<String, String>();
    private static final Hashtable<String, String> mDefaultCRLExtensionIDs = new Hashtable<String, String>();

    private ILogger mLogger = CMS.getLogger();

    static {

        /* Default CRL Extensions */
        mDefaultCRLExtensionNames.addElement(AuthorityKeyIdentifierExtension.NAME);
        mDefaultCRLExtensionNames.addElement(IssuerAlternativeNameExtension.NAME);
        mDefaultCRLExtensionNames.addElement(CRLNumberExtension.NAME);
        mDefaultCRLExtensionNames.addElement(DeltaCRLIndicatorExtension.NAME);
        mDefaultCRLExtensionNames.addElement(IssuingDistributionPointExtension.NAME);
        mDefaultCRLExtensionNames.addElement(FreshestCRLExtension.NAME);
        mDefaultCRLExtensionNames.addElement(AuthInfoAccessExtension.NAME2);

        /* Default CRL Entry Extensions */
        mDefaultCRLEntryExtensionNames.addElement(CRLReasonExtension.NAME);
        //mDefaultCRLEntryExtensionNames.addElement(HoldInstructionExtension.NAME);
        mDefaultCRLEntryExtensionNames.addElement(InvalidityDateExtension.NAME);
        //mDefaultCRLEntryExtensionNames.addElement(CertificateIssuerExtension.NAME);

        /* Default Enabled CRL Extensions */
        mDefaultEnabledCRLExtensions.addElement(CRLNumberExtension.NAME);
        //mDefaultEnabledCRLExtensions.addElement(DeltaCRLIndicatorExtension.NAME);
        mDefaultEnabledCRLExtensions.addElement(CRLReasonExtension.NAME);
        mDefaultEnabledCRLExtensions.addElement(InvalidityDateExtension.NAME);

        /* Default Critical CRL Extensions */
        mDefaultCriticalCRLExtensions.addElement(DeltaCRLIndicatorExtension.NAME);
        mDefaultCriticalCRLExtensions.addElement(IssuingDistributionPointExtension.NAME);
        //mDefaultCriticalCRLExtensions.addElement(CertificateIssuerExtension.NAME);

        /* CRL extension IDs */
        mDefaultCRLExtensionIDs.put(PKIXExtensions.AuthorityKey_Id.toString(),
                AuthorityKeyIdentifierExtension.NAME);
        mDefaultCRLExtensionIDs.put(PKIXExtensions.IssuerAlternativeName_Id.toString(),
                IssuerAlternativeNameExtension.NAME);
        mDefaultCRLExtensionIDs.put(PKIXExtensions.CRLNumber_Id.toString(),
                CRLNumberExtension.NAME);
        mDefaultCRLExtensionIDs.put(PKIXExtensions.DeltaCRLIndicator_Id.toString(),
                DeltaCRLIndicatorExtension.NAME);
        mDefaultCRLExtensionIDs.put(PKIXExtensions.IssuingDistributionPoint_Id.toString(),
                IssuingDistributionPointExtension.NAME);
        mDefaultCRLExtensionIDs.put(PKIXExtensions.ReasonCode_Id.toString(),
                CRLReasonExtension.NAME);
        mDefaultCRLExtensionIDs.put(PKIXExtensions.HoldInstructionCode_Id.toString(),
                HoldInstructionExtension.NAME);
        mDefaultCRLExtensionIDs.put(PKIXExtensions.InvalidityDate_Id.toString(),
                InvalidityDateExtension.NAME);
        //mDefaultCRLExtensionIDs.put(PKIXExtensions.CertificateIssuer_Id.toString(),
        //                     CertificateIssuerExtension.NAME);
        mDefaultCRLExtensionIDs.put(PKIXExtensions.FreshestCRL_Id.toString(),
                FreshestCRLExtension.NAME);
        mDefaultCRLExtensionIDs.put(AuthInfoAccessExtension.ID.toString(),
                AuthInfoAccessExtension.NAME2);

        /* Class names */
        mDefaultCRLExtensionClassNames.put(AuthorityKeyIdentifierExtension.NAME,
                "com.netscape.cms.crl.CMSAuthorityKeyIdentifierExtension");
        mDefaultCRLExtensionClassNames.put(IssuerAlternativeNameExtension.NAME,
                "com.netscape.cms.crl.CMSIssuerAlternativeNameExtension");
        mDefaultCRLExtensionClassNames.put(CRLNumberExtension.NAME,
                "com.netscape.cms.crl.CMSCRLNumberExtension");
        mDefaultCRLExtensionClassNames.put(DeltaCRLIndicatorExtension.NAME,
                "com.netscape.cms.crl.CMSDeltaCRLIndicatorExtension");
        mDefaultCRLExtensionClassNames.put(IssuingDistributionPointExtension.NAME,
                "com.netscape.cms.crl.CMSIssuingDistributionPointExtension");
        mDefaultCRLExtensionClassNames.put(CRLReasonExtension.NAME,
                "com.netscape.cms.crl.CMSCRLReasonExtension");
        mDefaultCRLExtensionClassNames.put(HoldInstructionExtension.NAME,
                "com.netscape.cms.crl.CMSHoldInstructionExtension");
        mDefaultCRLExtensionClassNames.put(InvalidityDateExtension.NAME,
                "com.netscape.cms.crl.CMSInvalidityDateExtension");
        //mDefaultCRLExtensionClassNames.put(CertificateIssuerExtension.NAME,
        //        "com.netscape.cms.crl.CMSCertificateIssuerExtension");
        mDefaultCRLExtensionClassNames.put(FreshestCRLExtension.NAME,
                "com.netscape.cms.crl.CMSFreshestCRLExtension");
        mDefaultCRLExtensionClassNames.put(AuthInfoAccessExtension.NAME2,
                "com.netscape.cms.crl.CMSAuthInfoAccessExtension");

        try {
            OIDMap.addAttribute(DeltaCRLIndicatorExtension.class.getName(),
                    DeltaCRLIndicatorExtension.OID,
                    DeltaCRLIndicatorExtension.NAME);
        } catch (CertificateException e) {
        }
        try {
            OIDMap.addAttribute(HoldInstructionExtension.class.getName(),
                    HoldInstructionExtension.OID,
                    HoldInstructionExtension.NAME);
        } catch (CertificateException e) {
        }
        try {
            OIDMap.addAttribute(InvalidityDateExtension.class.getName(),
                    InvalidityDateExtension.OID,
                    InvalidityDateExtension.NAME);
        } catch (CertificateException e) {
        }
        try {
            OIDMap.addAttribute(FreshestCRLExtension.class.getName(),
                    FreshestCRLExtension.OID,
                    FreshestCRLExtension.NAME);
        } catch (CertificateException e) {
        }
    }

    /**
     * Constructs a CRL extensions for CRL issuing point.
     */
    public CMSCRLExtensions(ICRLIssuingPoint crlIssuingPoint, IConfigStore config) {
        boolean modifiedConfig = false;

        mConfig = config;
        mCRLExtConfig = config.getSubStore(PROP_EXTENSION);
        mCRLIssuingPoint = crlIssuingPoint;

        IConfigStore mFileConfig =
                SubsystemRegistry.getInstance().get("MAIN").getConfigStore();

        IConfigStore crlExtConfig = mFileConfig;
        StringTokenizer st = new StringTokenizer(mCRLExtConfig.getName(), ".");

        while (st.hasMoreTokens()) {
            String subStoreName = st.nextToken();
            IConfigStore newConfig = crlExtConfig.getSubStore(subStoreName);

            if (newConfig != null) {
                crlExtConfig = newConfig;
            }
        }

        if (crlExtConfig != null) {
            Enumeration<String> enumExts = crlExtConfig.getSubStoreNames();

            while (enumExts.hasMoreElements()) {
                String extName = enumExts.nextElement();
                IConfigStore extConfig = crlExtConfig.getSubStore(extName);

                if (extConfig != null) {
                    modifiedConfig |= getEnableProperty(extName, extConfig);
                    modifiedConfig |= getCriticalProperty(extName, extConfig);
                    modifiedConfig |= getTypeProperty(extName, extConfig);
                    modifiedConfig |= getClassProperty(extName, extConfig);
                }
            }

            if (modifiedConfig) {
                try {
                    mFileConfig.commit(true);
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_SAVE_CONF", e.toString()));
                }
            }
        }
    }

    private boolean getEnableProperty(String extName, IConfigStore extConfig) {
        boolean modifiedConfig = false;

        try {
            if (extConfig.getBoolean(PROP_ENABLE)) {
                mEnabledCRLExtensions.addElement(extName);
            }
        } catch (EPropertyNotFound e) {
            extConfig.putBoolean(PROP_ENABLE, mDefaultEnabledCRLExtensions.contains(extName));
            modifiedConfig = true;
            if (mDefaultEnabledCRLExtensions.contains(extName)) {
                mEnabledCRLExtensions.addElement(extName);
            }
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CRLEXTS_NO_ENABLE", extName,
                            mDefaultEnabledCRLExtensions.contains(extName) ? "true" : "false"));
        } catch (EPropertyNotDefined e) {
            extConfig.putBoolean(PROP_ENABLE, mDefaultEnabledCRLExtensions.contains(extName));
            modifiedConfig = true;
            if (mDefaultEnabledCRLExtensions.contains(extName)) {
                mEnabledCRLExtensions.addElement(extName);
            }
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CRLEXTS_UNDEFINE_ENABLE", extName,
                            mDefaultEnabledCRLExtensions.contains(extName) ? "true" : "false"));
        } catch (EBaseException e) {
            extConfig.putBoolean(PROP_ENABLE, mDefaultEnabledCRLExtensions.contains(extName));
            modifiedConfig = true;
            if (mDefaultEnabledCRLExtensions.contains(extName)) {
                mEnabledCRLExtensions.addElement(extName);
            }
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CRLEXTS_INVALID_ENABLE", extName,
                            mDefaultEnabledCRLExtensions.contains(extName) ? "true" : "false"));
        }
        return modifiedConfig;
    }

    private boolean getCriticalProperty(String extName, IConfigStore extConfig) {
        boolean modifiedConfig = false;

        try {
            if (extConfig.getBoolean(PROP_CRITICAL)) {
                mCriticalCRLExtensions.addElement(extName);
            }
        } catch (EPropertyNotFound e) {
            extConfig.putBoolean(PROP_CRITICAL, mDefaultCriticalCRLExtensions.contains(extName));
            modifiedConfig = true;
            if (mDefaultCriticalCRLExtensions.contains(extName)) {
                mCriticalCRLExtensions.addElement(extName);
            }
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CRLEXTS_NO_CRITICAL", extName,
                            mDefaultEnabledCRLExtensions.contains(extName) ? "true" : "false"));
        } catch (EPropertyNotDefined e) {
            extConfig.putBoolean(PROP_CRITICAL, mDefaultCriticalCRLExtensions.contains(extName));
            modifiedConfig = true;
            if (mDefaultCriticalCRLExtensions.contains(extName)) {
                mCriticalCRLExtensions.addElement(extName);
            }
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CRLEXTS_UNDEFINE_CRITICAL", extName,
                            mDefaultEnabledCRLExtensions.contains(extName) ? "true" : "false"));
        } catch (EBaseException e) {
            extConfig.putBoolean(PROP_CRITICAL, mDefaultCriticalCRLExtensions.contains(extName));
            modifiedConfig = true;
            if (mDefaultCriticalCRLExtensions.contains(extName)) {
                mCriticalCRLExtensions.addElement(extName);
            }
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_CA_CRLEXTS_INVALID_CRITICAL", extName,
                            mDefaultEnabledCRLExtensions.contains(extName) ? "true" : "false"));
        }
        return modifiedConfig;
    }

    private boolean getTypeProperty(String extName, IConfigStore extConfig) {
        boolean modifiedConfig = false;
        String extType = null;

        try {
            extType = extConfig.getString(PROP_TYPE);
            if (extType.length() > 0) {
                if (extType.equals(PROP_CRL_ENTRY_EXT)) {
                    mCRLEntryExtensionNames.addElement(extName);
                } else if (extType.equals(PROP_CRL_EXT)) {
                    mCRLExtensionNames.addElement(extName);
                } else {
                    if (mDefaultCRLEntryExtensionNames.contains(extName)) {
                        extConfig.putString(PROP_TYPE, PROP_CRL_ENTRY_EXT);
                        modifiedConfig = true;
                        mCRLEntryExtensionNames.addElement(extName);
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSCORE_CA_CRLEXTS_INVALID_EXT", extName, PROP_CRL_ENTRY_EXT));
                    } else if (mDefaultCRLExtensionNames.contains(extName)) {
                        extConfig.putString(PROP_TYPE, PROP_CRL_EXT);
                        modifiedConfig = true;
                        mCRLExtensionNames.addElement(extName);
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSCORE_CA_CRLEXTS_INVALID_EXT", extName, PROP_CRL_EXT));
                    } else {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_INVALID_EXT", extName, ""));
                    }
                }
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_UNDEFINE_EXT", extName));
            }
        } catch (EPropertyNotFound e) {
            if (mDefaultCRLEntryExtensionNames.contains(extName)) {
                extConfig.putString(PROP_TYPE, PROP_CRL_ENTRY_EXT);
                modifiedConfig = true;
            } else if (mDefaultCRLExtensionNames.contains(extName)) {
                extConfig.putString(PROP_TYPE, PROP_CRL_EXT);
                modifiedConfig = true;
            }
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_MISSING_EXT", extName));
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_INVALID_EXT", extName, ""));
        }
        return modifiedConfig;
    }

    private boolean getClassProperty(String extName, IConfigStore extConfig) {
        boolean modifiedConfig = false;
        String extClass = null;

        try {
            extClass = extConfig.getString(PROP_CLASS);
            if (extClass.length() > 0) {
                mCRLExtensionClassNames.put(extName, extClass);

                try {
                    @SuppressWarnings("unchecked")
                    Class<ICMSCRLExtension> crlExtClass = (Class<ICMSCRLExtension>) Class.forName(extClass);

                    if (crlExtClass != null) {
                        ICMSCRLExtension cmsCRLExt = crlExtClass.newInstance();

                        if (cmsCRLExt != null) {
                            String id = cmsCRLExt.getCRLExtOID();

                            if (id != null) {
                                mCRLExtensionIDs.put(id, extName);
                            }
                        }
                    }
                } catch (ClassCastException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_CRLEXTS_INCORRECT_CLASS", extClass, e.toString()));
                } catch (ClassNotFoundException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_FOUND", extClass, e.toString()));
                } catch (InstantiationException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_INST", extClass, e.toString()));
                } catch (IllegalAccessException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_ACCESS", extClass, e.toString()));
                }

            } else {
                if (mDefaultCRLExtensionClassNames.containsKey(extName)) {
                    extClass = mCRLExtensionClassNames.get(extName);
                    extConfig.putString(PROP_CLASS, extClass);
                    modifiedConfig = true;
                }
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_DEFINED", extName));
            }
        } catch (EPropertyNotFound e) {
            if (mDefaultCRLExtensionClassNames.containsKey(extName)) {
                extClass = mDefaultCRLExtensionClassNames.get(extName);
                extConfig.putString(PROP_CLASS, extClass);
                modifiedConfig = true;
            }
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_MISSING", extName));
        } catch (EBaseException e) {
            if (mDefaultCRLExtensionClassNames.containsKey(extName)) {
                extClass = mDefaultCRLExtensionClassNames.get(extName);
                extConfig.putString(PROP_CLASS, extClass);
                modifiedConfig = true;
            }
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_INVALID", extName));
        }
        return modifiedConfig;
    }

    public boolean isCRLExtension(String extName) {
        return mCRLExtensionNames.contains(extName);
    }

    public boolean isCRLEntryExtension(String extName) {
        return mCRLEntryExtensionNames.contains(extName);
    }

    public boolean isCRLExtensionEnabled(String extName) {
        return ((mCRLExtensionNames.contains(extName) || mCRLEntryExtensionNames.contains(extName)) && 
                mEnabledCRLExtensions.contains(extName));
    }

    public boolean isCRLExtensionCritical(String extName) {
        return mCriticalCRLExtensions.contains(extName);
    }

    public String getCRLExtensionName(String id) {
        String name = null;

        if (mCRLExtensionIDs.containsKey(id)) {
            name = mCRLExtensionIDs.get(id);
        }
        return name;
    }

    public Vector<String> getCRLExtensionNames() {
        return new Vector<String>(mCRLExtensionNames);
    }

    public Vector<String> getCRLEntryExtensionNames() {
        return new Vector<String>(mCRLEntryExtensionNames);
    }

    public void addToCRLExtensions(CRLExtensions crlExts, String extName, Extension ext) {
        if (mCRLExtensionClassNames.containsKey(extName)) {
            String name = mCRLExtensionClassNames.get(extName);

            try {
                @SuppressWarnings("unchecked")
                Class<ICMSCRLExtension> extClass = (Class<ICMSCRLExtension>) Class.forName(name);

                if (extClass != null) {
                    ICMSCRLExtension cmsCRLExt = extClass.newInstance();

                    if (cmsCRLExt != null) {
                        if (ext != null) {
                            if (isCRLExtensionCritical(extName) ^ ext.isCritical()) {
                                ext = cmsCRLExt.setCRLExtensionCriticality(
                                            ext, isCRLExtensionCritical(extName));
                            }
                        } else {
                            ext = cmsCRLExt.getCRLExtension(mCRLExtConfig.getSubStore(extName),
                                        mCRLIssuingPoint,
                                        isCRLExtensionCritical(extName));
                        }

                        if (crlExts != null && ext != null) {
                            crlExts.set(extName, ext);
                        }
                    }
                }
            } catch (ClassCastException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_INCORRECT_CLASS", name, e.toString()));
            } catch (ClassNotFoundException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_FOUND", name, e.toString()));
            } catch (InstantiationException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_INST", name, e.toString()));
            } catch (IllegalAccessException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_ACCESS", name, e.toString()));
            } catch (IOException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_ADD", name, e.toString()));
            }
        }
    }

    public NameValuePairs getConfigParams(String id) {
        NameValuePairs nvp = null;

        if (mCRLEntryExtensionNames.contains(id) ||
                mCRLExtensionNames.contains(id)) {
            nvp = new NameValuePairs();

            /*
             if (mCRLEntryExtensionNames.contains(id)) {
             nvp.add(Constants.PR_CRLEXT_IMPL_NAME, "CRLEntryExtension");
             } else {
             nvp.add(Constants.PR_CRLEXT_IMPL_NAME, "CRLExtension");
             }

             if (mCRLEntryExtensionNames.contains(id)) {
             nvp.add(PROP_TYPE, "CRLEntryExtension");
             } else {
             nvp.add(PROP_TYPE, "CRLExtension");
             }
             */

            if (mEnabledCRLExtensions.contains(id)) {
                nvp.put(PROP_ENABLE, Constants.TRUE);
            } else {
                nvp.put(PROP_ENABLE, Constants.FALSE);
            }
            if (mCriticalCRLExtensions.contains(id)) {
                nvp.put(PROP_CRITICAL, Constants.TRUE);
            } else {
                nvp.put(PROP_CRITICAL, Constants.FALSE);
            }

            if (mCRLExtensionClassNames.containsKey(id)) {
                String name = mCRLExtensionClassNames.get(id);

                if (name != null) {

                    try {
                        Class<?> extClass = Class.forName(name);

                        if (extClass != null) {
                            ICMSCRLExtension cmsCRLExt = (ICMSCRLExtension) extClass.newInstance();

                            if (cmsCRLExt != null) {
                                cmsCRLExt.getConfigParams(mCRLExtConfig.getSubStore(id), nvp);
                            }
                        }
                    } catch (ClassNotFoundException e) {
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_FOUND", name, e.toString()));
                    } catch (InstantiationException e) {
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_INST", name, e.toString()));
                    } catch (IllegalAccessException e) {
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSCORE_CA_CRLEXTS_CLASS_NOT_ACCESS", name, e.toString()));
                    }

                    int i = name.lastIndexOf('.');

                    if ((i > -1) && (i + 1 < name.length())) {
                        String idName = name.substring(i + 1);

                        if (idName != null) {
                            nvp.put(Constants.PR_CRLEXT_IMPL_NAME, idName);
                        }
                    }
                }
            }
        }
        return nvp;
    }

    public void setConfigParams(String id, NameValuePairs nvp, IConfigStore config) {
        ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
        String ipId = nvp.get("id");

        ICRLIssuingPoint ip = null;
        if (ipId != null && ca != null) {
            ip = ca.getCRLIssuingPoint(ipId);
        }

        for (String name : nvp.keySet()) {
            String value = nvp.get(name);

            if (name.equals(PROP_ENABLE)) {
                if (!(value.equals(Constants.TRUE) || value.equals(Constants.FALSE))) {
                    continue;
                }
                if (value.equals(Constants.TRUE)) {
                    if (!(mEnabledCRLExtensions.contains(id))) {
                        mEnabledCRLExtensions.addElement(id);
                    }
                }
                if (value.equals(Constants.FALSE)) {
                    mEnabledCRLExtensions.remove(id);
                }
            }

            if (name.equals(PROP_CRITICAL)) {
                if (!(value.equals(Constants.TRUE) || value.equals(Constants.FALSE))) {
                    continue;
                }
                if (value.equals(Constants.TRUE)) {
                    if (!(mCriticalCRLExtensions.contains(id))) {
                        mCriticalCRLExtensions.addElement(id);
                    }
                }
                if (value.equals(Constants.FALSE)) {
                    mCriticalCRLExtensions.remove(id);
                }
            }
            //Sync the onlyContainsCACerts with similar property in CRLIssuingPoint 
            //called caCertsOnly.
            if (name.equals(CMSIssuingDistributionPointExtension.PROP_CACERTS)) {
                NameValuePairs crlIssuingPointPairs = null;
                boolean crlCACertsOnly = false;

                boolean issuingDistPointExtEnabled = false;

                CMSCRLExtensions cmsCRLExtensions = (CMSCRLExtensions) ip.getCRLExtensions();
                if (cmsCRLExtensions != null) {
                    issuingDistPointExtEnabled =
                            cmsCRLExtensions.isCRLExtensionEnabled(IssuingDistributionPointExtension.NAME);
                }

                CMS.debug("issuingDistPointExtEnabled = " + issuingDistPointExtEnabled);

                if (!(value.equals(Constants.TRUE) || value.equals(Constants.FALSE))) {
                    continue;
                }

                //Get value of caCertsOnly from CRLIssuingPoint
                if ((ip != null) && (issuingDistPointExtEnabled == true)) {
                    crlCACertsOnly = ip.isCACertsOnly();
                    CMS.debug("CRLCACertsOnly is: " + crlCACertsOnly);
                    crlIssuingPointPairs = new NameValuePairs();

                }

                String newValue = "";
                boolean modifiedCRLConfig = false;
                //If the CRLCACertsOnly prop is false change it to true to sync.
                if (value.equals(Constants.TRUE) && (issuingDistPointExtEnabled == true)) {
                    if (crlCACertsOnly == false) {
                        CMS.debug(" value = true and CRLCACertsOnly is already false.");
                        crlIssuingPointPairs.put(Constants.PR_CA_CERTS_ONLY, Constants.TRUE);
                        newValue = Constants.TRUE;
                        ip.updateConfig(crlIssuingPointPairs);
                        modifiedCRLConfig = true;
                    }
                }

                //If the CRLCACertsOnly prop is true change it to false to sync.
                if (value.equals(Constants.FALSE) && (issuingDistPointExtEnabled == true)) {
                    crlIssuingPointPairs.put(Constants.PR_CA_CERTS_ONLY, Constants.FALSE);
                    if (ip != null) {
                        ip.updateConfig(crlIssuingPointPairs);
                        newValue = Constants.FALSE;
                        modifiedCRLConfig = true;
                    }
                }

                if (modifiedCRLConfig == true) {
                    //Commit to this CRL IssuingPoint's config store
                    ICertificateAuthority CA = (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
                    IConfigStore crlsSubStore = CA.getConfigStore();
                    crlsSubStore = crlsSubStore.getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
                    crlsSubStore = crlsSubStore.getSubStore(ipId);
                    try {
                        crlsSubStore.putString(Constants.PR_CA_CERTS_ONLY, newValue);
                        crlsSubStore.commit(true);
                    } catch (EBaseException e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CRLEXTS_SAVE_CONF", e.toString()));
                    }
                }
            }

            config.putString(name, value);
        }
    }

    public String getClassPath(String name) {
        Enumeration<String> enum1 = mCRLExtensionClassNames.elements();

        while (enum1.hasMoreElements()) {
            String extClassName = enum1.nextElement();

            if (extClassName != null) {
                int i = extClassName.lastIndexOf('.');

                if ((i > -1) && (i + 1 < extClassName.length())) {
                    String idName = extClassName.substring(i + 1);

                    if (idName != null) {
                        if (name.equals(idName)) {
                            return extClassName;
                        }
                    }
                }
            }
        }

        return null;
    }

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_CA, level,
                "CMSCRLExtension - " + msg);
    }
}
