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
package com.netscape.cms.publish.publishers;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.TimeZone;
import java.util.Vector;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import netscape.ldap.LDAPConnection;

import org.mozilla.jss.util.Base64OutputStream;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.ILdapPublisher;
import com.netscape.cmsutil.util.Utils;

/**
 * This publisher writes certificate and CRL into
 * a directory.
 *
 * @version $Revision$, $Date$
 */
public class FileBasedPublisher implements ILdapPublisher, IExtendedPluginInfo {
    private static final String PROP_DIR = "directory";
    private static final String PROP_DER = "Filename.der";
    private static final String PROP_B64 = "Filename.b64";
    private static final String PROP_LNK = "latestCrlLink";
    private static final String PROP_GMT = "timeStamp";
    private static final String PROP_EXT = "crlLinkExt";
    private static final String PROP_ZIP = "zipCRLs";
    private static final String PROP_LEV = "zipLevel";
    private IConfigStore mConfig = null;
    private String mDir = null;
    private ILogger mLogger = CMS.getLogger();
    private String mCrlIssuingPointId;
    protected boolean mDerAttr = true;
    protected boolean mB64Attr = false;
    protected boolean mLatestCRL = false;
    protected boolean mZipCRL = false;
    protected String mTimeStamp = null;
    protected String mLinkExt = null;
    protected int mZipLevel = 9;

    public void setIssuingPointId(String crlIssuingPointId) {
        mCrlIssuingPointId = crlIssuingPointId;
    }

    /**
     * Returns the implementation name.
     */
    public String getImplName() {
        return "FileBasedPublisher";
    }

    /**
     * Returns the description of the ldap publisher.
     */

    public String getDescription() {
        return "This publisher writes the Certificates and CRLs into files.";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_DIR
                        + ";string;Directory in which to put the files (absolute path or relative path to cert-* instance directory).",
                PROP_DER + ";boolean;Store certificates or CRLs into *.der files.",
                PROP_B64 + ";boolean;Store certificates or CRLs into *.b64 files.",
                PROP_GMT
                        + ";choice(LocalTime,GMT);Use local time or GMT to time stamp CRL file name with CRL's 'thisUpdate' field.",
                PROP_LNK
                        + ";boolean;Generate link to the latest binary CRL. It requires '" + PROP_DER
                        + "' to be enabled.",
                PROP_EXT
                        + ";string;Name extension used by link to the latest CRL. Default name extension is 'der'.",
                PROP_ZIP + ";boolean;Generate compressed CRLs.",
                PROP_LEV + ";choice(0,1,2,3,4,5,6,7,8,9);Set compression level from 0 to 9.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ldappublish-publisher-filepublisher",
                IExtendedPluginInfo.HELP_TEXT
                        +
                        ";Stores the certificates or CRLs into files. Certificate is named as cert-<serialno>.der or *.b64, and CRL is named as <IssuingPoint>-<thisUpdate-time>.der or *.b64."
        };

        return params;
    }

    /**
     * Returns the current instance parameters.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();
        String dir = "";
        String ext = "";

        try {
            dir = mConfig.getString(PROP_DIR);
        } catch (EBaseException e) {
        }
        try {
            ext = mConfig.getString(PROP_EXT);
        } catch (EBaseException e) {
        }
        try {
            mTimeStamp = mConfig.getString(PROP_GMT);
        } catch (EBaseException e) {
        }
        try {
            mZipLevel = mConfig.getInteger(PROP_LEV, 9);
        } catch (EBaseException e) {
        }
        try {
            if (mTimeStamp == null || (!mTimeStamp.equals("GMT")))
                mTimeStamp = "LocalTime";
            v.addElement(PROP_DIR + "=" + dir);
            v.addElement(PROP_DER + "=" + mConfig.getBoolean(PROP_DER, true));
            v.addElement(PROP_B64 + "=" + mConfig.getBoolean(PROP_B64, false));
            v.addElement(PROP_GMT + "=" + mTimeStamp);
            v.addElement(PROP_LNK + "=" + mConfig.getBoolean(PROP_LNK, false));
            v.addElement(PROP_EXT + "=" + ext);
            v.addElement(PROP_ZIP + "=" + mConfig.getBoolean(PROP_ZIP, false));
            v.addElement(PROP_LEV + "=" + mZipLevel);
        } catch (Exception e) {
        }
        return v;
    }

    /**
     * Returns the initial default parameters.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        v.addElement(PROP_DIR + "=");
        v.addElement(PROP_DER + "=true");
        v.addElement(PROP_B64 + "=false");
        v.addElement(PROP_GMT + "=LocalTime");
        v.addElement(PROP_LNK + "=false");
        v.addElement(PROP_EXT + "=");
        v.addElement(PROP_ZIP + "=false");
        v.addElement(PROP_LEV + "=9");
        return v;
    }

    /**
     * Initializes this plugin.
     */
    public void init(IConfigStore config) {
        mConfig = config;
        String dir = null;

        try {
            dir = mConfig.getString(PROP_DIR, null);
            mDerAttr = mConfig.getBoolean(PROP_DER, true);
            mB64Attr = mConfig.getBoolean(PROP_B64, false);
            mTimeStamp = mConfig.getString(PROP_GMT, "LocalTime");
            mLatestCRL = mConfig.getBoolean(PROP_LNK, false);
            mLinkExt = mConfig.getString(PROP_EXT, null);
            mZipCRL = mConfig.getBoolean(PROP_ZIP, false);
            mZipLevel = mConfig.getInteger(PROP_LEV, 9);
        } catch (EBaseException e) {
        }
        if (dir == null) {
            throw new RuntimeException("No Directory Specified");
        }

        // convert to forward slash
        dir = dir.replace('\\', '/');
        config.putString(PROP_DIR, dir);

        File dirCheck = new File(dir);

        if (dirCheck.isDirectory()) {
            mDir = dir;
        } else {
            // maybe it is relative path
            String mInstanceRoot = null;

            try {
                mInstanceRoot = CMS.getConfigStore().getString("instanceRoot");
            } catch (Exception e) {
                throw new RuntimeException("Invalid Instance Dir " + e);
            }
            dirCheck = new File(mInstanceRoot +
                        File.separator + dir);
            if (dirCheck.isDirectory()) {
                mDir = mInstanceRoot + File.separator + dir;
            } else {
                throw new RuntimeException("Invalid Directory " + dir);
            }
        }
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    private String[] getCrlNamePrefix(X509CRL crl, boolean useGMT) {
        String[] namePrefix = { "crl", "crl" };

        if (mCrlIssuingPointId != null && mCrlIssuingPointId.length() != 0) {
            namePrefix[0] = mCrlIssuingPointId;
            namePrefix[1] = mCrlIssuingPointId;
        }
        java.text.SimpleDateFormat format = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss");
        TimeZone tz = TimeZone.getTimeZone("GMT");
        if (useGMT)
            format.setTimeZone(tz);
        String timeStamp = format.format(crl.getThisUpdate()).toString();
        namePrefix[0] += "-" + timeStamp;
        if (((netscape.security.x509.X509CRLImpl) crl).isDeltaCRL()) {
            namePrefix[0] += "-delta";
            namePrefix[1] += "-delta";
        }

        return namePrefix;
    }

    private void createLink(String linkName, String fileName) {
        String cmd = "ln -s " + fileName + " " + linkName + ".new";
        if (com.netscape.cmsutil.util.Utils.exec(cmd)) {
            File oldLink = new File(linkName + ".old");
            if (oldLink.exists()) { // remove old link if exists
                oldLink.delete();
            }
            File link = new File(linkName);
            if (link.exists()) { // current link becomes an old link
                link.renameTo(new File(linkName + ".old"));
            }
            File newLink = new File(linkName + ".new");
            if (newLink.exists()) { // new link becomes current link
                newLink.renameTo(new File(linkName));
            }
            oldLink = new File(linkName + ".old");
            if (oldLink.exists()) { // remove a new old link
                oldLink.delete();
            }
        } else {
            CMS.debug("FileBasedPublisher:  createLink: '" + cmd + "' --- failed");
        }
    }

    /**
     * Publishs a object to the ldap directory.
     *
     * @param conn a Ldap connection
     *            (null if LDAP publishing is not enabled)
     * @param dn dn of the ldap entry to publish cert
     *            (null if LDAP publishing is not enabled)
     * @param object object to publish
     *            (java.security.cert.X509Certificate or,
     *            java.security.cert.X509CRL)
     */
    public void publish(LDAPConnection conn, String dn, Object object)
            throws ELdapException {
        CMS.debug("FileBasedPublisher: publish");

        try {
            if (object instanceof X509Certificate) {
                X509Certificate cert = (X509Certificate) object;
                BigInteger sno = cert.getSerialNumber();
                String name = mDir +
                        File.separator + "cert-" +
                        sno.toString();
                if (mDerAttr) {
                    FileOutputStream fos = null;
                    try {
                        String fileName = name + ".der";
                        fos = new FileOutputStream(fileName);
                        fos.write(cert.getEncoded());
                    } finally {
                        if (fos != null)
                            fos.close();
                    }
                }
                if (mB64Attr) {
                    String fileName = name + ".b64";
                    PrintStream ps = null;
                    Base64OutputStream b64 = null;
                    FileOutputStream fos = null;
                    try {
                        fos = new FileOutputStream(fileName);
                        ByteArrayOutputStream output = new ByteArrayOutputStream();
                        b64 = new Base64OutputStream(new PrintStream(new FilterOutputStream(output)));
                        b64.write(cert.getEncoded());
                        b64.flush();
                        ps = new PrintStream(fos);
                        ps.print(output.toString("8859_1"));
                    } finally {
                        if (ps != null) {
                            ps.close();
                        }
                        if (b64 != null) {
                            b64.close();
                        }
                        if (fos != null)
                            fos.close();
                    }
                }
            } else if (object instanceof X509CRL) {
                X509CRL crl = (X509CRL) object;
                String[] namePrefix = getCrlNamePrefix(crl, mTimeStamp.equals("GMT"));
                String baseName = mDir + File.separator + namePrefix[0];
                String tempFile = baseName + ".temp";
                ZipOutputStream zos = null;
                byte[] encodedArray = null;
                File destFile = null;
                String destName = null;
                File renameFile = null;

                if (mDerAttr) {
                    FileOutputStream fos = null;
                    try {
                        fos = new FileOutputStream(tempFile);
                        encodedArray = crl.getEncoded();
                        fos.write(encodedArray);
                    } finally {
                        if (fos != null)
                            fos.close();
                    }
                    if (mZipCRL) {
                        try {
                            zos = new ZipOutputStream(new FileOutputStream(baseName + ".zip"));
                            zos.setLevel(mZipLevel);
                            zos.putNextEntry(new ZipEntry(baseName + ".der"));
                            zos.write(encodedArray, 0, encodedArray.length);
                            zos.closeEntry();
                        } finally {
                            if (zos != null)
                                zos.close();
                        }
                    }
                    destName = baseName + ".der";
                    destFile = new File(destName);

                    if (destFile.exists()) {
                        destFile.delete();
                    }
                    renameFile = new File(tempFile);
                    renameFile.renameTo(destFile);

                    if (mLatestCRL) {
                        String linkExt = ".";
                        if (mLinkExt != null && mLinkExt.length() > 0) {
                            linkExt += mLinkExt;
                        } else {
                            linkExt += "der";
                        }
                        String linkName = mDir + File.separator + namePrefix[1] + linkExt;
                        createLink(linkName, destName);
                        if (mZipCRL) {
                            linkName = mDir + File.separator + namePrefix[1] + ".zip";
                            createLink(linkName, baseName + ".zip");
                        }
                    }
                }

                // output base64 file
                if (mB64Attr == true) {
                    if (encodedArray == null)
                        encodedArray = crl.getEncoded();
                    FileOutputStream fos = null;
                    try {
                        fos = new FileOutputStream(tempFile);
                        fos.write(Utils.base64encode(encodedArray).getBytes());
                    } finally {
                        if (fos != null)
                            fos.close();
                    }
                    destName = baseName + ".b64";
                    destFile = new File(destName);

                    if (destFile.exists()) {
                        destFile.delete();
                    }
                    renameFile = new File(tempFile);
                    renameFile.renameTo(destFile);
                }
            }
        } catch (IOException e) {
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_FILE_PUBLISHER_ERROR", e.toString()));
        } catch (CertificateEncodingException e) {
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_FILE_PUBLISHER_ERROR", e.toString()));
        } catch (CRLException e) {
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_FILE_PUBLISHER_ERROR", e.toString()));
        }
    }

    /**
     * Unpublishs a object to the ldap directory.
     *
     * @param conn the Ldap connection
     *            (null if LDAP publishing is not enabled)
     * @param dn dn of the ldap entry to unpublish cert
     *            (null if LDAP publishing is not enabled)
     * @param object object to unpublish
     *            (java.security.cert.X509Certificate)
     */
    public void unpublish(LDAPConnection conn, String dn, Object object)
            throws ELdapException {
        CMS.debug("FileBasedPublisher: unpublish");
        String name = mDir + File.separator;
        String fileName;

        if (object instanceof X509Certificate) {
            X509Certificate cert = (X509Certificate) object;
            BigInteger sno = cert.getSerialNumber();
            name += "cert-" + sno.toString();
        } else if (object instanceof X509CRL) {
            X509CRL crl = (X509CRL) object;
            String[] namePrefix = getCrlNamePrefix(crl, mTimeStamp.equals("GMT"));
            name += namePrefix[0];

            fileName = name + ".zip";
            File f = new File(fileName);
            f.delete();
        }
        fileName = name + ".der";
        File f = new File(fileName);
        f.delete();

        fileName = name + ".b64";
        f = new File(fileName);
        f.delete();
    }

    /**
     * returns the Der attribute where it'll be published.
     */
    public boolean getDerAttr() {
        return mDerAttr;
    }

    /**
     * returns the B64 attribute where it'll be published.
     */
    public boolean getB64Attr() {
        return mB64Attr;
    }
}
