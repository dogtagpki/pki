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


import java.math.*;
import java.io.*;
import java.security.cert.*;
import java.util.*;
import netscape.ldap.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.publish.*;
import org.mozilla.jss.util.Base64OutputStream;

/** 
 * This publisher writes certificate and CRL into
 * a directory.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class FileBasedPublisher implements ILdapPublisher, IExtendedPluginInfo {
    private static final String PROP_DIR = "directory";
    private static final String PROP_DER = "Filename.der";
    private static final String PROP_B64 = "Filename.b64";
    private static final String PROP_LNK = "LatestCrlLink";
    private static final String PROP_EXT = "CrlLinkExt";
    private IConfigStore mConfig = null;
    private String mDir = null;
    private ILogger mLogger = CMS.getLogger();
    private String mcrlIssuingPointId;
    protected boolean mDerAttr = true;
    protected boolean mB64Attr = false;
    protected boolean mLatestCRL = false;
    protected String mLinkExt = null;

    public void setIssuingPointId(String crlIssuingPointId)
    {
        mcrlIssuingPointId = crlIssuingPointId;
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
                PROP_DIR + ";string;Directory in which to put the files (absolute path or relative path to cert-* instance directory)",
                PROP_DER + ";boolean;Store certificates or CRLs into *.der files",
                PROP_B64 + ";boolean;Store certificates or CRLs into *.b64 files",
                PROP_LNK + ";boolean;Generate link to the latest CRL",
                PROP_EXT + ";string;Name extension used by link to the latest CRL. Default name extension is 'der'",
                IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-ldappublish-publisher-filepublisher",
                IExtendedPluginInfo.HELP_TEXT +
                ";Stores the certificates or CRLs into files. Certificate is named as <IssuingPoint>-<serialno>.der, and CRL is named as *.der or *.b64."
            };

        return params;
    }

    /**
     * Returns the current instance parameters.
     */
    public Vector getInstanceParams() {
        Vector v = new Vector();
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
            v.addElement(PROP_DIR+"=" + dir);
            
            v.addElement(PROP_DER+"=" + mConfig.getBoolean(PROP_DER,true));
            v.addElement(PROP_B64+"=" +  mConfig.getBoolean(PROP_B64,false));
            v.addElement(PROP_LNK+"=" +  mConfig.getBoolean(PROP_LNK,false));

            v.addElement(PROP_EXT+"=" + ext);
        } catch (Exception e) {
        }
        return v;
    }

    /**
     * Returns the initial default parameters.
     */
    public Vector getDefaultParams() {
        Vector v = new Vector();

        v.addElement(PROP_DIR+"=");
        v.addElement(PROP_DER+"=true");
        v.addElement(PROP_B64+"=false");
        v.addElement(PROP_LNK+"=false");
        v.addElement(PROP_EXT+"=");
        return v;
    }

    /**
     * Initializes this plugin.
     */
    public void init(IConfigStore config) {
        mConfig = config;
        String dir = null;
        String ext = null;

        try {
            dir = mConfig.getString(PROP_DIR, null);
            mDerAttr = mConfig.getBoolean(PROP_DER, true);
            mB64Attr = mConfig.getBoolean(PROP_B64, false);
            mLatestCRL = mConfig.getBoolean(PROP_LNK, false);
            mLinkExt = mConfig.getString(PROP_EXT, null);
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

    /**
     * Publishs a object to the ldap directory.
     * 
     * @param conn a Ldap connection 
     *        (null if LDAP publishing is not enabled)
     * @param dn dn of the ldap entry to publish cert
     *        (null if LDAP publishing is not enabled)
     * @param object object to publish
     *        (java.security.cert.X509Certificate or,
     *         java.security.cert.X509CRL)
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
                if (mDerAttr)
                {
                    String fileName = name + ".der";
                    FileOutputStream fos = new FileOutputStream(fileName);
                    fos.write(cert.getEncoded());
                    fos.close();
                }
                if (mB64Attr)
                {
                    String fileName = name + ".b64";
                    FileOutputStream fos = new FileOutputStream(fileName);
                    ByteArrayOutputStream output = new ByteArrayOutputStream();
                    Base64OutputStream b64 =
                        new Base64OutputStream(new PrintStream(new FilterOutputStream(output)));
                    b64.write(cert.getEncoded());
                    b64.flush();
                    (new PrintStream(fos)).print(output.toString("8859_1"));
                    fos.close();
                }
            } else if (object instanceof X509CRL) {
                X509CRL crl = (X509CRL) object;
                java.text.SimpleDateFormat format = new java.text.SimpleDateFormat("yyMMddHHmmss");
                TimeZone tz = TimeZone.getTimeZone("GMT");
                format.setTimeZone(tz);
                String GMTTime = "20" + format.format(crl.getThisUpdate()) ;
                String prefix;
                String deltaNumber = null;
                if(mcrlIssuingPointId!=null && mcrlIssuingPointId.length()!=0)
                {
                    com.netscape.certsrv.ca.ICertificateAuthority ca = 
                        (com.netscape.certsrv.ca.ICertificateAuthority)CMS.getSubsystem(CMS.SUBSYSTEM_CA);
                    com.netscape.certsrv.ca.ICRLIssuingPoint currentIssuingPoint =  
                        ca.getCRLIssuingPoint(mcrlIssuingPointId);
                    if(currentIssuingPoint.isDeltaCRLEnabled()){
                        deltaNumber = currentIssuingPoint.getCRLNumber().toString();
                    }
                    prefix = mcrlIssuingPointId;
                }else
                    prefix = "crl";
        
                String baseName = mDir + File.separator + prefix + "-" + GMTTime;
                if(deltaNumber!=null && deltaNumber.length()!=0)
                    baseName = baseName + "." + deltaNumber;
                String tempFile = baseName + ".temp";
                FileOutputStream fos;
                byte [] encodedArray = null;
                File destFile = null;
                String destName = null;
                File renameFile = null; 
                if(mDerAttr==true)
                {
                fos = new FileOutputStream(
                        tempFile);
                encodedArray = crl.getEncoded();
                fos.write(encodedArray);
                fos.close();
                destName = baseName + ".der";
                destFile = new File(destName);
                
                if(destFile.exists())
                    destFile.delete();
                renameFile = new File(tempFile);
                renameFile.renameTo(destFile);

                if (mLatestCRL) {
                    String linkExt = ".";
                    if (mLinkExt != null && mLinkExt.length() > 0) {
                        linkExt += mLinkExt;
                    } else {
                        linkExt += "der";
                    }
                    String linkName = mDir + File.separator + prefix + linkExt;
                    String cmd = "ln -s " + destName + " " + linkName + ".new";
                    CMS.debug("FileBasedPublisher: cmd: " + cmd);
                    if (com.netscape.cmsutil.util.Utils.exec(cmd)) {
                        File oldLink = new File(linkName + ".old");
                        if (oldLink.exists()) {
                            oldLink.delete();
                        }
                        File link = new File(linkName);
                        if (link.exists()) {
                            link.renameTo(new File(linkName + ".old"));
                        }
                        File newLink = new File(linkName + ".new");
                        if (newLink.exists()) {
                            newLink.renameTo(new File(linkName));
                        }
                        oldLink = new File(linkName + ".old");
                        if (oldLink.exists()) {
                            oldLink.delete();
                        }
                    } else {
                        CMS.debug("FileBasedPublisher: cmd: " + cmd + " --- failed");
                    }
                }
                }
                
                // output base64 file
                if(mB64Attr==true)
                {
                if (encodedArray ==null)
                    encodedArray = crl.getEncoded();
                   
                ByteArrayOutputStream os = new ByteArrayOutputStream();

                 fos = new FileOutputStream(tempFile);
                fos.write(com.netscape.osutil.OSUtil.BtoA(encodedArray).getBytes());
                fos.close();
                destName = baseName + ".b64";
                destFile = new File(destName);
                
                if(destFile.exists())
                    destFile.delete();
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
     *        (null if LDAP publishing is not enabled)
     * @param dn dn of the ldap entry to unpublish cert
     *        (null if LDAP publishing is not enabled)
     * @param object object to unpublish 
     *        (java.security.cert.X509Certificate)
     */
    public void unpublish(LDAPConnection conn, String dn, Object object)
        throws ELdapException {
        CMS.debug("FileBasedPublisher: unpublish");
        String name = mDir + File.separator;
        if (object instanceof X509Certificate) {
            X509Certificate cert = (X509Certificate) object;
            BigInteger sno = cert.getSerialNumber();
            name += "cert-" + sno.toString();
        } else if (object instanceof X509CRL) {
            X509CRL crl = (X509CRL) object;
            name += "crl-" + crl.getThisUpdate().getTime();
        }
        String fileName = name + ".der";
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
