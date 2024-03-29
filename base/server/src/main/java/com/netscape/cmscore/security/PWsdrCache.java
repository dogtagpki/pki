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
package com.netscape.cmscore.security;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import org.mozilla.jss.SecretDecoderRing.Decryptor;
import org.mozilla.jss.SecretDecoderRing.Encryptor;
import org.mozilla.jss.SecretDecoderRing.KeyManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.util.Base64OutputStream;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;

/*
 * A class for managing passwords in the SDR password cache
 *
 * @author Christina Fu
 * @version $Revision$, $Date$
 */
public class PWsdrCache {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PWsdrCache.class);

    public static final String PROP_PWC_TOKEN_NAME = "pwcTokenname";
    public static final String PROP_PWC_KEY_ID = "pwcKeyid";
    public static final String PROP_PWC_NICKNAME = "sso_key";

    protected EngineConfig engineConfig;
    private String mPWcachedb = null;
    // mTool tells if this is called from the PasswordCache tool
    private boolean mIsTool = false;
    private byte[] mKeyID = null;
    private String mTokenName = null;
    private CryptoToken mToken = null;

    // for CMSEngine
    public PWsdrCache() {
    }

    public EngineConfig getEngineConfig() {
        return engineConfig;
    }

    public void setEngineConfig(EngineConfig engineConfig) {
        this.engineConfig = engineConfig;
    }

    public void init() throws EBaseException {

        try {
            mPWcachedb = engineConfig.getString("pwCache");
            logger.debug("PWsdrCache: got pwCache file path from configstore");
        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("CMSCORE_SECURITY_GET_CONFIG"), e);
            // let it fall through
        }

        initToken();
        initKey();
    }

    private void initToken() throws EBaseException {

        if (mToken == null) {
            try {
                mTokenName = engineConfig.getString(PROP_PWC_TOKEN_NAME);
                logger.debug("PWsdrCache: pwcTokenname specified.  Use token for SDR key. tokenname= " + mTokenName);
                mToken = CryptoUtil.getKeyStorageToken(mTokenName);
            } catch (Exception e) {
                logger.error("PWsdrCache: " + e.getMessage(), e);
                throw new EBaseException(e);
            }
        }
    }

    // called from PWCBsdr or CMSEngine only
    private void initKey() throws EBaseException {

        if (mKeyID == null) {
            try {
                String keyID = engineConfig.getString(PROP_PWC_KEY_ID);
                logger.debug("PWsdrCache: retrieved PWC SDR key");
                mKeyID = base64Decode(keyID);

            } catch (Exception e) {
                logger.error("PWsdrCache: no pwcSDRKey specified", e);
                throw new EBaseException(e);
            }
        }
    }

    // for PasswordCache tool (isTool == true)
    // and installation wizard (isTool == false)
    // Do not use for PWCBsdr, since we don't want to mistakenly
    // generate SDR keys in case of configuration errors
    public PWsdrCache(String pwCache, String pwcTokenname, byte[] keyId,
                      boolean isTool) throws Exception {
        mPWcachedb = pwCache;
        mIsTool = isTool;
        mTokenName = pwcTokenname;

        if (keyId != null) {
            mKeyID = keyId;
        }

        mToken = CryptoUtil.getKeyStorageToken(mTokenName);
        logger.debug("PWsdrCache: token: " + mToken.getName());
    }

    public byte[] getKeyId() {
        return mKeyID;
    }

    public String getTokenName() {
        return mTokenName;
    }

    public void deleteUniqueNamedKey(String nickName)
            throws Exception {
        KeyManager km = new KeyManager(mToken);
        km.deleteUniqueNamedKey(nickName);
    }

    public byte[] generateSDRKey() throws Exception {
        return generateSDRKeyWithNickName(PROP_PWC_NICKNAME);
    }

    public byte[] generateSDRKeyWithNickName(String nickName)
            throws Exception {
        try {

            if (mIsTool != true) {
                // generate SDR key
                KeyManager km = new KeyManager(mToken);
                try {
                    // Bugscape Bug #54838:  Due to the CMS cloning feature,
                    //                       we must check for the presence of
                    //                       a uniquely named symmetric key
                    //                       prior to making an attempt to
                    //                       generate it!
                    //
                    if (!(km.uniqueNamedKeyExists(nickName))) {
                        mKeyID = km.generateUniqueNamedKey(nickName);
                    }
                } catch (TokenException e) {
                    logger.error("PWsdrCache: " + e.getMessage(), e);
                    throw e;
                }
            }
        } catch (Exception e) {
            logger.error("PWsdrCache: " + e.getMessage(), e);
            throw e;
        }
        return mKeyID;
    }

    public byte[] base64Decode(String s) throws IOException {
        byte[] d = Utils.base64decode(s);
        return d;
    }

    public static String base64Encode(byte[] bytes) throws IOException {
        // All this streaming is lame, but Base64OutputStream needs a
        // PrintStream
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (Base64OutputStream b64 = new Base64OutputStream(
                new PrintStream(new FilterOutputStream(output)))) {

            b64.write(bytes);
            b64.flush();

            // This is internationally safe because Base64 chars are
            // contained within 8859_1
            return output.toString("8859_1");
        }
    }

    // for PWCBsdr
    public PWsdrCache(String pwCache) throws EBaseException {
        mPWcachedb = pwCache;
        initToken();
        initKey();
    }

    public void addEntry(String tag, String pwd) throws EBaseException {
        addEntry(tag, pwd, (Hashtable<String, String>) null);
    }

    /*
     * Store passwd in pwcache.
     */
    public void addEntry(Hashtable<String, String> ht) throws EBaseException {
        addEntry((String) null, (String) null, ht);
    }

    /*
     * add passwd in pwcache.
     */
    public void addEntry(String tag, String pwd, Hashtable<String, String> tagPwds) throws EBaseException {
        StringBuffer stringToAdd = new StringBuffer();

        String bufs = null;

        if (tagPwds == null) {
            stringToAdd.append(tag + ":" + pwd + "\n");
        } else {
            Enumeration<String> enum1 = tagPwds.keys();

            while (enum1.hasMoreElements()) {
                tag = enum1.nextElement();
                pwd = tagPwds.get(tag);
                logger.debug("PWsdrCache: password tag: " + tag + " stored in " + mPWcachedb);

                stringToAdd.append(tag + ":" + pwd + "\n");
            }
        }

        String dcrypts = readPWcache();

        if (dcrypts != null) {
            // converts to Hashtable, replace if tag exists, add
            //                if tag doesn't exist
            Hashtable<String, String> ht = string2Hashtable(dcrypts);

            if (ht.containsKey(tag) == false) {
                logger.debug("PWsdrCache: adding new tag: " + tag);
                ht.put(tag, pwd);
            } else {
                logger.debug("PWsdrCache: replacing tag: " + tag);
                ht.put(tag, pwd);
            }
            bufs = hashtable2String(ht);
        } else {
            logger.debug("PWsdrCache: adding new tag: " + tag);
            bufs = stringToAdd.toString();
        }

        // write update to cache
        writePWcache(bufs);
    }

    /*
     * delete passwd in pwcache.
     */
    public void deleteEntry(String tag) throws EBaseException {
        String bufs = null;

        String dcrypts = readPWcache();

        if (dcrypts != null) {
            // converts to Hashtable, replace if tag exists, add
            //                if tag doesn't exist
            Hashtable<String, String> ht = string2Hashtable(dcrypts);

            if (!ht.containsKey(tag)) {
                logger.debug("PWsdrCache: tag: " + tag + " does not exist");
                return;
            }
            logger.debug("PWsdrCache: deleting tag: " + tag);
            ht.remove(tag);
            bufs = hashtable2String(ht);
        } else {
            logger.debug("PWsdrCache: password cache contains no tags");
            return;
        }

        // write update to cache
        writePWcache(bufs);
    }

    /*
     * reads and decrypts the pwcache.db content
     */
    public String readPWcache() throws EBaseException {
        logger.debug("PWsdrCache: about to read password cache");
        String dcrypts = null;
        Decryptor sdr = new Decryptor(mToken);

        // not used, but could used for debugging
        int totalRead = 0;
        FileInputStream inputs = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try {
            // for SDR -> read, decrypt, append, and write
            inputs = new FileInputStream(mPWcachedb);
            byte[] readbuf = new byte[2048]; // for now
            int numRead = 0;

            while ((numRead = inputs.read(readbuf)) != -1) {
                bos.write(readbuf, 0, numRead);
                totalRead += numRead;
            }

        } catch (FileNotFoundException e) {
            logger.error(CMS.getLogMessage("CMSCORE_SECURITY_PW_FILE", mPWcachedb, e.toString()), e);
            throw new EBaseException(e.toString() + ": " + mPWcachedb);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSCORE_SECURITY_PW_FILE", mPWcachedb, e.toString()), e);
            throw new EBaseException(e.toString() + ": " + mPWcachedb);

        } finally {
            if (inputs != null) {
                try {
                    inputs.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        if (totalRead > 0) {
            try {
                // decrypt it first to append
                byte[] dcryptb = sdr.decrypt(bos.toByteArray());

                dcrypts = new String(dcryptb, "UTF-8");
            } catch (Exception e) {
                logger.error(CMS.getLogMessage("CMSCORE_SECURITY_PW_DECRYPT", e.toString()), e);
                throw new EBaseException("password cache decrypt failed");
            }
        }

        return dcrypts;
    }

    /*
     * encrypts and writes the whole String buf into pwcache.db
     */
    public void writePWcache(String bufs) throws EBaseException {
        FileOutputStream outstream = null;
        try {
            Encryptor sdr = new Encryptor(mToken, mKeyID,
                                Encryptor.DEFAULT_ENCRYPTION_ALG);

            byte[] writebuf = null;

            try {
                // now encrypt it again
                writebuf = sdr.encrypt(bufs.getBytes("UTF-8"));
            } catch (Exception e) {
                logger.error(CMS.getLogMessage("CMSCORE_SECURITY_PW_ENCRYPT", e.toString()), e);
                throw new EBaseException("password cache encrypt failed", e);
            }

            File tmpPWcache = new File(mPWcachedb + ".tmp");

            if (tmpPWcache.exists()) {
                // it wasn't removed?
                if (!tmpPWcache.delete()) {
                    logger.warn("PWsdrCache: Could not delete the existing " + mPWcachedb + ".tmp file.");
                }
                tmpPWcache = new File(mPWcachedb + ".tmp");
            }
            outstream = new FileOutputStream(mPWcachedb + ".tmp");

            outstream.write(writebuf);


            File origFile = new File(mPWcachedb);

            try {
                if (Utils.isNT()) {
                    // NT is very picky on the path
                    Utils.exec("copy " +
                                tmpPWcache.getAbsolutePath().replace('/',
                                                                      '\\') +
                                " " +
                                origFile.getAbsolutePath().replace('/',
                                                                    '\\'));
                } else {
                    // Create a copy of the original file which
                    // preserves the original file permissions.
                    Utils.exec("cp -p " + tmpPWcache.getAbsolutePath() + " " +
                                origFile.getAbsolutePath());
                }

                // Remove the original file if and only if
                // the backup copy was successful.
                if (origFile.exists()) {
                    if (!Utils.isNT()) {
                        try {
                            Utils.exec("chmod 00660 " +
                                        origFile.getCanonicalPath());
                        } catch (IOException e) {
                            logger.warn("PWsdrCache: Unable to change file permissions: " + e.getMessage(), e);
                        }
                    }
                    if (!tmpPWcache.delete()) {
                        logger.warn("PWsdrCache: Could not delete the existing " + mPWcachedb + ".tmp file.");
                    }
                    logger.debug("PWsdrCache: operation completed for " + mPWcachedb);
                }
            } catch (Exception exx) {
                logger.error(CMS.getLogMessage("CMSCORE_SECURITY_PW_CACHE", exx.toString()), exx);
                throw new EBaseException(exx.toString() + ": " + mPWcachedb, exx);
            }

        } catch (FileNotFoundException e) {
            logger.error(CMS.getLogMessage("CMSCORE_SECURITY_PW_FILE", mPWcachedb, e.toString()), e);
            throw new EBaseException(e.toString() + ": " + mPWcachedb, e);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSCORE_SECURITY_PW_FILE", mPWcachedb, e.toString()), e);
            throw new EBaseException(e.toString() + ": " + mPWcachedb, e);

        } catch (Exception e) {
            logger.error(CMS.getLogMessage("CMSCORE_SECURITY_PW_FILE", mPWcachedb, e.toString()), e);
            throw new EBaseException(e.toString() + ": " + mPWcachedb, e);

        } finally {
            if (outstream != null) {
                try {
                    outstream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public String hashtable2String(Hashtable<String, String> ht) {
        Enumeration<String> enum1 = ht.keys();
        StringBuffer returnString = new StringBuffer();

        while (enum1.hasMoreElements()) {
            String tag = enum1.nextElement();
            String pwd = ht.get(tag);
            returnString.append(tag + ":" + pwd + "\n");
        }
        return returnString.toString();
    }

    public Hashtable<String, String> string2Hashtable(String cache) {
        Hashtable<String, String> ht = new Hashtable<>();

        // first, break into lines
        StringTokenizer st = new StringTokenizer(cache, "\n");

        while (st.hasMoreTokens()) {
            String line = st.nextToken();
            // break into tag:password format for each line
            int colonIdx = line.indexOf(":");

            if (colonIdx != -1) {
                String tag = line.substring(0, colonIdx);
                String passwd = line.substring(colonIdx + 1,
                        line.length());

                ht.put(tag.trim(), passwd.trim());
            } else {
                //invalid format...log or throw...later
            }
        }
        return ht;
    }

    /*
     * get password from cache.  This one supplies cache file name
     */
    public Password getEntry(String fileName, String tag) {
        mPWcachedb = fileName;
        return getEntry(tag);
    }

    /*
     * if tag found with pwd, return it
     * if tag not found, return null, which will cause it to give up
     */
    public Password getEntry(String tag) {
        Hashtable<String, String> pwTable = null;
        String pw = null;

        logger.debug("PWsdrCache: in getEntry, tag=" + tag);

        if (mPWcachedb == null) {
            logger.warn("PWsdrCache: mPWcachedb file path name is not initialized");
            return null;
        }

        String dcrypts = null;

        try {
            dcrypts = readPWcache();
        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("CMSCORE_SECURITY_PW_READ", e.toString()), e);
            return null;
        }

        if (dcrypts != null) {
            // parse the cache
            String cache = dcrypts;

            // this is created and destroyed at each use
            pwTable = string2Hashtable(cache);
            logger.debug("PWsdrCache: in getEntry, pw cache parsed");
            pw = pwTable.get(tag);
        }

        if (pw == null) {
            logger.warn(CMS.getLogMessage("CMSCORE_SECURITY_PW_TAG", tag));
            return null;
        }
        logger.debug("PWsdrCache: getEntry gotten password for " + tag);
        return new Password(pw.toCharArray());
    }

    //copied from IOUtil.java
    /**
     * Checks if this is NT.
     */
    public static boolean isNT() {
        return ((File.separator).equals("\\"));
    }

    public static boolean exec(String cmd) throws IOException {
        String cmds[] = null;

        if (isNT()) {
            // NT
            cmds = new String[3];
            cmds[0] = "cmd";
            cmds[1] = "/c";
            cmds[2] = cmd;
        } else {
            // UNIX
            cmds = new String[3];
            cmds[0] = "/bin/sh";
            cmds[1] = "-c";
            cmds[2] = cmd;
        }
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(cmds);
            process.waitFor();
        } catch (IOException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return process.exitValue() == 0;
    }

    /*
     * list passwds in pwcache.
     */
    public boolean pprint() {
        String dcrypts = null;

        try {
            dcrypts = readPWcache();
        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("CMSCORE_SECURITY_PW_READ", e.toString()), e);
            return false;
        }

        logger.debug("PWsdrCache: ----- Password Cache Content -----");

        if (dcrypts != null) {
            // first, break into lines
            StringTokenizer st = new StringTokenizer(dcrypts, "\n");

            while (st.hasMoreTokens()) {
                String line = st.nextToken();
                // break into tag:password format for each line
                int colonIdx = line.indexOf(":");

                if (colonIdx != -1) {
                    String tag = line.substring(0, colonIdx);
                    String passwd = line.substring(colonIdx + 1,
                            line.length());

                    logger.debug("PWsdrCache: " + tag.trim() + " : " + passwd.trim());
                } else {
                    //invalid format...log or throw...later
                    logger.warn("PWsdrCache: invalid format");
                }
            }
        } // else print nothing
        return true;
    }
}
