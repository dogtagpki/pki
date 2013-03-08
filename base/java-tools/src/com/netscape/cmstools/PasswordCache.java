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
package com.netscape.cmstools;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.SecretDecoderRing.Decryptor;
import org.mozilla.jss.SecretDecoderRing.Encryptor;
import org.mozilla.jss.SecretDecoderRing.KeyManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.util.Base64OutputStream;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.util.Utils;

/**
 * Tool for interacting with the PWcache
 *
 * @version $Revision$, $Date$
 */

public class PasswordCache {

    /* These are the tags that identify various passwords
     * They should probably be converted instances of some
     * class so that we can expose an API to add additional
     * TAG's for use if I want to add a password for use
     * with my own authenticaion module
     */
    public static final String PROP_PWC_NICKNAME = "sso_key";
    public static final String PW_TAG_INTERNAL_LDAP_DB = "Internal LDAP Database";

    private static void usage() {
        System.out.println(
                "This tool has to be run from the same directory where pwcache.db file resides, normally <cms instance>/config directory, unless the file's full path is specified in the -c option..\nUsage: PasswordCache <SSO_PASSWORD> <-d cert/key db directory> <-h tokenName> <-P cert/key db prefix> <-c pwcache.db_file_full_path> <-k file containing Base64EncodedKeyID> <COMMAND> ...");
        System.out.println("  commands:");
        System.out.println("     'add <password_name> <password>'");
        System.out.println("     'change <password_name> <password>'");
        System.out.println("     'delete <password_name>'");
        System.out.println("     'rekey'");
        System.out.println("     'list'");
        System.out.println(
                "\nExample:\n\tPasswordCache thePassword1 -d /usr/netscape/servers/cms/alias -P cert-instance1-machine1- -c pwcache.db -k keyidFile list");
        System.exit(1);
    }

    private static boolean debugMode = false;

    public PasswordCache() {
    }

    private static void debug(String s) {
        if (debugMode == true)
            System.out.println("PasswordCache debug: " + s);
    }

    /**
     * clean up an argv by removing the trailing, empty arguments
     *
     * This is necessary to support the script wrapper which calls the
     * tool with arguments in quotes such as:
     * "$1" "$2"
     * if $2 is not specified, the empty arg "" gets passed, which causes
     * an error in the arg-count checking code.
     */
    private static String[] cleanArgs(String[] s) {
        int length;
        int i;

        length = s.length;
        debug("before cleanArgs argv length =" + length);

        for (i = length - 1; i >= 0; i--) {
            if (s[i].equals("")) {
                length--;
            } else {
                break;
            }
        }

        String[] new_av = new String[length];
        for (i = 0; i < length; i++) {
            new_av[i] = s[i];
            debug("arg " + i + " is " + new_av[i]);
        }
        debug("after cleanArgs argv length =" + length);

        return new_av;
    }

    public static byte[] base64Decode(String s) throws IOException {
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

    public static void main(String[] av) {
        // default path is "."
        String mPath = ".";
        String mTokenName = null;
        // default prefix is ""
        String mPrefix = "";
        String mKeyIdString = null;
        byte[] mKeyId = null;
        String mCacheFile = "pwcache.db";

        String pwdPath = null;
        String instancePath = null;
        String instanceName = null;

        String[] argv = cleanArgs(av);

        if (argv.length < 2) {
            usage();
        }

        String pw = argv[0];

        char[] testpw = pw.toCharArray();
        Password pass = new Password(testpw);

        String command = "";
        String aTag = "";
        String aPasswd = "";

        int i = 0;
        for (i = 1; i < argv.length; ++i) {
            if (argv[i].equals("-d")) {
                if (++i >= argv.length)
                    usage();
                mPath = argv[i];
            } else if (argv[i].equals("-h")) {
                if (++i >= argv.length)
                    usage();
                mTokenName = argv[i];
            } else if (argv[i].equals("-P")) {
                if (++i >= argv.length)
                    usage();
                mPrefix = argv[i];
            } else if (argv[i].equals("-c")) {
                if (++i >= argv.length)
                    usage();
                mCacheFile = argv[i];
            } else if (argv[i].equals("-k")) {
                if (++i >= argv.length)
                    usage();
                String keyFile = argv[i];
                BufferedReader r = null;
                try {
                    r = new BufferedReader(new FileReader(keyFile));
                    mKeyIdString = r.readLine();
                } catch (Exception e) {
                    System.out.println("Error: " + e.toString());
                    System.exit(1);
                } finally {
                    if (r != null) {
                        try {
                            r.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }

                if (mKeyIdString != null) {
                    try {
                        mKeyId = base64Decode(mKeyIdString);
                        debug("base64Decode of key id string successful");
                    } catch (IOException e) {
                        System.out.println("base64Decode of key id string failed");
                        System.exit(1);
                    }
                }
            } else {
                command = argv[i++];
                debug("command = " + command);

                if ((command.equals("add")) ||
                        (command.equals("change"))) {
                    aTag = argv[i++];
                    aPasswd = argv[i];
                    debug("command is " + command + " " + aTag + ":" + aPasswd);
                } else if (command.equals("delete")) {
                    aTag = argv[i];
                } else if (command.equals("list")) {
                } else if (command.equals("rekey")) {
                }
                break;
            }
        }

        try {
            // initialize CryptoManager
            System.out.println("cert/key prefix = " + mPrefix);
            System.out.println("cert/key db path = " + mPath);
            System.out.println("password cache file = " + mCacheFile);

            CryptoManager.InitializationValues vals =
                    new CryptoManager.InitializationValues(mPath, mPrefix,
                            mPrefix, "secmod.db");

            CryptoManager.initialize(vals);

            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = null;
            if (mTokenName == null) {
                token = cm.getInternalKeyStorageToken();
                System.out.println("token name = internal");
            } else {
                token = cm.getTokenByName(mTokenName);
                System.out.println("token name = " + mTokenName);
            }

            token.login(pass);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        // generating new key
        if (command.equals("rekey")) {
            System.out.println("generating new key...");
            PWsdrCache cache = null;
            try {
                // compose instance name
                File passwordCacheDB = new File(mCacheFile);
                pwdPath = passwordCacheDB.getAbsolutePath();
                int beginIndex = pwdPath.lastIndexOf("cert-");
                instancePath = pwdPath.substring(beginIndex);
                int endIndex = 0;
                endIndex = instancePath.lastIndexOf("config");
                instanceName = instancePath.substring(0, (endIndex - 1));

                cache = new PWsdrCache(mCacheFile, mTokenName, null, true);
                cache.deleteUniqueNamedKey(PROP_PWC_NICKNAME
                                          + " "
                                          + instanceName);
                byte[] newKeyId = cache.generateSDRKeyWithNickName(
                                                        PROP_PWC_NICKNAME
                                                                + " "
                                                                + instanceName);
                if (newKeyId != null) {
                    String newKeyIDString = base64Encode(newKeyId);
                    System.out.println("key generated successfully with key id = " +
                                       newKeyIDString);
                    System.out.println("Save the VALUE portion of this key id in a local file,");
                    System.out.println("and under variable \"pwcKeyid\" in CS.cfg !!");
                    System.out.println("If you have not already done so,");
                    System.out.println("remove the old pwcache.db and use this local file to add passwords.");
                    // job is done
                    System.exit(0);
                } else {
                    System.out.println("key expected to be generated but wasn't");
                    System.exit(1);
                }
            } catch (Exception e) {
                System.out.println(e.toString());
                System.exit(1);
            }
        }

        PWsdrCache cache = null;
        try {
            cache = new PWsdrCache(mCacheFile, mTokenName, mKeyId, true);
        } catch (Exception e) {
            System.out.println(e.toString());
            System.exit(1);
        }

        if ((command.equals("add")) || (command.equals("change"))) {
            // current key id must be specified
            if (mKeyId == null) {
                System.out.println("operation failed: no key id specified");
                System.exit(1);
            }

            try {
                System.out.println("adding " + aTag + ":" + aPasswd);
                cache.addEntry(aTag, aPasswd);
            } catch (Exception e) {
                System.out.println("--failed--" + e.toString());
            }
        } else if (command.equals("list")) {
            cache.pprint();
        } else if (command.equals("delete")) {
            // current key id must be specified
            if (mKeyId == null) {
                System.out.println("operation failed: no key id specified");
                System.exit(1);
            }

            try {
                cache.deleteEntry(aTag);
            } catch (Exception e) {
                System.out.println("User not found");
            }
        } else {
            System.out.println("Illegal command: " + command);
            System.exit(1);
        }
    }
}

/*
 * A class for managing passwords in the SDR password cache
 *
 * @author Christina Fu
 * @version $Revision$, $Date$
 */
class PWsdrCache {

    public static final String PROP_PWC_NICKNAME = "sso_key";

    private String mPWcachedb = null;
    private byte[] mKeyID = null;
    private String mTokenName = null;
    private CryptoToken mToken = null;

    // mTool tells if this is called from the PasswordCache tool
    private boolean mIsTool = false;

    // for PasswordCache tool (isTool == true)
    public PWsdrCache(String pwCache, String pwcTokenname, byte[] keyId,
                      boolean isTool) throws Exception {
        mPWcachedb = pwCache;
        mIsTool = isTool;
        mTokenName = pwcTokenname;
        CryptoManager cm = null;

        if (keyId != null) {
            mKeyID = keyId;
        }

        cm = CryptoManager.getInstance();
        if (mTokenName != null) {
            mToken = cm.getTokenByName(mTokenName);
            debug("PWsdrCache: mToken = " + mTokenName);
        } else {
            mToken = cm.getInternalKeyStorageToken();
            debug("PWsdrCache: mToken = internal");
        }
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
            if (mIsTool == true) {
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
                        debug("PWsdrCache: SDR key generated");
                    }
                } catch (TokenException e) {
                    log(0, "generateSDRKey() failed on " + e.toString());
                    throw e;
                }
            }
        } catch (Exception e) {
            log(0, e.toString());
            throw e;
        }
        return mKeyID;
    }

    public void addEntry(String tag, String pwd) throws IOException {
        addEntry(tag, pwd, (Hashtable<String, String>) null);
    }

    /*
     * Store passwd in pwcache.
     */
    public void addEntry(Hashtable<String, String> ht) throws IOException {
        addEntry((String) null, (String) null, ht);
    }

    /*
     * add passwd in pwcache.
     */
    public void addEntry(String tag, String pwd, Hashtable<String, String> tagPwds) throws IOException {
        System.out.println("PWsdrCache: in addEntry");
        StringBuffer stringToAdd = new StringBuffer();
        String bufs = null;

        if (tagPwds == null) {
            stringToAdd.append(tag + ":" + pwd + "\n");
        } else {
            Enumeration<String> enum1 = tagPwds.keys();

            while (enum1.hasMoreElements()) {
                tag = enum1.nextElement();
                pwd = tagPwds.get(tag);
                debug("password tag: " + tag + " stored in " + mPWcachedb);

                stringToAdd.append(tag + ":" + pwd + "\n");
            }
        }

        String dcrypts = readPWcache();
        System.out.println("PWsdrCache: after readPWcache()");
        if (dcrypts != null) {
            // converts to Hashtable, replace if tag exists, add
            //                if tag doesn't exist
            Hashtable<String, String> ht = string2Hashtable(dcrypts);

            if (ht.containsKey(tag) == false) {
                debug("adding new tag: " + tag);
                ht.put(tag, pwd);
            } else {
                debug("replacing tag: " + tag);
                ht.put(tag, pwd);
            }
            bufs = hashtable2String(ht);
        } else {
            debug("adding new tag: " + tag);
            bufs = stringToAdd.toString();
        }

        // write update to cache
        writePWcache(bufs);
    }

    /*
     * delete passwd in pwcache.
     */
    public void deleteEntry(String tag) throws IOException {
        String bufs = null;

        String dcrypts = readPWcache();

        if (dcrypts != null) {
            // converts to Hashtable, replace if tag exists, add
            //                if tag doesn't exist
            Hashtable<String, String> ht = string2Hashtable(dcrypts);

            if (ht.containsKey(tag) == false) {
                debug("tag: " + tag + " does not exist");
                return;
            } else {
                debug("deleting tag: " + tag);
                ht.remove(tag);
            }
            bufs = hashtable2String(ht);
        } else {
            debug("password cache contains no tags");
            return;
        }

        // write update to cache
        writePWcache(bufs);
    }

    /*
     * reads and decrypts the pwcache.db content
     */
    public String readPWcache() throws IOException {
        debug("about to read password cache");
        String dcrypts = null;
        if (mToken == null) {
            debug("mToken is null");
            throw new IOException("token must be specified");
        }

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
            System.out.println("Failed for file " + mPWcachedb + " " + e.toString());
            throw new IOException(e.toString() + ": " + mPWcachedb);
        } catch (IOException e) {
            System.out.println("Failed for file " + mPWcachedb + " " + e.toString());
            throw new IOException(e.toString() + ": " + mPWcachedb);
        } finally {
            if (inputs != null)
                inputs.close();
        }

        if (totalRead > 0) {
            try {
                // decrypt it first to append
                byte[] dcryptb = sdr.decrypt(bos.toByteArray());

                dcrypts = new String(dcryptb, "UTF-8");
            } catch (TokenException e) {
                System.out.println("password cache decrypto failed " + e.toString());
                e.printStackTrace();
                throw new IOException("password cache decrypt failed");
            } catch (UnsupportedEncodingException e) {
                System.out.println("password cache decrypto failed " + e.toString());
                e.printStackTrace();
                throw new IOException("password cache decrypt failed");
            } catch (Exception e) {
                System.out.println("password cache decrypto failed " + e.toString());
                e.printStackTrace();
                throw new IOException("password cache decrypt failed");
            }
        }

        return dcrypts;
    }

    /*
     * encrypts and writes the whole String buf into pwcache.db
     */
    public void writePWcache(String bufs) throws IOException {
        FileOutputStream outstream = null;
        try {
            Encryptor sdr = new Encryptor(mToken, mKeyID,
                                Encryptor.DEFAULT_ENCRYPTION_ALG);

            byte[] writebuf = null;

            try {
                // now encrypt it again
                writebuf = sdr.encrypt(bufs.getBytes("UTF-8"));
            } catch (Exception e) {
                System.out.println("password cache encrypt failed " + e.toString());
                e.printStackTrace();
                throw new IOException("password cache encrypt failed");
            }

            File tmpPWcache = new File(mPWcachedb + ".tmp");

            if (tmpPWcache.exists()) {
                // it wasn't removed?
                if (!tmpPWcache.delete()) {
                    debug("Could not delete the existing " + mPWcachedb + ".tmp file.");
                }
            }
            outstream = new FileOutputStream(mPWcachedb + ".tmp");

            outstream.write(writebuf);

            // Make certain that this temporary file has
            // the correct permissions.
            if (!isNT()) {
                exec("chmod 00660 " + tmpPWcache.getAbsolutePath());
            }

            File origFile = new File(mPWcachedb);

            try {
                // Always remove any pre-existing target file
                if (origFile.exists()) {
                    if (!origFile.delete()) {
                        debug("Could not delete the existing " + mPWcachedb + "file.");
                    }
                }

                if (isNT()) {
                    // NT is very picky on the path
                    exec("copy " +
                            tmpPWcache.getAbsolutePath().replace('/', '\\') + " " +
                            origFile.getAbsolutePath().replace('/', '\\'));
                } else {
                    // Create a copy of the temporary file which
                    // preserves the temporary file's permissions.
                    exec("cp -p " + tmpPWcache.getAbsolutePath() + " " +
                            origFile.getAbsolutePath());
                }

                // Remove the temporary file if and only if
                // the "rename" was successful.
                if (origFile.exists()) {
                    if (!tmpPWcache.delete()) {
                        debug("Could not delete the existing " + mPWcachedb + ".tmp file.");
                    }

                    // Make certain that the final file has
                    // the correct permissions.
                    if (!isNT()) {
                        exec("chmod 00660 " + origFile.getAbsolutePath());
                    }

                    // report success
                    debug("Renaming operation completed for " + mPWcachedb);
                } else {
                    // report failure and exit
                    debug("Renaming operation failed for " + mPWcachedb);
                    System.exit(1);
                }
            } catch (IOException exx) {
                System.out.println("sdrPWcache: Error " + exx.toString());
                throw new IOException(exx.toString() + ": " + mPWcachedb);
            }
        } catch (FileNotFoundException e) {
            System.out.println("sdrPWcache: Error " + e.toString());
            throw new IOException(e.toString() + ": " + mPWcachedb);
        } catch (IOException e) {
            System.out.println("Failed for file " + mPWcachedb + " " + e.toString());
            throw new IOException(e.toString() + ": " + mPWcachedb);
        } catch (Exception e) {
            System.out.println("sdrPWcache: Error " + e.toString());
            throw new IOException(e.toString());
        } finally {
            if (outstream != null) {
                outstream.close();
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
        Hashtable<String, String> ht = new Hashtable<String, String>();

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

        debug("in getEntry, tag=" + tag);

        if (mPWcachedb == null) {
            debug("mPWcachedb file path name is not initialized");
            return null;
        }

        String dcrypts = null;

        try {
            dcrypts = readPWcache();
        } catch (IOException e) {
            System.out.println("dfailed readPWcache() " + e.toString());
            return null;
        }

        if (dcrypts != null) {
            // parse the cache
            String cache = dcrypts;

            // this is created and destroyed at each use
            pwTable = string2Hashtable(cache);
            debug("in getEntry, pw cache parsed");
            pw = pwTable.get(tag);
        }

        if (pw != null) {
            debug("getEntry gotten password for " + tag);
            return new Password(pw.toCharArray());
        } else {
            System.out.println("getEntry did not get password for tag " + tag);
            return null;
        }
    }

    //copied from IOUtil.java
    /**
     * Checks if this is NT.
     */
    public static boolean isNT() {
        return ((File.separator).equals("\\"));
    }

    public static boolean exec(String cmd) throws IOException {
        try {
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
            Process process = Runtime.getRuntime().exec(cmds);

            process.waitFor();

            if (process.exitValue() == 0) {

                /**
                 * pOut = new BufferedReader(
                 * new InputStreamReader(process.getInputStream()));
                 * while ((l = pOut.readLine()) != null) {
                 * System.out.println(l);
                 * }
                 **/
                return true;
            } else {

                /**
                 * pOut = new BufferedReader(
                 * new InputStreamReader(process.getErrorStream()));
                 * l = null;
                 * while ((l = pOut.readLine()) != null) {
                 * System.out.println(l);
                 * }
                 **/
                return false;
            }
        } catch (IOException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return false;
    }

    public void debug(String msg) {
        System.out.println(msg);
    }

    public void log(int level, String msg) {
        System.out.println(msg);
    }

    /*
     * list passwds in pwcache.
     */
    public boolean pprint() {
        String dcrypts = null;

        try {
            dcrypts = readPWcache();
        } catch (IOException e) {
            System.out.println("failed readPWcache() " + e.toString());
            return false;
        }

        debug("----- Password Cache Content -----");

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

                    debug(tag.trim() +
                            " : " + passwd.trim());
                } else {
                    //invalid format...log or throw...later
                    debug("invalid format");
                }
            }
        } // else print nothing
        return true;
    }
}
