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

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.JDialogPasswordCallback;

/*
 * A class to retrieve passwords from the SDR password cache
 *
 * @author Christina Fu
 * @version $Revision$, $Date$
 */

public class PWCBsdr implements PasswordCallback {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PWCBsdr.class);

    String mprompt = "";
    boolean firsttime = true;
    private PasswordCallback mCB = null;
    private String mPWcachedb = null;

    public PWCBsdr() {
        this(null);
    }

    public PWCBsdr(String prompt) {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        mprompt = prompt;

        // get path to password cache
        try {
            mPWcachedb = cs.getString("pwCache");
            logger.debug("got pwCache from configstore: " + mPWcachedb);
        } catch (NullPointerException e) {
            logger.warn("after CMS.getConfigStore got NullPointerException ... testing ok", e);
        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("CMSCORE_SECURITY_GET_CONFIG"), e);
            // let it fall through
        }

        //    System.out.println("after CMS.getConfigStore");

            // Unix
            mCB = new PWsdrConsolePasswordCallback(prompt);

            // mCB = new PWsdrDialogPasswordCallback( prompt );


        // System.out.println( "Created PWCBsdr with prompt of "
        //                   + mprompt );
    }

    /* We are now assuming that PasswordCallbackInfo.getname() returns
     * the tag we are hoping to match in the cache.
     */

    @Override
    public Password getPasswordFirstAttempt(PasswordCallbackInfo info)
            throws PasswordCallback.GiveUpException {

        logger.debug("in getPasswordFirstAttempt");

        /* debugging code to see if token is logged in
         try {
         CryptoManager cm = CryptoManager.getInstance();
         CryptoToken token =
         cm.getInternalKeyStorageToken();
         if (token.isLoggedIn() == false) {
         // missed it.
         logger.debug("token not yet logged in!!");
         } else {
         logger.debug("token logged in.");
         }
         } catch (Exception e) {
         logger.warn("crypto manager error:" + e.getMessage(), e);
         }
         logger.debug("still in getPasswordFirstAttempt");
         */
        Password pw = null;
        String tmpPrompt = info.getName();

        String skip_token = System.getProperty("cms.skip_token");

        if (skip_token != null) {
            if (tmpPrompt.equals(skip_token)) {
                throw new PasswordCallback.GiveUpException();
            }
        }

        try {
            String defpw = System.getProperty("cms.defaultpassword");

            if (defpw != null) {
                return new Password(defpw.toCharArray());
            }

            /* mprompt has precedence over info.name */
            if (!(mprompt == null)) {
                tmpPrompt = mprompt;
            }

            if (tmpPrompt == null) { /* no name, fail */
                System.out.println("Shouldn't get here");
                throw new PasswordCallback.GiveUpException();
            }
            /* get password from password cache */
            logger.debug("getting tag = " + tmpPrompt);
            PWsdrCache pwc = new PWsdrCache(mPWcachedb);

            pw = pwc.getEntry(tmpPrompt);

            if (pw == null) { /* password not found */
                // we don't want caller to do getPasswordAgain,    for now
                logger.error(CMS.getLogMessage("CMSCORE_SECURITY_THROW_CALLBACK"));
                throw new PasswordCallback.GiveUpException();
            }
            logger.debug("non-null password returned in first attempt");
            return pw;
        } catch (Throwable e) {
            // System.out.println( "BUG HERE!!!!first!!!!!!!!!!!!!!!!!" );
            // e.printStackTrace();
            throw new PasswordCallback.GiveUpException();
        }
    }

    /* The password cache has failed to return a password (or a usable password.
     * Now we will try and get the password from the user and hopefully add
     * the password to the cache pw cache
     */
    @Override
    public Password getPasswordAgain(PasswordCallbackInfo info)
            throws PasswordCallback.GiveUpException {

        logger.debug("in getPasswordAgain");
        try {
            Password pw = null;

            try {
                if (firsttime) {
                    try {
                        firsttime = false;

                        pw = mCB.getPasswordFirstAttempt(info);
                    } catch (PasswordCallback.GiveUpException e) {
                        throw new PasswordCallback.GiveUpException();
                    }
                } else {
                    pw = mCB.getPasswordAgain(info);
                }
                return (pw);
            } catch (PasswordCallback.GiveUpException e) {
                throw new PasswordCallback.GiveUpException();
            }
        } catch (Throwable e) {
            // logger.error("Unable to get the password again: " + e.getMessage(), e);
            throw new PasswordCallback.GiveUpException();
        }
    }
}

class PWsdrConsolePasswordCallback implements PasswordCallback {
    private String mPrompt = null;

    public PWsdrConsolePasswordCallback(String p) {
        mPrompt = p;
    }

    public String getPrompt() {
        return mPrompt;
    }

    @Override
    public Password getPasswordFirstAttempt(PasswordCallbackInfo info)
            throws PasswordCallback.GiveUpException {
        if (mPrompt == null) {
            System.out.println("Get password " + info.getName());
        } else {
            System.out.println(getPrompt());
        }

        Password tmppw = PWUtil.readPasswordFromStream();

        return (tmppw);
    }

    @Override
    public Password getPasswordAgain(PasswordCallbackInfo info)
            throws PasswordCallback.GiveUpException {
        System.out.println("Password Incorrect.");
        if (mPrompt == null) {
            System.out.println("Get password " + info.getName());
        } else {
            System.out.println(getPrompt());
        }

        Password tmppw = PWUtil.readPasswordFromStream();

        return (tmppw);
    }
}

class PWsdrDialogPasswordCallback extends JDialogPasswordCallback {
    private String mPrompt = null;

    public PWsdrDialogPasswordCallback(String p) {
        super();
        mPrompt = p;
    }

    @Override
    public String getPrompt(PasswordCallbackInfo info) {
        return mPrompt == null ? super.getPrompt(info) : mPrompt;
    }
}
