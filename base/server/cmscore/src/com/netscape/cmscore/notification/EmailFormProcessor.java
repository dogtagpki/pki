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
package com.netscape.cmscore.notification;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.notification.IEmailFormProcessor;

/**
 * formulates the final email. Escape character '\' is understood.
 * '$' is used preceeding a token name. A token name should not be a
 * substring of any other token name
 * <p>
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class EmailFormProcessor implements IEmailFormProcessor {

    protected final static String TOK_PREFIX = "$";
    protected final static String TOK_ESC = "\\";
    protected final static char TOK_END = ' ';
    protected final static String TOK_VALUE_UNKNOWN = "VALUE UNKNOWN";
    protected final static String TOK_TOKEN_UNKNOWN = "UNKNOWN TOKEN:";
    protected ILogger mLogger = CMS.getLogger();

    // stores all the available token keys; added so that we can
    // parse strings to replace unresolvable token keys and replace
    // them by the words "VALUE UNKNOWN"
    protected static String[] token_keys = {
            TOKEN_ID,
            TOKEN_SERIAL_NUM,
            TOKEN_HTTP_HOST,
            TOKEN_HTTP_PORT,
            TOKEN_ISSUER_DN,
            TOKEN_SUBJECT_DN,
            TOKEN_REQUESTOR_EMAIL,
            TOKEN_CERT_TYPE,
            TOKEN_REQUEST_TYPE,
            TOKEN_STATUS,
            TOKEN_NOT_AFTER,
            TOKEN_NOT_BEFORE,
            TOKEN_SENDER_EMAIL,
            TOKEN_RECIPIENT_EMAIL,
            TOKEN_SUMMARY_ITEM_LIST,
            TOKEN_SUMMARY_TOTAL_NUM,
            TOKEN_SUMMARY_SUCCESS_NUM,
            TOKEN_SUMMARY_FAILURE_NUM,
            TOKEN_EXECUTION_TIME
        };

    // stores the eventual content of the email
    Vector<String> mContent = new Vector<String>();
    Hashtable<String, Object> mTok2vals = null;

    public EmailFormProcessor() {
    }

    /*
     * takes the form template, parse and replace all $tokens with the
     *		 right values.  It handles escape character '\'
     * @param form The locale specific form template,
     * @param tok2vals a hashtable containing one to one mapping
     *	 from $tokens used by the admins in the form template to the real
     *	 values corresponding to the $tokens
     * @return mail content
     */
    public String getEmailContent(String form,
            Hashtable<String, Object> tok2vals) {
        mTok2vals = tok2vals;

        if (form == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_NOTIFY_TEMPLATE_NULL"));
            return null;
        }

        if (mTok2vals == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_NOTIFY_TOKEN_NULL"));
            return null;
        }

        /**
         * first, take care of the escape characters '\'
         */
        StringTokenizer es = new StringTokenizer(form, TOK_ESC);

        if (es.hasMoreTokens() && !form.startsWith(TOK_ESC)) {
            dollarProcess(es.nextToken());
        }

        // rest of them start with '\'
        while (es.hasMoreTokens()) {
            String t = es.nextToken();

            // put first character (escaped char) in mContent
            char c = t.charAt(0);

            Character ch = Character.valueOf(c);

            mContent.add(ch.toString());

            // process the rest for $tokens
            String r = t.substring(1);

            dollarProcess(r);
        }

        return formContent(mContent);
    }

    private void dollarProcess(String sub) {
        StringTokenizer st = new StringTokenizer(sub, TOK_PREFIX);

        // if first token is not a $token, put in mContent as is
        if (st.hasMoreTokens() && !sub.startsWith(TOK_PREFIX)) {
            String a = st.nextToken();

            mContent.add(a);
        }

        /*
         * all of the string tokens below begin with a '$'
         * match it one by one with the mTok2vals table
         */
        while (st.hasMoreTokens()) {
            String t = st.nextToken();

            /*
             * We don't know when a token ends.  Compare with every
             * token in the table for the first match.  Which means, a
             * token name should not be a substring of any token name
             */
            boolean matched = false;
            String tok = null;

            for (Enumeration<String> e = mTok2vals.keys(); e.hasMoreElements();) {
                // get key
                tok = e.nextElement();

                // compare key with $token
                if (t.startsWith(tok)) {
                    // match, put val in mContent
                    Object o = mTok2vals.get(tok);

                    if (o != null) {
                        String s = (String) o;

                        if (!s.equals("")) {
                            mContent.add(s);
                        } else {
                            break;
                        }
                    } else { // no value, bail out
                        break;
                    }

                    // now, put the rest of the non-token string in mContent
                    if (t.length() != tok.length()) {
                        mContent.add(t.substring(tok.length()));
                    }

                    matched = true;

                    // replaced! bail out.
                    break;
                }
            }

            if (!matched) {
                boolean keyFound = false;

                // no match, put the token back, as is
                // -- for bug 382162, don't remove the following line, in
                //	 case John changes his mind for the better
                //				mContent.add(TOK_PREFIX+t);

                for (int i = 0; i < token_keys.length; i++) {
                    if (t.startsWith(token_keys[i])) {
                        // match,  replace it with the TOK_VALUE_UNKNOWN
                        mContent.add(TOK_VALUE_UNKNOWN);

                        // now, put the rest of the non-token string
                        //						in mContent
                        if (t.length() != token_keys[i].length()) {
                            mContent.add(t.substring(token_keys[i].length()));
                        }
                        keyFound = true;
                        break;
                    }
                    // keep looking
                }
                if (keyFound == false) {
                    mContent.add(TOK_TOKEN_UNKNOWN + TOK_PREFIX + t);
                }
            }
        }
    }

    /**
     * takes a vector of strings and concatenate them
     */
    public String formContent(Vector<String> vec) {
        StringBuffer content = new StringBuffer();

        Enumeration<String> e = vec.elements();

        // initialize content with first element
        if (e.hasMoreElements()) {
            content.append(e.nextElement());
        }

        while (e.hasMoreElements()) {
            String v = e.nextElement();
            content.append(v);
        }

        return content.toString();
    }

    /**
     * logs an entry in the log file.
     */
    public void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_OTHER,
                level, "EmailFormProcessor: " + msg);
    }
}
