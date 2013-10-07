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
package com.netscape.cms.authentication;

import java.io.IOException;
import java.io.PushbackReader;
import java.io.StringReader;
import java.util.Vector;

import netscape.ldap.LDAPEntry;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.base.EBaseException;

/**
 * class for parsing a DN pattern used to construct a certificate
 * subject name from ldap attributes and dn.
 * <p>
 *
 * dnpattern is a string representing a subject name pattern to formulate from the directory attributes and entry dn. If
 * empty or not set, the ldap entry DN will be used as the certificate subject name.
 * <p>
 *
 * The syntax is
 *
 * <pre>
 * 	dnPattern := rdnPattern *[ "," rdnPattern ]
 * 	rdnPattern := avaPattern *[ "+" avaPattern ]
 * 		avaPattern := name "=" value |
 * 			      name "=" "$attr" "." attrName [ "." attrNumber ] |
 * 			      name "=" "$dn" "." attrName [ "." attrNumber ] |
 * 			 	  "$dn" "." "$rdn" "." number
 * </pre>
 *
 * <pre>
 * Example1: <i>E=$attr.mail.1, CN=$attr.cn, OU=$dn.ou.2, O=$dn.o, C=US </i>
 * Ldap entry: dn:  UID=jjames, OU=IS, OU=people, O=acme.org
 * Ldap attributes: cn: Jesse James
 * Ldap attributes: mail: jjames@acme.org
 * <p>
 * The subject name formulated will be : <br>
 *     E=jjames@acme.org, CN=Jesse James, OU=people, O=acme.org, C=US
 * <p>
 *     E = the first 'mail' ldap attribute value in user's entry. <br>
 *     CN = the (first) 'cn' ldap attribute value in the user's entry. <br>
 *     OU = the second 'ou' value in the user's entry DN. <br>
 *     O = the (first) 'o' value in the user's entry DN. <br>
 *     C = the string "US"
 * <p>
 * Example2: <i>E=$attr.mail.1, CN=$attr.cn, OU=$dn.ou.2, O=$dn.o, C=US</i>
 * Ldap entry: dn:  UID=jjames, OU=IS+OU=people, O=acme.org
 * Ldap attributes: cn: Jesse James
 * Ldap attributes: mail: jjames@acme.org
 * <p>
 * The subject name formulated will be : <br>
 *     E=jjames@acme.org, CN=Jesse James, OU=people, O=acme.org, C=US
 * <p>
 *     E = the first 'mail' ldap attribute value in user's entry. <br>
 *     CN = the (first) 'cn' ldap attribute value in the user's entry. <br>
 *     OU = the second 'ou' value in the user's entry DN. note multiple AVAs
 * 	    in a RDN in this example. <br>
 *     O = the (first) 'o' value in the user's entry DN. <br>
 *     C = the string "US"
 * <p>
 * </pre>
 *
 * <pre>
 * Example3: <i>CN=$attr.cn, $rdn.2, O=$dn.o, C=US</i>
 * Ldap entry: dn:  UID=jjames, OU=IS+OU=people, O=acme.org
 * Ldap attributes: cn: Jesse James
 * Ldap attributes: mail: jjames@acme.org
 * <p>
 * The subject name formulated will be : <br>
 *     CN=Jesse James, OU=IS+OU=people, O=acme.org, C=US
 * <p>
 *     CN = the (first) 'cn' ldap attribute value in the user's entry. <br>
 *     followed by the second RDN in the user's entry DN. <br>
 *     O = the (first) 'o' value in the user's entry DN. <br>
 *     C = the string "US"
 * <p>
 * Example4: <i>CN=$attr.cn, OU=$dn.ou.2+OU=$dn.ou.1, O=$dn.o, C=US</i>
 * Ldap entry: dn:  UID=jjames, OU=IS+OU=people, O=acme.org
 * Ldap attributes: cn: Jesse James
 * Ldap attributes: mail: jjames@acme.org
 * <p>
 * The subject name formulated will be : <br>
 *     CN=Jesse James, OU=people+OU=IS, O=acme.org, C=US
 * <p>
 *     CN = the (first) 'cn' ldap attribute value in the user's entry. <br>
 *     OU = the second 'ou' value in the user's entry DN followed by the
 * 		first 'ou' value in the user's entry. note multiple AVAs
 * 	    in a RDN in this example. <br>
 *     O = the (first) 'o' value in the user's entry DN. <br>
 *     C = the string "US"
 * <p>
 * </pre>
 *
 * If an attribute or subject DN component does not exist the attribute is skipped.
 *
 * @version $Revision$, $Date$
 */
class RDNPattern {

    /* ldap attributes needed by this RDN (to retrieve from ldap) */
    private String[] mLdapAttrs = null;

    /* AVA patterns */
    protected AVAPattern[] mAVAPatterns = null;

    /* original pattern string */
    protected String mPatternString = null;

    protected String mTestDN = null;

    /**
     * Construct a DN pattern by parsing a pattern string.
     *
     * @param pattenr the DN pattern
     * @exception EBaseException If parsing error occurs.
     */
    public RDNPattern(String pattern)
            throws EAuthException {
        if (pattern == null || pattern.equals("")) {
            // create an attribute list that is the dn.
            mLdapAttrs = new String[] { "dn" };
        } else {
            mPatternString = pattern;
            PushbackReader in = new PushbackReader(new StringReader(pattern));

            parse(in);
        }
    }

    /**
     * Construct a DN pattern from a input stream of pattern
     */
    public RDNPattern(PushbackReader in)
            throws EAuthException {
        parse(in);
    }

    private void parse(PushbackReader in)
            throws EAuthException {
        //System.out.println("_________ begin rdn _________");
        Vector<AVAPattern> avaPatterns = new Vector<AVAPattern>();
        AVAPattern avaPattern = null;
        int lastChar;

        do {
            avaPattern = new AVAPattern(in);
            avaPatterns.addElement(avaPattern);
            //System.out.println("added AVAPattern"+
            //" mType "+avaPattern.mType+
            //" mAttr "+avaPattern.mAttr+
            //" mValue "+avaPattern.mValue+
            //" mElement "+avaPattern.mElement);
            try {
                lastChar = in.read();
            } catch (IOException e) {
                throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
            }
        } while (lastChar == '+');

        if (lastChar != -1) {
            try {
                in.unread(lastChar); // pushback last ,
            } catch (IOException e) {
                throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
            }
        }

        mAVAPatterns = new AVAPattern[avaPatterns.size()];
        avaPatterns.copyInto(mAVAPatterns);

        Vector<String> ldapAttrs = new Vector<String>();

        for (int i = 0; i < mAVAPatterns.length; i++) {
            String avaAttr = mAVAPatterns[i].getLdapAttr();

            if (avaAttr == null || avaAttr.length() == 0)
                continue;
            ldapAttrs.addElement(avaAttr);
        }
        mLdapAttrs = new String[ldapAttrs.size()];
        ldapAttrs.copyInto(mLdapAttrs);
    }

    /**
     * Form a Ldap v3 DN string from results of a ldap search.
     *
     * @param entry LDAPentry from a ldap search
     * @return Ldap v3 DN string to use for a subject name.
     */
    public String formRDN(LDAPEntry entry)
            throws EAuthException {
        StringBuffer formedRDN = new StringBuffer();

        for (int i = 0; i < mAVAPatterns.length; i++) {
            if (mTestDN != null)
                mAVAPatterns[i].mTestDN = mTestDN;
            String ava = mAVAPatterns[i].formAVA(entry);

            if (ava != null && ava.length() > 0) {
                if (formedRDN.length() != 0)
                    formedRDN.append("+");
                formedRDN.append(ava);
            }
        }
        //System.out.println("formed RDN "+formedRDN.toString());
        return formedRDN.toString();
    }

    public String[] getLdapAttrs() {
        return mLdapAttrs.clone();
    }
}
