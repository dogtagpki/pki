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
public class DNPattern {

    /* ldap attributes to retrieve */
    private String[] mLdapAttrs = null;

    /* rdn patterns */
    protected RDNPattern[] mRDNPatterns = null;

    /* original pattern string */
    protected String mPatternString = null;

    protected String mTestDN = null;

    /**
     * Construct a DN pattern by parsing a pattern string.
     *
     * @param pattern the DN pattern
     * @exception EBaseException If parsing error occurs.
     */
    public DNPattern(String pattern)
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

    public DNPattern(PushbackReader in)
            throws EAuthException {
        parse(in);
    }

    private void parse(PushbackReader in)
            throws EAuthException {
        Vector<RDNPattern> rdnPatterns = new Vector<RDNPattern>();
        RDNPattern rdnPattern = null;
        int lastChar = -1;

        do {
            rdnPattern = new RDNPattern(in);
            rdnPatterns.addElement(rdnPattern);
            try {
                lastChar = in.read();
            } catch (IOException e) {
                throw new EAuthException("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString());
            }
        } while (lastChar == ',');

        mRDNPatterns = new RDNPattern[rdnPatterns.size()];
        rdnPatterns.copyInto(mRDNPatterns);

        Vector<String> ldapAttrs = new Vector<String>();

        for (int i = 0; i < mRDNPatterns.length; i++) {
            String[] rdnAttrs = mRDNPatterns[i].getLdapAttrs();

            if (rdnAttrs != null && rdnAttrs.length > 0)
                for (int j = 0; j < rdnAttrs.length; j++)
                    ldapAttrs.addElement(rdnAttrs[j]);
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
    public String formDN(LDAPEntry entry)
            throws EAuthException {
        StringBuffer formedDN = new StringBuffer();

        for (int i = 0; i < mRDNPatterns.length; i++) {
            if (mTestDN != null)
                mRDNPatterns[i].mTestDN = mTestDN;
            String rdn = mRDNPatterns[i].formRDN(entry);

            if (rdn != null) {
                if (rdn != null && rdn.length() != 0) {
                    if (formedDN.length() != 0)
                        formedDN.append(",");
                    formedDN.append(rdn);
                }
            }
        }
        //System.out.println("formed DN "+formedDN.toString());
        return formedDN.toString();
    }

    public String[] getLdapAttrs() {
        return mLdapAttrs.clone();
    }
}
