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
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AVA;
import netscape.security.x509.LdapV3DNStrConverter;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.ECompSyntaxErr;

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
class AVAPattern {

    /* the value type of the dn component */
    public static final String TYPE_ATTR = "$attr";
    public static final String TYPE_DN = "$dn";
    public static final String TYPE_RDN = "$rdn";
    public static final String TYPE_CONSTANT = "constant";

    private static final LdapV3DNStrConverter mLdapDNStrConverter =
            new LdapV3DNStrConverter();

    /* ldap attributes needed by this AVA (to retrieve from ldap) */
    protected String[] mLdapAttrs = null;

    /* value type */
    protected String mType = null;

    /* the attribute in the AVA pair */
    protected String mAttr = null;

    /* value - could be name of an ldap attribute or entry dn attribute. */
    protected String mValue = null;

    /* nth value of the ldap or dn attribute */
    protected int mElement = 0;

    protected String mTestDN = null;

    public AVAPattern(String component)
            throws EAuthException {
        if (component == null || component.length() == 0)
            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", component));
        parse(new PushbackReader(new StringReader(component)));
    }

    public AVAPattern(PushbackReader in)
            throws EAuthException {
        parse(in);
    }

    private void parse(PushbackReader in)
            throws EAuthException {
        int c;

        // mark ava beginning.

        // skip spaces
        //System.out.println("============ AVAPattern Begin ===========");
        //System.out.println("skip spaces");

        try {
            while ((c = in.read()) == ' ' || c == '\t') {//System.out.println("spaces read "+(char)c);
                ;
            }
        } catch (IOException e) {
            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", "All blank"));
        }
        if (c == -1)
            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", "All blank"));

        // $rdn "." number syntax.

        if (c == '$') {
            //System.out.println("$rdn syntax");
            mType = TYPE_RDN;
            try {
                if (in.read() != 'r' ||
                        in.read() != 'd' ||
                        in.read() != 'n' ||
                        in.read() != '.')
                    throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                            "Invalid $ syntax, expecting $rdn"));
            } catch (IOException e) {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                        "Invalid $ syntax, expecting $rdn"));
            }

            StringBuffer rdnNumberBuf = new StringBuffer();

            try {
                while ((c = in.read()) != ',' && c != -1 && c != '+') {
                    //System.out.println("rdnNumber read "+(char)c);
                    rdnNumberBuf.append((char) c);
                }
                if (c != -1) // either ',' or '+'
                    in.unread(c);
            } catch (IOException e) {
                throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
            }

            String rdnNumber = rdnNumberBuf.toString().trim();

            if (rdnNumber.length() == 0)
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                        "$rdn number not set in ava pattern"));
            try {
                mElement = Integer.parseInt(rdnNumber) - 1;
            } catch (NumberFormatException e) {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                        "Invalid $rdn number in ava pattern"));
            }
            return;
        }

        // name "=" ... syntax.

        // read name
        //System.out.println("reading name");

        StringBuffer attrBuf = new StringBuffer();

        try {
            while (c != '=' && c != -1 && c != ',' && c != '+') {
                attrBuf.append((char) c);
                c = in.read();
                //System.out.println("name read "+(char)c);
            }
            if (c == ',' || c == '+')
                in.unread(c);
        } catch (IOException e) {
            throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
        }
        if (c != '=')
            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                    "Missing \"=\" in ava pattern"));

        // read value
        //System.out.println("reading value");

        // skip spaces
        //System.out.println("skip spaces for value");
        try {
            while ((c = in.read()) == ' ' || c == '\t') {//System.out.println("spaces2 read "+(char)c);
                ;
            }
        } catch (IOException e) {
            throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
        }
        if (c == -1)
            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                    "no value after = in ava pattern"));

        if (c == '$') {
            // check for $dn or $attr
            try {
                c = in.read();
                //System.out.println("check $dn or $attr read "+(char)c);
            } catch (IOException e) {
                throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
            }
            if (c == -1)
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                            "expecting $dn or $attr in ava pattern"));
            if (c == 'a') {
                try {
                    if (in.read() != 't' ||
                            in.read() != 't' ||
                            in.read() != 'r' ||
                            in.read() != '.')
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "expecting $attr in ava pattern"));
                } catch (IOException e) {
                    throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
                }
                mType = TYPE_ATTR;
                //System.out.println("---- mtype $attr");
            } else if (c == 'd') {
                try {
                    if (in.read() != 'n' ||
                            in.read() != '.')
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "expecting $dn in ava pattern"));
                } catch (IOException e) {
                    throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
                }
                mType = TYPE_DN;
                //System.out.println("----- mtype $dn");
            } else {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                            "unknown keyword. expecting $dn or $attr."));
            }

            // get attr name of dn pattern from above.
            String attrName = attrBuf.toString().trim();

            //System.out.println("----- attrName "+attrName);
            if (attrName.length() == 0)
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                        "attribute name expected"));
            try {
                ObjectIdentifier attrOid =
                        mLdapDNStrConverter.parseAVAKeyword(attrName);

                mAttr = mLdapDNStrConverter.encodeOID(attrOid);
                //System.out.println("----- mAttr "+mAttr);
            } catch (IOException e) {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", e.getMessage()));
            }

            // get dn or attribute from ldap search.
            StringBuffer valueBuf = new StringBuffer();

            try {
                while ((c = in.read()) != ',' &&
                        c != -1 && c != '.' && c != '+') {
                    //System.out.println("mValue read "+(char)c);
                    valueBuf.append((char) c);
                }
                if (c == '+' || c == ',') // either ',' or '+'
                    in.unread(c); // pushback last , or +
            } catch (IOException e) {
                throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
            }

            mValue = valueBuf.toString().trim();
            if (mValue.length() == 0)
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                            "$dn or $attr attribute name expected"));
            //System.out.println("----- mValue "+mValue);

            // get nth dn or attribute from ldap search.
            if (c == '.') {
                StringBuffer attrNumberBuf = new StringBuffer();

                try {
                    while ((c = in.read()) != ',' && c != -1 && c != '+') {
                        //System.out.println("mElement read "+(char)c);
                        attrNumberBuf.append((char) c);
                    }
                    if (c != -1) // either ',' or '+'
                        in.unread(c); // pushback last , or +
                } catch (IOException e) {
                    throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.toString()));
                }
                String attrNumber = attrNumberBuf.toString().trim();

                if (attrNumber.length() == 0)
                    throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                "nth element $dn or $attr expected"));
                try {
                    mElement = Integer.parseInt(attrNumber) - 1;
                } catch (NumberFormatException e) {
                    throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                "Invalid format in nth element $dn or $attr"));
                }
            }
            //System.out.println("----- mElement "+mElement);
        } else {
            // value is constant. treat as regular ava.
            mType = TYPE_CONSTANT;
            //System.out.println("----- mType constant");
            // parse ava value.
            StringBuffer valueBuf = new StringBuffer();

            valueBuf.append((char) c);
            try {
                while ((c = in.read()) != ',' &&
                        c != -1) {
                    valueBuf.append((char) c);
                }
                if (c == '+' || c == ',') { // either ',' or '+'
                    in.unread(c); // pushback last , or +
                }
            } catch (IOException e) {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", e.getMessage()));
            }
            try {
                AVA ava = mLdapDNStrConverter.parseAVA(attrBuf + "=" + valueBuf);

                mValue = ava.toLdapDNString();
                //System.out.println("----- mValue "+mValue);
            } catch (IOException e) {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", e.getMessage()));
            }
        }
    }

    public String formAVA(LDAPEntry entry)
            throws EAuthException {
        if (mType == TYPE_CONSTANT)
            return mValue;

        if (mType == TYPE_RDN) {
            String dn = entry.getDN();

            if (mTestDN != null)
                dn = mTestDN;
            //System.out.println("AVAPattern Using dn "+mTestDN);
            String[] rdns = LDAPDN.explodeDN(dn, false);

            if (mElement >= rdns.length)
                return null;
            return rdns[mElement];
        }

        if (mType == TYPE_DN) {
            String dn = entry.getDN();

            if (mTestDN != null)
                dn = mTestDN;
            //System.out.println("AVAPattern Using dn "+mTestDN);
            String[] rdns = LDAPDN.explodeDN(dn, false);
            String value = null;
            int nFound = -1;

            for (int i = 0; i < rdns.length; i++) {
                String[] avas = explodeRDN(rdns[i]);

                for (int j = 0; j < avas.length; j++) {
                    String[] exploded = explodeAVA(avas[j]);

                    if (exploded[0].equalsIgnoreCase(mValue) &&
                            ++nFound == mElement) {
                        value = exploded[1];
                        break;
                    }
                }
            }
            if (value == null)
                return null;
            return mAttr + "=" + value;
        }

        if (mType == TYPE_ATTR) {
            LDAPAttribute ldapAttr = entry.getAttribute(mValue);

            if (ldapAttr == null)
                return null;
            String value = null;
            @SuppressWarnings("unchecked")
            Enumeration<String> ldapValues = ldapAttr.getStringValues();

            for (int i = 0; ldapValues.hasMoreElements(); i++) {
                String val = ldapValues.nextElement();

                if (i == mElement) {
                    value = val;
                    break;
                }
            }
            if (value == null)
                return null;
            String v = escapeLdapString(value);

            return mAttr + "=" + v;
        }

        return null;
    }

    private String escapeLdapString(String value) {
        int len = value.length();
        char[] c = new char[len];
        char[] newc = new char[len * 2];

        value.getChars(0, len, c, 0);
        int j = 0;

        for (int i = 0; i < c.length; i++) {
            // escape special characters that directory does not.
            if ((c[i] == ',' || c[i] == '=' || c[i] == '+' || c[i] == '<' ||
                    c[i] == '>' || c[i] == '#' || c[i] == ';')) {
                if (i == 0 || c[i - 1] != '\\') {
                    newc[j++] = '\\';
                    newc[j++] = c[i];
                }
            } // escape "\"
            else if (c[i] == '\\') {
                int k = i + 1;

                if (i == len - 1 ||
                        (c[k] == ',' || c[k] == '=' || c[k] == '+' || c[k] == '<' ||
                                c[k] == '>' || c[k] == '#' || c[k] == ';')) {
                    newc[j++] = '\\';
                    newc[j++] = c[i];
                }
            } // escape QUOTATION
            else if (c[i] == '"') {
                if ((i == 0 && c[len - 1] != '"') ||
                        (i == len - 1 && c[0] != '"') ||
                        (i > 0 && i < len - 1)) {
                    newc[j++] = '\\';
                    newc[j++] = c[i];
                }
            } else
                newc[j++] = c[i];
        }
        return new String(newc, 0, j);
    }

    public String getLdapAttr() {
        if (mType == TYPE_ATTR)
            return mValue;
        else
            return null;
    }

    /**
     * Explode RDN into AVAs.
     * Does not handle escaped '+'
     * Java ldap library does not yet support multiple avas per rdn.
     * If RDN is malformed returns empty array.
     */
    public static String[] explodeRDN(String rdn) {
        int plus = rdn.indexOf('+');

        if (plus == -1)
            return new String[] { rdn };
        Vector<String> avas = new Vector<String>();
        StringTokenizer token = new StringTokenizer(rdn, "+");

        while (token.hasMoreTokens())
            avas.addElement(token.nextToken());
        String[] theAvas = new String[avas.size()];

        avas.copyInto(theAvas);
        return theAvas;
    }

    /**
     * Explode AVA into name and value.
     * Does not handle escaped '='
     * If AVA is malformed empty array is returned.
     */
    public static String[] explodeAVA(String ava) {
        int equals = ava.indexOf('=');

        if (equals == -1)
            return null;
        return new String[] {
                ava.substring(0, equals).trim(), ava.substring(equals + 1).trim() };
    }
}
