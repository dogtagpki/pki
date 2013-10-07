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
package com.netscape.cms.publish.mappers;

import java.io.IOException;
import java.io.PushbackReader;
import java.io.StringReader;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.ldap.LDAPDN;
import netscape.security.x509.AVA;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.Extension;
import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNameInterface;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.LdapV3DNStrConverter;
import netscape.security.x509.OIDMap;
import netscape.security.x509.SubjectAlternativeNameExtension;
import netscape.security.x509.X500Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.publish.ECompSyntaxErr;
import com.netscape.certsrv.request.IRequest;

/**
 * class for parsing a DN pattern used to construct a ldap dn from
 * request attributes and cert subject name.
 * <p>
 *
 * dnpattern is a string representing a ldap dn pattern to formulate from the certificate subject name attributes and
 * request attributes . If empty or not set, the certificate subject name will be used as the ldap dn.
 * <p>
 *
 * The syntax is
 *
 * <pre>
 * 	dnPattern := rdnPattern *[ "," rdnPattern ]
 * 	rdnPattern := avaPattern *[ "+" avaPattern ]
 * 		avaPattern := name "=" value |
 * 			      name "=" "$subj" "." attrName [ "." attrNumber ] |
 * 			      name "=" "$ext" "." extName [ "." nameType ] [ "." attrNumber ]
 * 			      name "=" "$req" "." attrName [ "." attrNumber ] |
 * 			 	  "$rdn" "." number
 * </pre>
 *
 * <pre>
 * Example1: <i>cn=Certificate Manager,ou=people,o=mcom.com</i>
 * cert subject name: dn:  CN=Certificate Manager, OU=people, O=mcom.com
 * request attributes: uid: cmanager
 * <p>
 * The dn formulated will be : <br>
 *     CN=Certificate Manager, OU=people, O=mcom.com
 * <p>
 * note: Subordinate ca enrollment will use ca mapper. Use predicate
 * to distinguish the ca itself and the subordinates.
 *
 * Example2: <i>UID=$req.HTTP_PARAMS.uid, OU=$subj.ou, OU=people, , O=mcom.com</i>
 * cert subject name: dn:  UID=jjames, OU=IS, OU=people, , O=mcom.com
 * request attributes: uid: cmanager
 * <p>
 * The dn formulated will be : <br>
 *     UID=jjames, OU=IS, OU=people, O=mcom.com
 * <p>
 *     UID = the 'uid' attribute value in the request. <br>
 *     OU = the 'ou' value in the cert subject name.  <br>
 *     O = the string mcom.com. <br>
 * <p>
 * Example3: <i>UID=$req.HTTP_PARAMS.uid, E=$ext.SubjectAlternativeName.RFC822Name.1, O=mcom.com</i>
 * cert subject name: dn:  UID=jjames, OU=IS, OU=people, O=mcom.com
 * cert subjectAltName is rfc822Name: jjames@mcom.com
 * request attributes: uid: cmanager
 * <p>
 * The dn formulated will be : <br>
 *     UID=jjames, E=jjames@mcom.com, O=mcom.com
 * <p>
 *     UID = the 'uid' attribute value in the request. <br>
 *     E = The first rfc822name value in the subjAltName extension.  <br>
 *     O = the string mcom.com. <br>
 * <p>
 * </pre>
 *
 * If an request attribute or subject DN component does not exist, the attribute is skipped. There is potential risk
 * that a wrong dn will be mapped into.
 *
 * @version $Revision$, $Date$
 */
class MapAVAPattern {

    /* the value type of the dn component */
    public static final String TYPE_REQ = "$req";
    public static final String TYPE_SUBJ = "$subj";
    public static final String TYPE_EXT = "$ext";
    public static final String TYPE_RDN = "$rdn";
    public static final String TYPE_CONSTANT = "constant";

    public static final String[] GENERAL_NAME_TYPE = { "ANY",
            "RFC822Name",
            "DNSName",
            "X400Name",
            "DIRECTORYName",
            "EDIName",
            "URIName",
            "IPAddress",
            "OIDName" };

    private static final LdapV3DNStrConverter mLdapDNStrConverter =
            new LdapV3DNStrConverter();

    /* the list of request attributes needed by this AVA  */
    protected String[] mReqAttrs = null;

    /* the list of cert attributes needed by this AVA*/
    protected String[] mCertAttrs = null;

    /* value type */
    protected String mType = null;

    /* the attribute in the AVA pair */
    protected String mAttr = null;

    /* value - could be name of a request  attribute or
     * cert subject dn attribute. */
    protected String mValue = null;

    /* value type - general name type of an extension attribute if any. */
    protected String mGNType = null;

    /* prefix - prefix of a request attribute if any. */
    protected String mPrefix = null;

    /* nth value of the ldap or dn attribute */
    protected int mElement = 0;

    protected String mTestDN = null;

    public MapAVAPattern(String component)
            throws ELdapException {
        if (component == null || component.length() == 0)
            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", component));
        parse(new PushbackReader(new StringReader(component)));
    }

    public MapAVAPattern(PushbackReader in)
            throws ELdapException {
        parse(in);
    }

    private void parse(PushbackReader in)
            throws ELdapException {
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
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
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
            throw new ELdapException(
                    CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
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
            throw new ELdapException(
                    CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
        }
        if (c == -1)
            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                    "no value after = in ava pattern"));

        if (c == '$') {
            // check for $subj $ext or $req
            try {
                c = in.read();
                //System.out.println("check $dn or $attr read "+(char)c);
            } catch (IOException e) {
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
            }
            if (c == -1)
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                            "expecting $subj or $req in ava pattern"));
            if (c == 'r') {
                try {
                    if (in.read() != 'e' ||
                            in.read() != 'q' ||
                            in.read() != '.')
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "expecting $req in ava pattern"));
                } catch (IOException e) {
                    throw new ELdapException(
                            CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
                }
                mType = TYPE_REQ;
                //System.out.println("---- mtype $req");
            } else if (c == 's') {
                try {
                    if (in.read() != 'u' ||
                            in.read() != 'b' ||
                            in.read() != 'j' ||
                            in.read() != '.')
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "expecting $subj in ava pattern"));
                } catch (IOException e) {
                    throw new ELdapException(
                            CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
                }
                mType = TYPE_SUBJ;
                //System.out.println("----- mtype $subj");
            } else if (c == 'e') {
                try {
                    if (in.read() != 'x' ||
                            in.read() != 't' ||
                            in.read() != '.')
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "expecting $ext in ava pattern"));
                } catch (IOException e) {
                    throw new ELdapException(
                            CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
                }
                mType = TYPE_EXT;
                //System.out.println("----- mtype $ext");
            } else {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                            "unknown keyword. expecting $subj $ext or $req."));
            }

            // get request attr name of subject dn pattern from above.
            String attrName = attrBuf.toString().trim();

            //System.out.println("----- attrName "+attrName);
            if (attrName.length() == 0)
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                        "attribute name expected"));
            mAttr = attrName;

            /*
             try {
             ObjectIdentifier attrOid =
             mLdapDNStrConverter.parseAVAKeyword(attrName);
             mAttr = mLdapDNStrConverter.encodeOID(attrOid);
             //System.out.println("----- mAttr "+mAttr);
             }
             catch (IOException e) {
             throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", e.toString()));
             }
             */

            // get request attribute or cert subject dn attribute

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
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
            }

            mValue = valueBuf.toString().trim();
            if (mValue.length() == 0)
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                            "$subj or $req attribute name expected"));
            //System.out.println("----- mValue "+mValue);

            // get nth dn xxx not nth request attribute .
            if (c == '.') {
                StringBuffer attrNumberBuf = new StringBuffer();

                try {
                    while ((c = in.read()) != ',' && c != -1 && c != '.'
                            && c != '+') {
                        //System.out.println("mElement read "+(char)c);
                        attrNumberBuf.append((char) c);
                    }
                    if (c == ',' || c == '+') // either ','  or '+'
                        in.unread(c); // pushback last , or +
                } catch (IOException e) {
                    throw new ELdapException(
                            CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
                }
                String attrNumber = attrNumberBuf.toString().trim();

                if (attrNumber.length() == 0)
                    throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                "nth element $req $ext or $subj expected"));
                try {
                    mElement = Integer.parseInt(attrNumber) - 1;
                } catch (NumberFormatException e) {
                    if (TYPE_REQ.equals(mType)) {
                        mPrefix = mValue;
                        mValue = attrNumber;
                    } else if (TYPE_EXT.equals(mType)) {
                        mGNType = attrNumber;
                    } else
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "Invalid format in nth element $req $ext or $subj"));

                    // get nth request attribute .
                    if (c == '.') {
                        StringBuffer attrNumberBuf1 = new StringBuffer();

                        try {
                            while ((c = in.read()) != ',' && c != -1 && c != '+') {
                                //System.out.println("mElement read "+(char)c);
                                attrNumberBuf1.append((char) c);
                            }
                            if (c != -1) // either ',' or '+'
                                in.unread(c); // pushback last , or +
                        } catch (IOException ex) {
                            throw new ELdapException(
                                    CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", ex.toString()));
                        }
                        String attrNumber1 = attrNumberBuf1.toString().trim();

                        if (attrNumber1.length() == 0)
                            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                        "nth element $req expected"));
                        try {
                            mElement = Integer.parseInt(attrNumber1) - 1;
                        } catch (NumberFormatException ex) {
                            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                        "Invalid format in nth element $req."));

                        }
                    }
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
            // read forward to get attribute value
            try {
                while ((c = in.read()) != ',' &&
                        c != -1) {
                    valueBuf.append((char) c);
                }
                if (c == '+' || c == ',') { // either ',' or '+'
                    in.unread(c); // pushback last , or +
                }
            } catch (IOException e) {
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
            }
            try {
                AVA ava = mLdapDNStrConverter.parseAVA(attrBuf + "=" + valueBuf);

                mValue = ava.toLdapDNString();
                //System.out.println("----- mValue "+mValue);
            } catch (IOException e) {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", e.toString()));
            }
        }
    }

    public String formAVA(IRequest req, X500Name subject, CertificateExtensions extensions)
            throws ELdapException {
        if (TYPE_CONSTANT.equals(mType))
            return mValue;

        if (TYPE_RDN.equals(mType)) {
            String dn = subject.toString();

            if (mTestDN != null)
                dn = mTestDN;
            //System.out.println("AVAPattern Using dn "+mTestDN);
            String[] rdns = LDAPDN.explodeDN(dn, false);

            if (mElement >= rdns.length)
                return null;
            return rdns[mElement];
        }

        if (TYPE_SUBJ.equals(mType)) {
            String dn = subject.toString();

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
            if (value == null) {
                CMS.debug(
                        "MapAVAPattern: attr " + mAttr +
                                " not formed from: cert subject " +
                                dn +
                                "-- no subject component : " + mValue);
                return null;
            }
            return mAttr + "=" + value;
        }

        if (TYPE_EXT.equals(mType)) {
            if (extensions != null) {
                for (int i = 0; i < extensions.size(); i++) {
                    Extension ext = extensions.elementAt(i);
                    String extName = OIDMap.getName(ext.getExtensionId());
                    int index = extName.lastIndexOf(".");

                    if (index != -1)
                        extName = extName.substring(index + 1);
                    if (extName.equals(mValue)) {
                        // Check the extensions one by one.
                        // For now, just give subjectAltName as an example.
                        if (mValue.equalsIgnoreCase(SubjectAlternativeNameExtension.NAME)) {
                            try {
                                GeneralNames subjectNames =
                                        (GeneralNames)
                                        ((SubjectAlternativeNameExtension) ext)
                                                .get(SubjectAlternativeNameExtension.SUBJECT_NAME);

                                if (subjectNames.size() == 0)
                                    break;
                                int j = 0;

                                for (Enumeration<GeneralNameInterface> n = subjectNames.elements(); n.hasMoreElements();) {
                                    GeneralName gn = (GeneralName) n.nextElement();
                                    String gname = gn.toString();

                                    index = gname.indexOf(":");
                                    if (index == -1)
                                        break;
                                    String gType = gname.substring(0, index);

                                    if (mGNType != null) {
                                        if (mGNType.equalsIgnoreCase(gType)) {
                                            if (mElement == j) {
                                                gname =
                                                        gname.substring(index + 2);
                                                return mAttr + "=" + gname;
                                            } else {
                                                j++;
                                            }
                                        }
                                    } else {
                                        if (mElement == j) {
                                            gname =
                                                    gname.substring(index + 2);
                                            return mAttr + "=" + gname;
                                        }
                                        j++;
                                    }
                                }
                            } catch (IOException e) {
                                CMS.debug(
                                        "MapAVAPattern: Publishing attr not formed from extension." +
                                                "-- no attr : " + mValue);
                            }
                        }
                    }
                }
            }
            CMS.debug(
                    "MapAVAPattern: Publishing:attr not formed from extension " +
                            "-- no attr : " + mValue);

            return null;
        }

        if (TYPE_REQ.equals(mType)) {
            // mPrefix and mValue are looked up case-insensitive
            String reqAttr = req.getExtDataInString(mPrefix, mValue);
            if (reqAttr == null) {
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_REQUEST",
                        mValue, mAttr));
            }
            return mAttr + "=" + reqAttr;
        }

        return null;
    }

    public String getReqAttr() {
        if (TYPE_REQ.equals(mType))
            return mValue;
        else
            return null;
    }

    public String getCertAttr() {
        if (TYPE_SUBJ.equals(mType))
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
