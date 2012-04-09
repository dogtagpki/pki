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
// package statement //
///////////////////////

package com.netscape.cms.publish.mappers;

///////////////////////
// import statements //
///////////////////////

/* cert server imports */
import java.io.IOException;
import java.io.PushbackReader;
import java.io.StringReader;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.ldap.LDAPDN;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.Extension;
import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNameInterface;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.OIDMap;
import netscape.security.x509.SubjectAlternativeNameExtension;
import netscape.security.x509.X500Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.publish.ECompSyntaxErr;
import com.netscape.certsrv.request.IRequest;

//////////////////////
// class definition //
//////////////////////

/**
 * avaPattern is a string representing an ldap
 * attribute formulated from the certificate
 * subject name, extension or request attributes.
 * <p>
 *
 * The syntax is
 *
 * <pre>
 *     avaPattern := constant-value |
 *                   "$subj" "." attrName [ "." attrNumber ] |
 *                   "$req" "." [ prefix .] attrName [ "." attrNumber ] |
 *                   "$ext" "." extName [ "." nameType ] [ "." attrNumber ]
 * </pre>
 *
 * <pre>
 * Example: <i>$ext.SubjectAlternativeName.RFC822Name.1</i>
 * cert subjectAltName is rfc822Name: jjames@mcom.com
 * <p>
 * The ldap attribute formulated will be : <br>
 *     jjames@mcom.com
 * <p>
 *     The first rfc822name value in the subjAltName extension.  <br>
 * <p>
 * </pre>
 *
 * If a request attribute or subject DN component does not exist, the attribute is skipped.
 *
 * @version $Revision$, $Date$
 */
class AVAPattern {
    ////////////////
    // parameters //
    ////////////////

    /* the value type of the dn component */
    public static final String TYPE_REQ = "$req";
    public static final String TYPE_SUBJ = "$subj";
    public static final String TYPE_EXT = "$ext";
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

    /* the list of request attributes needed by this AVA  */
    protected String[] mReqAttrs = null;

    /* the list of cert attributes needed by this AVA*/
    protected String[] mCertAttrs = null;

    /* value type */
    protected String mType = null;

    /* value - could be name of a request  attribute or
     * cert subject attribute or extension name.
     */
    protected String mValue = null;

    /* value type - general name type of an
     *              extension attribute if any.
     */
    protected String mGNType = null;

    /* prefix - prefix of a request attribute if any. */
    protected String mPrefix = null;

    /* nth value of the ldap or dn attribute */
    protected int mElement = 0;

    protected String mTestDN = null;

    /////////////
    // methods //
    /////////////

    public AVAPattern(String component)
            throws ELdapException {
        if (component == null || component.length() == 0) {
            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", component));
        }

        parse(new PushbackReader(new StringReader(component)));
    }

    public AVAPattern(PushbackReader in)
            throws ELdapException {
        parse(in);
    }

    private void parse(PushbackReader in)
            throws ELdapException {
        int c;

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

        if (c == -1) {
            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX", "All blank"));
        }

        if (c == '$') {
            // check for $subj $ext or $req
            try {
                c = in.read();
            } catch (IOException e) {
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
            }

            if (c == -1) {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                            "expecting $subj $ext or $req in ava pattern"));
            }

            if (c == 'r') {
                try {
                    if (in.read() != 'e' ||
                            in.read() != 'q' ||
                            in.read() != '.') {
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "expecting $req in ava pattern"));
                    }
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
                            in.read() != '.') {
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "expecting $subj in ava pattern"));
                    }
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
                            in.read() != '.') {
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "expecting $ext in ava pattern"));
                    }
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

            // get request attribute or
            // cert subject or
            // extension attribute

            StringBuffer valueBuf = new StringBuffer();

            try {
                while ((c = in.read()) != ',' &&
                        c != -1 && c != '.' && c != '+') {
                    //System.out.println("mValue read "+(char)c);
                    valueBuf.append((char) c);
                }

                if (c == '+' || c == ',') { // either ',' or '+'
                    in.unread(c); // pushback last , or +
                }
            } catch (IOException e) {
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
            }

            mValue = valueBuf.toString().trim();
            if (mValue.length() == 0) {
                throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                            "$subj $ext or $req attribute name expected"));
            }
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

                    if (c == ',' || c == '+') { // either ','  or '+'
                        in.unread(c); // pushback last , or +
                    }
                } catch (IOException e) {
                    throw new ELdapException(
                            CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
                }

                String attrNumber = attrNumberBuf.toString().trim();

                if (attrNumber.length() == 0) {
                    throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                "nth element $req $ext or $subj expected"));
                }

                try {
                    mElement = Integer.parseInt(attrNumber) - 1;
                } catch (NumberFormatException e) {

                    if (TYPE_REQ.equals(mType)) {
                        mPrefix = mValue;
                        mValue = attrNumber;
                    } else if (TYPE_EXT.equals(mType)) {
                        mGNType = attrNumber;
                    } else {
                        throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "Invalid format in nth element " +
                                            "$req $ext or $subj"));
                    }

                    // get nth request attribute .
                    if (c == '.') {
                        StringBuffer attrNumberBuf1 = new StringBuffer();

                        try {
                            while ((c = in.read()) != ',' &&
                                    c != -1 && c != '+') {
                                //System.out.println("mElement read "+
                                //                   (char)c);
                                attrNumberBuf1.append((char) c);
                            }

                            if (c != -1) { // either ',' or '+'
                                in.unread(c); // pushback last , or +
                            }
                        } catch (IOException ex) {
                            throw new ELdapException(
                                    CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", ex.toString()));
                        }

                        String attrNumber1 =
                                attrNumberBuf1.toString().trim();

                        if (attrNumber1.length() == 0) {
                            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                    "nth element $req or $ext expected"));
                        }

                        try {
                            mElement = Integer.parseInt(attrNumber1) - 1;
                        } catch (NumberFormatException ex) {
                            throw new ECompSyntaxErr(CMS.getUserMessage("CMS_AUTHENTICATION_COMPONENT_SYNTAX",
                                        "Invalid format in nth element " +
                                                "$req or $ext."));
                        }
                    }
                }
            }
            //System.out.println("----- mElement "+mElement);
        } else {
            // value is constant. treat as regular ava.
            mType = TYPE_CONSTANT;

            // parse ava value.
            StringBuffer valueBuf = new StringBuffer();

            valueBuf.append((char) c);

            // read forward to get attribute value
            try {
                while ((c = in.read()) != ',' && c != -1) {
                    valueBuf.append((char) c);
                }

                if (c == '+' || c == ',') { // either ',' or '+'
                    in.unread(c); // pushback last , or +
                }
            } catch (IOException e) {
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
            }

            mValue = valueBuf.toString().trim();

            /*  try {
             *      AVA ava = mLdapDNStrConverter.parseAVA(
             *                    valueBuf.toString());
             *      mValue = ava.toLdapDNString();
             *      //System.out.println("----- mValue "+mValue);
             *  } catch (IOException e) {
             *      throw new ECompSyntaxErr(e.toString());
             *  }
             */
        }
    }

    public String formAVA(IRequest req,
            X500Name subject,
            CertificateExtensions extensions)
            throws ELdapException {
        if (TYPE_CONSTANT.equals(mType)) {
            return mValue;
        }

        if (TYPE_SUBJ.equals(mType)) {
            String dn = subject.toString();

            if (mTestDN != null) {
                dn = mTestDN;
            }

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
                return null;
            }

            return value;
        }

        if (TYPE_EXT.equals(mType)) {

            if (extensions != null) {

                for (int i = 0; i < extensions.size(); i++) {
                    Extension ext = extensions.elementAt(i);

                    String extName =
                            OIDMap.getName(ext.getExtensionId());

                    int index = extName.lastIndexOf(".");

                    if (index != -1) {
                        extName = extName.substring(index + 1);
                    }

                    if (extName.equals(mValue)) {
                        // Check the extensions one by one.
                        // For now, just give subjectAltName
                        // as an example.
                        if (mValue.equalsIgnoreCase(
                                SubjectAlternativeNameExtension.NAME)) {
                            try {
                                GeneralNames subjectNames = (GeneralNames)
                                        ((SubjectAlternativeNameExtension)
                                        ext).get(
                                                SubjectAlternativeNameExtension.SUBJECT_NAME);

                                if (subjectNames.size() == 0) {
                                    break;
                                }

                                int j = 0;

                                for (Enumeration<GeneralNameInterface> n =
                                        subjectNames.elements(); n.hasMoreElements();) {

                                    GeneralName gn = (GeneralName)
                                            n.nextElement();

                                    String gname = gn.toString();

                                    index = gname.indexOf(":");

                                    if (index == -1) {
                                        break;
                                    }

                                    String gType =
                                            gname.substring(0, index);

                                    if (mGNType != null) {
                                        if (mGNType.equalsIgnoreCase(gType)) {
                                            if (mElement == j) {
                                                gname =
                                                        gname.substring(index + 2);
                                                return gname;
                                            } else {
                                                j++;
                                            }
                                        }
                                    } else {
                                        if (mElement == j) {
                                            gname =
                                                    gname.substring(index + 2);
                                            return gname;
                                        }
                                        j++;
                                    }
                                }
                            } catch (IOException e) {
                                CMS.debug(
                                        "AVAPattern: Publishing attr not formed " +
                                                "from extension " +
                                                "-- no attr : " +
                                                mValue);
                            }
                        }
                    }
                }
            }

            CMS.debug(
                    "AVAPattern: Publishing:attr not formed " +
                            "from extension " +
                            "-- no attr : " +
                            mValue);

            return null;
        }

        if (TYPE_REQ.equals(mType)) {
            // mPrefix and mValue are looked up case-insensitive
            String reqAttr = req.getExtDataInString(mPrefix, mValue);
            if (reqAttr == null) {
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_NO_REQUEST", mValue, ""));
            }

            return reqAttr;
        }

        return null;
    }

    public String getReqAttr() {
        if (TYPE_REQ.equals(mType)) {
            return mValue;
        } else {
            return null;
        }
    }

    public String getCertAttr() {
        if (TYPE_SUBJ.equals(mType)) {
            return mValue;
        } else {
            return null;
        }
    }

    /**
     * Explode RDN into AVAs.
     * Does not handle escaped '+'
     * Java ldap library does not yet support multiple avas per rdn.
     * If RDN is malformed returns empty array.
     */
    public static String[] explodeRDN(String rdn) {
        int plus = rdn.indexOf('+');

        if (plus == -1) {
            return new String[] { rdn };
        }

        Vector<String> avas = new Vector<String>();

        StringTokenizer token = new StringTokenizer(rdn, "+");

        while (token.hasMoreTokens()) {
            avas.addElement(token.nextToken());
        }

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

        if (equals == -1) {
            return null;
        }

        return new String[] { ava.substring(0, equals).trim(),
                ava.substring(equals + 1).trim() };
    }
}
