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
import java.util.Vector;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.X500Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.ldap.ELdapException;
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
 * Example2: <i>UID=$req.HTTP_PARAMS.uid, OU=$subj.ou, O=people, , O=mcom.com</i>
 * cert subject name: dn:  UID=jjames, OU=IS, O=people, , O=mcom.com
 * request attributes: uid: cmanager
 * <p>
 * The dn formulated will be : <br>
 *     UID=jjames, OU=IS, OU=people, O=mcom.com
 * <p>
 *     UID = the 'uid' attribute value in the request. <br>
 *     OU = the 'ou' value in the cert subject name.  <br>
 *     O = the string people, mcom.com. <br>
 * <p>
 * </pre>
 *
 * If an request attribute or subject DN component does not exist, the attribute is skipped.There is potential risk that
 * a wrong dn will be mapped into.
 *
 * @version $Revision$, $Date$
 */
class MapRDNPattern {

    /* the list of request attributes needed by this RDN  */
    protected String[] mReqAttrs = null;

    /* the list of cert attributes needed by this RDN  */
    protected String[] mCertAttrs = null;

    /* AVA patterns */
    protected MapAVAPattern[] mAVAPatterns = null;

    /* original pattern string */
    protected String mPatternString = null;

    protected String mTestDN = null;

    /**
     * Construct a DN pattern by parsing a pattern string.
     *
     * @param pattenr the DN pattern
     * @exception ELdapException If parsing error occurs.
     */
    public MapRDNPattern(String pattern)
            throws ELdapException {
        if (pattern == null || pattern.equals("")) {
            CMS.debug(
                    "MapDNPattern: null pattern");
        } else {
            mPatternString = pattern;
            PushbackReader in = new PushbackReader(new StringReader(pattern));

            parse(in);
        }
    }

    /**
     * Construct a DN pattern from a input stream of pattern
     */
    public MapRDNPattern(PushbackReader in)
            throws ELdapException {
        parse(in);
    }

    private void parse(PushbackReader in)
            throws ELdapException {
        //System.out.println("_________ begin rdn _________");
        Vector<MapAVAPattern> avaPatterns = new Vector<MapAVAPattern>();
        MapAVAPattern avaPattern = null;
        int lastChar;

        do {
            avaPattern = new MapAVAPattern(in);
            avaPatterns.addElement(avaPattern);
            //System.out.println("added AVAPattern"+
            //" mType "+avaPattern.mType+
            //" mAttr "+avaPattern.mAttr+
            //" mValue "+avaPattern.mValue+
            //" mElement "+avaPattern.mElement);
            try {
                lastChar = in.read();
            } catch (IOException e) {
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
            }
        } while (lastChar == '+');

        if (lastChar != -1) {
            try {
                in.unread(lastChar); // pushback last ,
            } catch (IOException e) {
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_INTERNAL_ERROR", e.toString()));
            }
        }

        mAVAPatterns = new MapAVAPattern[avaPatterns.size()];
        avaPatterns.copyInto(mAVAPatterns);

        Vector<String> reqAttrs = new Vector<String>();

        for (int i = 0; i < mAVAPatterns.length; i++) {
            String avaAttr = mAVAPatterns[i].getReqAttr();

            if (avaAttr == null || avaAttr.length() == 0)
                continue;
            reqAttrs.addElement(avaAttr);
        }
        mReqAttrs = new String[reqAttrs.size()];
        reqAttrs.copyInto(mReqAttrs);

        Vector<String> certAttrs = new Vector<String>();

        for (int i = 0; i < mAVAPatterns.length; i++) {
            String avaAttr = mAVAPatterns[i].getCertAttr();

            if (avaAttr == null || avaAttr.length() == 0)
                continue;
            certAttrs.addElement(avaAttr);
        }
        mCertAttrs = new String[certAttrs.size()];
        certAttrs.copyInto(mCertAttrs);
    }

    /**
     * Form a Ldap v3 DN string from a request and a cert subject name.
     *
     * @param req the request for (un)publish
     * @param subject the subjectDN of the certificate
     * @return Ldap v3 DN string to use for base ldap search.
     */
    public String formRDN(IRequest req, X500Name subject, CertificateExtensions ext)
            throws ELdapException {
        StringBuffer formedRDN = new StringBuffer();

        for (int i = 0; i < mAVAPatterns.length; i++) {
            if (mTestDN != null)
                mAVAPatterns[i].mTestDN = mTestDN;
            String ava = mAVAPatterns[i].formAVA(req, subject, ext);

            if (ava != null && ava.length() > 0) {
                if (formedRDN.length() != 0)
                    formedRDN.append("+");
                formedRDN.append(ava);
            }
        }
        //System.out.println("formed RDN "+formedRDN.toString());
        return formedRDN.toString();
    }

    public String[] getReqAttrs() {
        return mReqAttrs.clone();
    }

    public String[] getCertAttrs() {
        return mCertAttrs.clone();
    }
}
