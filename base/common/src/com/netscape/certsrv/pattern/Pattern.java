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
package com.netscape.certsrv.pattern;

import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IAttrSet;

/**
 * This is a generic pattern subtitution engine. The
 * pattern format should be:
 * <p>
 * $[attribute set key].[attribute name]$
 * <p>
 * For example,
 * <p>
 * $request.requestor_email$ $ctx.user_id$
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class Pattern {

    private String mS = null;

    /**
     * Constructs a pattern object with the given string.
     *
     * @param s string with pattern (i.e. $request.requestor_email$)
     */
    public Pattern(String s) {
        mS = s;
    }

    /**
     * Subtitutes this pattern with the given attribute set.
     *
     * @param key key name of the given attribute set
     * @param attrSet attribute set
     * @return substituted string
     */
    public String substitute(String key, IAttrSet attrSet) {
        return substitute2(key, attrSet);
    }

    /**
     * Subtitutes this pattern with the given attribute set.
     *
     * @param attrSetCollection attribute set collection
     * @return substituted string
     */
    public String substitute(AttrSetCollection attrSetCollection) {
        String temp = mS;
        Enumeration<String> keys = attrSetCollection.keys();

        while (keys.hasMoreElements()) {
            String key = (String) keys.nextElement();
            Pattern p = new Pattern(temp);

            temp = p.substitute(key,
                        attrSetCollection.getAttrSet(key));

        }
        return temp;
    }

    /**
     * Subtitutes this pattern with the given attribute set.
     *
     * This is an extended version of the substitute() method.
     * It takes a more flexible pattern format that could have
     * non-token ($...$) format. e.g.
     * $request.screenname$@redhat.com
     * where "@redhat.com" is not in token pattern format, and will be
     * literally put in place. e.g.
     * TomRiddle@redhat.com
     *
     * @param key key name of the given attribute set
     * @param attrSet attribute set
     * @return substituted string
     */
    public String substitute2(String key, IAttrSet attrSet) {
        StringBuffer sb = new StringBuffer();

        int startPos = 0;
        int lastPos;

        do {
            // from startPos to right before '$' or end of string
            // need to be copied over

            lastPos = mS.indexOf('$', startPos);

            // if no '$', return the entire string
            if (lastPos == -1 && startPos == 0)
                return mS;

            // no more '$' found, copy the rest of chars, done
            if (lastPos == -1) {
                sb.append(mS.substring(startPos)); //
                return sb.toString(); //
                //                continue;
            }

            // found '$'
            if (startPos < lastPos) {
                sb.append(mS.substring(startPos, lastPos));
            }

            // look for the ending '$'
            int endPos = mS.indexOf('$', lastPos + 1);
            String token = mS.substring(lastPos + 1, endPos);
            int dotPos = token.indexOf('.');

            // it's assuming there's always a '.'
            String attrKey = token.substring(0, dotPos);
            String attrName = token.substring(dotPos + 1);

            if (!key.equals(attrKey)) {
                startPos = endPos + 1;
                sb.append("$" + attrKey + "." + attrName + "$");
                continue;
            }

            try {
                Object o = attrSet.get(attrName);

                if (!(o instanceof String)) {
                    startPos = endPos + 1;
                    // if no such attrName, copy the token pattern over
                    sb.append("$" + attrKey + "." + attrName + "$");
                    continue;
                }
                String val = (String) o;

                sb.append(val);
            } catch (EBaseException e) {
                sb.append("$" + attrKey + "." + attrName + "$");
            }
            startPos = endPos + 1;
        } while (lastPos != -1);

        return sb.toString();
    }

}
