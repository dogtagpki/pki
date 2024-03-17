/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/

package com.netscape.management.client.util;


/**
 * AcceptLanguage class definition.
 *
 * @see http://lemming/as40/javadoc/ for documentation
 * @see http://lemming/as40/javadoc/Main.java for sample
 */
public class AcceptLanguage {

    /**
     * Constructor creates an AcceptLanguage object with lang and q value.
     *
     * @param acceptlang  the accept language
     */
    public AcceptLanguage(String acceptlang) {
        acceptlang = acceptlang.trim();

        int tmp = acceptlang.indexOf(";");
        if (tmp == -1) {
            tmp = acceptlang.length();
            qvalue = Float.valueOf((float) 1.0);
        }
        lang = acceptlang.substring(0, tmp);

        if (acceptlang.length() != tmp) {
            qvalue = Float.valueOf(
                    acceptlang.substring(tmp + 3, acceptlang.length()));
        }
    }

    /**
      * Retrieves the lang value.
      *
      * @return  the lang value
      */
    public String getLang() {
        return lang;
    }

    /**
      * Retrieves the q value.
      *
      * @return  the q value
      */
    public float getQvalue() {
        return qvalue.floatValue();
    }

    private String lang;
    private Float qvalue;
}
