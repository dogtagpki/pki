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

import java.util.*;


/**
 * AcceptLanguageList class definition.
 *
 * @see http://lemming/as40/javadoc/ for documentation
 * @see http://lemming/as40/javadoc/Main.java for sample
 */
public class AcceptLanguageList {

    /**
     * Contructor creates an AcceptLanguageList object containing Vector of
     * languages according qvalue
     *
     * @param qlist
     */
    public AcceptLanguageList(String qlist) {
        String string_buffer;
        int int_buffer, size = qlist.length(), prior = 0, i;
        lang_list = new Vector();

        for (i = 0; i < size; i++) {
            if (i == size - 1) {
                insertLang(
                        new AcceptLanguage(qlist.substring(prior, i + 1)));
            }

            if (qlist.charAt(i) == ',') {
                insertLang(
                        new AcceptLanguage(qlist.substring(prior, i++)));
                prior = i;
            }
        }
    }

    /**
      * Retrieves the language list vector.
      *
      * @return  the language list vector
      */
    public Vector getList() {
        return lang_list;
    }

    /**
      * Inserts language according to qvalue
      *
      * @param lang  AcceptLanguage object
      */
    private void insertLang(AcceptLanguage lang) {
        int tmp = lang_list.size(), i;
        float qvalue1, qvalue2;
        for (i = 0; i < tmp; i++) {
            qvalue1 = ((AcceptLanguage) lang_list.elementAt(i)).getQvalue();
            qvalue2 = lang.getQvalue();

            if (qvalue1 < qvalue2)
                break;
        }
        lang_list.insertElementAt(lang, i);
    }

    private Vector lang_list;
}
