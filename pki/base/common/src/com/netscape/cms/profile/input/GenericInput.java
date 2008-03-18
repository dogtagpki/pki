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
package com.netscape.cms.profile.input;


import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;


/**
 * This class implements a generic input.
 * <p>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class GenericInput extends EnrollInput implements IProfileInput { 

    public static final String CONFIG_NUM = "gi_num";
    public static final String CONFIG_DISPLAY_NAME = "gi_display_name";
    public static final String CONFIG_PARAM_NAME = "gi_param_name";
    public static final String CONFIG_ENABLE = "gi_param_enable";

    public static final int DEF_NUM = 5;

    public GenericInput() {
      int num = getNum();
      for (int i = 0; i < num; i++) {
        addConfigName(CONFIG_PARAM_NAME + i);
        addConfigName(CONFIG_DISPLAY_NAME + i);
        addConfigName(CONFIG_ENABLE + i);
      }
    }

    protected int getNum() {
        int num = DEF_NUM;
        String numC = getConfig(CONFIG_NUM);

        if (numC != null) {
            try {
                num = Integer.parseInt(numC);
            } catch (NumberFormatException e) {
                // ignore
            }
        }
        return num;
    }

    /**
     * Initializes this default policy.
     */
    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_GENERIC_NAME_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_GENERIC_NAME_TEXT");
    }

    /**
     * Returns selected value names based on the configuration.
     */
    public Enumeration getValueNames() {
         Vector v = new Vector();
         int num = getNum();
         for (int i = 0; i < num; i++) {
             String enable = getConfig(CONFIG_ENABLE + i);
             if (enable != null && enable.equals("true")) {
               v.addElement(getConfig(CONFIG_PARAM_NAME + i));
             }
         }
         return v.elements();
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IProfileContext ctx, IRequest request)
        throws EProfileException {
        int num = getNum();
        for (int i = 0; i < num; i++) {
             String enable = getConfig(CONFIG_ENABLE + i);
             if (enable != null && enable.equals("true")) {
                String param = getConfig(CONFIG_PARAM_NAME + i);
                request.setExtData(param, ctx.get(param));
             }
        }
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        int num = getNum();
        for (int i = 0; i < num; i++) {
          if (name.equals(CONFIG_PARAM_NAME + i)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_GI_PARAM_NAME") + i);
          } else if (name.equals(CONFIG_DISPLAY_NAME + i)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_GI_DISPLAY_NAME") + i);
          } else if (name.equals(CONFIG_ENABLE + i)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_GI_ENABLE") + i);
          }
        } // for
        return null;
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        int num = getNum();
        for (int i = 0; i < num; i++) {
             String param = getConfig(CONFIG_PARAM_NAME + i);
             if (param != null && param.equals(name)) {
               return new Descriptor(IDescriptor.STRING, null,
                    null,
                    getConfig(CONFIG_DISPLAY_NAME + i));
             }
        }
        return null;
    }
}
