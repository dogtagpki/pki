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
package com.netscape.certsrv.base;


import java.util.Locale;


/**
 * Plugin which can return extended information to console
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class ExtendedPluginInfo implements IExtendedPluginInfo {

    private String _epi[] = null;

    /**
     * Constructs an extended plugin info object.
     *
     * @param epi plugin info list
     */
    public ExtendedPluginInfo(String epi[]) {
        _epi = epi;
    }

    /**
     *  This method returns an array of strings. Each element of the
     *  array represents a configurable parameter, or some other
     *  meta-info (such as help-token)
     * 
     *  there is an entry indexed on that parameter name
     *  <param-name>;<type_info>[,required];<description>;...
     *  
     *  Where:
     *
     *    type_info is either 'string', 'number', 'boolean', 'password' or 
     *        'choice(ch1,ch2,ch3,...)'
     *
     *    If the marker 'required' is included after the type_info,
     *    the parameter will has some visually distinctive marking in
     *    the UI.
     * 
     *    'description' is a short sentence describing the parameter
     *    'choice' is rendered as a drop-down list. The first parameter in the
     *       list will be activated by default
     *    'boolean' is rendered as a checkbox. The resulting parameter will be
     *       either 'true' or 'false'
     *	  'string' allows any characters
     *	  'number' allows only numbers
     *    'password' is rendered as a password field (the characters are replaced
     *       with *'s when being types. This parameter is not passed through to
     *       the plugin. It is instead inserted directly into the password cache
     *       keyed on the instance name. The value of the parameter
     *       'bindPWPrompt' (see example below) is set to the key.
     *
     *  In addition to the configurable parameters, the following magic parameters
     *  may be defined:
     *  
     *    HELP_TOKEN;helptoken - a pointer to the online manual section for this plugin
     *    HELP_TEXT;helptext   - a general help string describing the plugin
     *
     *   For example:
     *    "username;string;The username you wish to login as"
     *    "bindPWPrompt;password;Enter password to bind as above user with"
     *    "algorithm;choice(RSA,DSA);Which algorithm do you want to use"
     *    "enable;boolean;Do you want to run this plugin"
     *    "port;number;Which port number do you want to use"
     *
     */
    public String[] getExtendedPluginInfo(Locale locale) {
        return _epi;
    }
}
