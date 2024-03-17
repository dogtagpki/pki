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
package com.netscape.management.client.preferences;

import java.util.*;
import com.netscape.management.client.console.*;

/**
 * Implements partial functionality to create,
 * access, and enumerate Preferences objects,
 * which are groups of preference settings.
 *
 * @author  ahakim@netscape.com
 * @see Preferences
 */
public abstract class PreferenceManager {
    private static Hashtable _pmTable = new Hashtable();
    private static boolean _isStoredLocally = false;

    protected String _product;
    protected String _version;

    protected PreferenceManager(String product, String version) {
        _product = product;
        _version = version;
    }

    public static boolean getLocalStorageFlag() {
        return _isStoredLocally;
    }

    // TODO: throwException if called more than once
    // this is intended to be called from Console during login
    public static void setLocalStorageFlag(boolean b) {
        _isStoredLocally = b;
    }

    public static PreferenceManager getPreferenceManager(
            String product, String version) {
        PreferenceManager pm =
                (PreferenceManager)_pmTable.get(product + version);
        if (pm == null) {
            if (_isStoredLocally || Console.getConsoleInfo() == null) {
                pm = new FilePreferenceManager(product, version);
                _isStoredLocally = true;
            } else {
                ConsoleInfo ci = Console.getConsoleInfo();
                pm = new LDAPPreferenceManager(ci.getLDAPConnection(),
                        ci.getUserPreferenceDN(), product, version);
            }
            _pmTable.put(product + version, pm);
        }
        return pm;
    }

    public String getProduct() {
        return _product;
    }

    public String getVersion() {
        return _version;
    }

    public abstract String[] getPreferencesList();

    public abstract Preferences getPreferences(String group);

    public abstract void savePreferences();

    public abstract boolean isPreferencesDirty();

    public static PreferenceManager[] getPreferenceManagerList() {
        PreferenceManager pmArray[] =
                new PreferenceManager[_pmTable.size()];

        Enumeration e = _pmTable.elements();
        for (int i = 0; e.hasMoreElements(); i++) {
            pmArray[i] = (PreferenceManager) e.nextElement();
        }
        return pmArray;
    }

    public static boolean isSaveNeeded() {
        PreferenceManager pm[] = getPreferenceManagerList();
        if (pm != null) {
            for (int i = 0; i < pm.length; i++) {
                if (pm[i].isPreferencesDirty())
                    return true;
            }
        }
        return false;
    }

    public static void saveAllPreferences() {
        PreferenceManager pm[] = getPreferenceManagerList();
        if (pm != null) {
            for (int i = 0; i < pm.length; i++) {
                pm[i].savePreferences();
            }
        }
    }

    public static void clearAllPreferences() {
        PreferenceManager pm[] = getPreferenceManagerList();
        if (pm != null) {
            for (int i = 0; i < pm.length; i++) {
                String group[] = pm[i].getPreferencesList();
                for (int j = 0; j < group.length; j++) {
                    Preferences p = pm[i].getPreferences(group[j]);
                    p.clear();
                    p.delete();
                }
            }
        }
    }
}
