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
package com.netscape.admin.certsrv.security;

import com.netscape.management.nmclf.*;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import javax.swing.*;

import java.awt.SystemColor;
import java.util.*;
import java.io.*;

class KeyCertUtility {

    static ResourceSet _resource = null;
    public static ResourceSet getKeyCertWizardResourceSet() {
        if (_resource == null) {
            _resource = new ResourceSet("com.netscape.admin.certsrv.security.KeyCertWizardResource");
        }

        return _resource;
    }

    public static String createTokenName(ConsoleInfo consoleInfo) {
        String tokenName = "";

        tokenName = (String)(consoleInfo.get("SIE"));
        if (tokenName == null) {
            Debug.println("SIE entry was not set in the ConsoleInfo...");
            try {
                String currentDN = consoleInfo.getCurrentDN().toLowerCase();
                tokenName = currentDN.substring(currentDN.indexOf("cn=") +
                        3, currentDN.indexOf(","));
            } catch (Exception e2) {
                tokenName = "Unknow-Server";
            }
        }


        return (tokenName);
    }

    //replace any occurance of 'val' in 'oldStr' with 'replacement'
    public static String replace(String oldStr, String val,
            String replacement) {
        String output = new String(oldStr);

        int index;

        while ((index = output.indexOf(val)) != -1) {
            output = output.substring(0, index) + replacement +
                    output.substring(index + val.length());
        }

        return output;
    }

    //a valid is a password that has more then 8 character and contain one or more
    //none alphabetic character
    public static boolean validPassword(String passwd,
            String confirmPasswd, ConsoleInfo consoleInfo) {
        boolean valid = true;
        if (!(passwd.equals(confirmPasswd))) {
            valid = false;
            SuiOptionPane.showMessageDialog(consoleInfo.getFrame(),
                    getKeyCertWizardResourceSet().getString("KeyCertUtility",
                    "passwdMissMatch"));
            ModalDialogUtil.sleep();
        } else if (passwd.length() < 8) {
            valid = false;
            SuiOptionPane.showMessageDialog(consoleInfo.getFrame(),
                    getKeyCertWizardResourceSet().getString("KeyCertUtility",
                    "lessThen8Char"));
            ModalDialogUtil.sleep();
        } else {
            boolean allChar = true;
            int length = confirmPasswd.length();
            for (int i = 0; i < length; i++) {
                char ch = confirmPasswd.charAt(i);
                if (!((ch >= 'A') && (ch <= 'Z')) &&
                        !((ch >= 'a') && (ch <= 'z'))) {
                    allChar = false;
                    break;
                }
            }
            if (allChar) {
                valid = false;
                SuiOptionPane.showMessageDialog(consoleInfo.getFrame(),
                        getKeyCertWizardResourceSet().getString("KeyCertUtility",
                        "noNumericChar"));
                ModalDialogUtil.sleep();
            }
        }

        return valid;
    }
}
