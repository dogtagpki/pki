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

import java.io.File;
import java.awt.*;
import javax.swing.*;
import javax.swing.border.*;

/**
 * A set of utility methods relating to UI functionality.
 */
public class UITools {

    static public final String OS_WIN32 = "Win32";
    static public final String OS_UNIX = "Unix (Generic)";

    public static Border createLoweredBorder() {
        return UIManager.getBorder("TextField.border");
    }

    public static void constrain(Container container,
            Component component, int gx, int gy, int gw, int gh,
            double wx, double wy, int a, int f, int top, int left,
            int bottom, int right) {
        GridBagUtil.constrain(container, component, gx, gy, gw, gh, wx,
                wy, a, f, top, left, bottom, right);
    }


    /**
       * Return menu label stripped of & menu mnemonic
       */
    public static String getDisplayLabel(String label) {
        if (label != null) {
            int mnemonicIndex = label.indexOf('&');
            if (mnemonicIndex != -1) {
                try {
                    char mnemonicChar =
                            label.charAt(mnemonicIndex + 1); // given "a&bc", return 'b'
                            String tmpLabel =
                            label.substring(0, mnemonicIndex); // return "a"
                            String dispLabel = tmpLabel.concat(
                            label.substring(mnemonicIndex + 1)); // concat "bc"
                            return dispLabel;
                } catch (StringIndexOutOfBoundsException e) {
                    System.out.println("label.length() = " +
                            label.length());
                    System.out.println("start = " + (mnemonicIndex + 1));
                    System.out.println("diff = " +
                            (label.length() - mnemonicIndex));
                    System.err.println("Error parsing menu label: " +
                            label);
                }
            }
        }
        return label;
    }

    /**
       * Return mnemonic character (char following &) from menu label
       */
    public static char getMnemonic(String label) {
        if (label != null) {
            int mnemonicIndex = label.indexOf('&');
            if (mnemonicIndex != -1) {
                try {
                    char mnemonicChar =
                            label.charAt(mnemonicIndex + 1); // given "a&bc", return 'b'
                            return mnemonicChar;
                } catch (StringIndexOutOfBoundsException e) {
                    System.err.println(
                            "Error parsing menu mnemonic: " + label);
                }
            }
        }
        return 0;
    }


    /**
     * Returns client OS in form of a String( UITools.OS_WIN32 OR UITools.OS_UNIX )
     *
     */
    static public String getOS() {
        if (File.separatorChar == '\\') {
            return OS_WIN32;
        } else {
            return OS_UNIX;
        }
    }
}



