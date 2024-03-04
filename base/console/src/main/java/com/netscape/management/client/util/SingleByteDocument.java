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

import java.awt.*;
import javax.swing.*;
import javax.swing.text.*;

/**
 * SingleByteDocument is a document model which only accept single byte input.
 * If the user types in any double bytes character, it will popup a
 * warning dialog.
 *
 * @author  Terence Kwan (terencek@netscape.com)
 *
 * @see     com.netscape.management.client.util.SingleByteTextField
 * @see     com.netscape.management.client.util.SingleBytePasswordField
 */

public class SingleByteDocument extends PlainDocument {
    static ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");
    static String _sEnableSingleByte = null;
    static boolean _fSingleByte = false;
    JComponent _parent;

    /**
     * constructor. Check for the global parameter in the
     * com.netscape.management.client.util.default.properties file to see whether
     * we need to turn on the double bytes checking.
     */
    SingleByteDocument(JComponent parent) {
        _parent = parent;
        if (_sEnableSingleByte == null) {

            _sEnableSingleByte = _resource.getString("global","singlebytepassword");
            if ((_sEnableSingleByte != null) &&
                    (_sEnableSingleByte.equalsIgnoreCase("true"))) {
                _fSingleByte = true;
            }
        }
    }

    /**
      * If the user types in double bytes character and double bytes checking
      * is turn on, popup a warning messaging.
      *
      * @param offs offset
      * @param str string input
      * @param a attribute set of the string
      */
    public void insertString(int offs, String str,
            AttributeSet a) throws BadLocationException {
        if (_fSingleByte == false) {
            super.insertString(offs, str, a);
        } else {
            if (str == null) {
                return;
            }
            StringBuffer buff = new StringBuffer();
            boolean fDisplayError = false;
            for (int i = 0; i < str.length(); i++) {
                char c = str.charAt(i);
                if (c <= 0x007F) {
                    buff.append(c);
                } else {
                    fDisplayError = true;
                }
            }
            /**
              * display error dialog
              */
            if (fDisplayError) {
                error();
            }
            super.insertString(offs, buff.toString(), a);
        }
    }

    public void error() {
        try {
            Toolkit tk = Toolkit.getDefaultToolkit();
            tk.beep();
        } catch (AWTError e) {
        }
    }
}
