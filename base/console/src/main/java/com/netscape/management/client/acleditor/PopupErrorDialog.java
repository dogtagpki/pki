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
package com.netscape.management.client.acleditor;

import com.netscape.management.client.util.Debug;
import com.netscape.management.nmclf.*;

class PopupErrorDialog implements Runnable, ACLEditorConstants {
    protected String message;
    protected String windowTitle;
    protected ACLEditorWindow parent;

    public PopupErrorDialog(ACLEditorWindow window, String msg,
            String title) {
        parent = window;
        message = msg;
        windowTitle = title;
        (new Thread(this)).start();
    }

    public void run() {
        if (message == null) {
            Debug.println("ACLEditorWindow():popupErrorDialog(): null message");
            return;
        }
        if (windowTitle == null) {
            Debug.println("ACLEditorWindow():popupErrorDialog(): null windowTitle");
            return;
        }

        // limit message to lines of length LINE_LENGTH

        int len = message.length();

        if (len <= LINE_LENGTH) {
            SuiOptionPane.showMessageDialog(parent, message,
                    windowTitle, SuiOptionPane.ERROR_MESSAGE);
            return;
        }

        int num = len / LINE_LENGTH + (((len % LINE_LENGTH) > 0) ? 1 : 0);

        String[] lines = new String[num];

        int i = 0;
        int i1 = 0;
        int i2 = LINE_LENGTH - 1;

        while (i1 < len) {
            while (i2 < len) {
                char c = message.charAt(i2++);

                if ((c == ' ') || (c == ',') || (c == '-'))
                    break;
            }

            lines[i++] = message.substring(i1, i2);

            i1 = i2;
            i2 = Math.min(len, i2 + LINE_LENGTH - 1);
        }

        SuiOptionPane.showMessageDialog(parent, lines, windowTitle,
                SuiOptionPane.ERROR_MESSAGE);
    }
}
