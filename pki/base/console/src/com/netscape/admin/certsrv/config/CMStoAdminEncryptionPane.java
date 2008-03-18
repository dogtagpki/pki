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
package com.netscape.admin.certsrv.config;

import com.netscape.admin.certsrv.security.EncryptionPane;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;

/**
 * Encryption set preference panel glue between CMS and KingPin
 *
 * @author Christina Fu (cfu)
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 * @see com.netscape.management.admserv.config
 */

/* replace "implements ActionListener" with
 *"implements IPluginConfigPanel" when the 
 * com.netscape.management.admserv.config.* package is available

public class CMStoAdminEncryptionPane extends EncryptionPane implements IPluginConfigPanel{
*/
public class CMStoAdminEncryptionPane extends EncryptionPane 
    implements ActionListener
{
    protected boolean mEncryptionPaneDirty = false;

    public CMStoAdminEncryptionPane(ConsoleInfo consoleInfo) {
        super(consoleInfo);
    }

   /**
    * overrides the super class action listener
    */
    public void actionPerformed(ActionEvent e) {
        Debug.println("CMStoAdminEncryptionPane: actionPerformed()");
        mEncryptionPaneDirty = true;
    }

    public boolean isDirty() {
        return mEncryptionPaneDirty;
    }
}
