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
package com.netscape.admin.certsrv.menu;

import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.ug.*;
import java.awt.*;

/**
 * Refresh Tab Pane
 *
 * This class is responsible for refreshing the selected tab pane
 * when user selects the refresh menu item
 *
 * @author Christine Ho
 * @author jpanchen
 *
 * @version $Revision$, $Date$
 *
 * @see com.netscape.admin.certsrv.IRefreshTab
 * @see com.netscape.admin.certsrv.IRefreshTabPanel
 * @see com.netscape.admin.certsrv.CMSBaseResourceModel
 * @see com.netscape.admin.certsrv.IMenuAction
 */
public class RefreshTabPane implements IMenuAction {

    /*==========================================================
     * variables
     *==========================================================*/
    protected IRefreshTabPanel mPanel;  //object ref to selected tab pane


    /*==========================================================
     * constructors
     *==========================================================*/
     
    /**
     * Default Constructor that creates the refresh menu
     * call back item.
     */
    public RefreshTabPane(CMSBaseResourceModel model) {
        model.setRefreshCallback(this);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
     
    /**
     * perform the refresh function on the selected
     * tab panel, if the tab panel support the IRefreshTab
     * intreface.
     */
    public void perform(IPage viewInstance) {
        if (mPanel != null) {
            if (mPanel instanceof IRefreshTabPanel) {
                CMSBasePanel panel = mPanel.getSelectedTab();
                if (panel instanceof IRefreshTab) {
                    IRefreshTab tab = (IRefreshTab)panel;
                    tab.refresh();
                }
            }
        }
    }
    
    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/ 

    /**
     * Accepts the selection notification from the
     * resource model. we must verify the class and
     * determine if the tab support the IRefreshTab
     * interface. If not, null is set.
     */
    public void select(Component c) {
        if (c instanceof IRefreshTabPanel) {
            mPanel = (IRefreshTabPanel)c;
        } else {
            mPanel = null;
        }
    }
}
