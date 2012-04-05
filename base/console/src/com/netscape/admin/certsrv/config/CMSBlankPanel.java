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

import com.netscape.management.client.*;
import com.netscape.admin.certsrv.*;

/**
 * Blank Panel to be displayed at the right hand side
 *  we should place some ads here... =-)
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CMSBlankPanel extends CMSBaseTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "CMSBLANKPANEL";

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSBlankPanel(ResourceModel model) {
        super(PANEL_NAME, null);
    }

    public CMSBlankPanel(ResourceModel model, CMSTabPanel parent, String name) {
        super(PANEL_NAME, parent);
        setTitle(name);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Actual Instanciation of the UI components
     */
    public void init() {
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        return true;
    }

    /**
     * Implementation for reset values
     * @return true if save successful; otherwise, false.
     */
    public boolean resetCallback() {
        return true;
    }

    /**
     * Implementation for calling help
     */
    public void helpCallback() {
    }

}
