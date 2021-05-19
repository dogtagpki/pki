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

import com.netscape.admin.certsrv.*;

/**
 * Netscape Certificate Server 4.0 Deafult Base TAB
 * This class is the base class for all the TAB panels.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public abstract class CMSBaseTab extends CMSBaseConfigPanel
  implements IRefreshTab {

    /*==========================================================
     * variables
     *==========================================================*/
     protected CMSTabPanel mParent;

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSBaseTab(String panelName, CMSTabPanel parent) {
        super(panelName);
        mParent = parent;
        add("Center", mCenterPanel);
    }

    /*==========================================================
	 * protected methods
     *==========================================================*/

    //set dirty flag
    @Override
    protected void setDirtyFlag() {
        super.setDirtyFlag();
        mParent.setDirtyTab(this);
    }

    //clear dirty flag
    @Override
    protected void clearDirtyFlag() {
        super.clearDirtyFlag();
        mParent.clearDirtyTab(this);
    }

    //=== OVERWRITE DIALOG MESSAGE =====================

    @Override
    protected void showMessageDialog(String keyword, int messageType ) {
        CMSAdminUtil.showMessageDialog(mParent.mModel.getFrame(), mResource, mPanelName, keyword, messageType);
    }

    @Override
    protected void showMessageDialog(String keyword) {
        showMessageDialog(keyword, ERROR_MESSAGE);
    }

    @Override
    protected int showConfirmDialog(String keyword, int messageType ) {
        return CMSAdminUtil.showConfirmDialog(mParent.mModel.getFrame(), mResource, mPanelName, keyword, messageType);
    }

    @Override
    protected int showConfirmDialog(String keyword) {
        return showConfirmDialog(keyword, WARNING_MESSAGE);
    }

    @Override
    protected void showErrorDialog(String message) {
        CMSAdminUtil.showErrorDialog(mParent.mModel.getFrame(), mResource, message, ERROR_MESSAGE);
    }

    @Override
    public void refresh() {
    }
}

