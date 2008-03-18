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
package com.netscape.admin.certsrv;

/**
 * Editor Panel Interface
 *
 * The Editor Panel is plugable UI intended for the editing of the
 * certificate attributes. It will contain editing components only.
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv
 */
public interface IEditorPanel {

    /**
     * Set the data associated with this ui
     */
    public void setEditorPanelContent(IAttributeContent content);

    /**
     * validate the content contained in this panel. Called when
     * the user pressed ok button.
     *
     * this method should return false if the selections
     * made by the user is not acceptable. ie. no selection made.
     *
     * getErrorMessage() will be called to retrieve the message
     * and displayed to the user.
     */
    public boolean validateEditorPanelContent();

    /**
     * retrieve the attribute content from the editing panel.
     * this method will be called after the validation has been
     * performed.
     */
    public IAttributeContent getEditorPanelContent();

    /**
     * Retrieve the error message to be displayed to the user
     */
    public String getErrorMessage();
}