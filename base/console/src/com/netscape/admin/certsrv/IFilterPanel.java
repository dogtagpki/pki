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
 * Filter Panel Interface
 *
 * The Filter Panel is plugable UI intended for constructing search filter for
 * the certificate attributes. It will contain the Filter type, operation type,
 * and construct the filter string to be used by the database mapper.
 *
 * <XXX DOCUMENT PANEL SIZE>
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 */
public interface IFilterPanel {

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
    public boolean validateFilterPanelContent();

    /**
     * name of this filter type. should be the same as attribute name.
     */
    public String getFilterIdentifier();

    /**
     * string representation of operation type
     */
    public String getFilterOperation();

    /**
     * Actual filter string to be passed on to the server side.
     * ie. (KeyUsage==1000111)
     */
    public String getFilterString();

    /**
     * Retrieve the error message to be displayed to the user
     */
    public String getErrorMessage();
}