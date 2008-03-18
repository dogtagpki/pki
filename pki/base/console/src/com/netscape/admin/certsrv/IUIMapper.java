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
 * UI Mapper Interface
 *
 * The UIMapper is intended for the editing and
 * the display of the certificate attributes. This
 * includes most the certificate attributes and extensions
 * defined in PKCS and PKIX.
 *
 * Each Individual UI Mapper should provide the methods
 * defined in this interface. It must extends the
 * JFC JPanel object. The UI Mapper should not exceeds
 * the size of 400(Width)x450(Height). Use of LayoutManager
 * is recommended.
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv
 */
public interface IUIMapper {

    /**
     * Retrieve the attr name.
     * The name will be presented to the user (i.e. Key Usage, Basic Constraints)
     *
     * @return attribute name
     */
    public String getName();

    /**
     * Retrieve the attr description.
     * The description will be use as tool tip on the extension selection
     * screen.
     *
     * @return description or null if none
     */
    public String getDesc();
    
    /**
     * Is this UI provide edit panel
     */
    public boolean isEditable(); 
    
    /**
     * Is this UI Provide display panel
     */
    public boolean isDisplayable(); 
    
    /**
     * Is this UI provide search filter panel
     */
    public boolean isFilterable(); 
    
    /**
     * retrieve Editor Panel
     * isEditable() will be called before this operation is
     * used.
     */
    public IEditorPanel getEditorPanel(); 
    
    /**
     * retrieve Display Panel
     */
    public IDisplayPanel getDisplayPanel(); 
    
    /**
     * Retrieve Filter Panel
     */
    public IFilterPanel getFilterPanel(); 

}
