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
package com.netscape.management.client.components;
/**
 * Wizard page's validator interface which allows wizard
 * to query individule page if back/next/cancel button should
 * be enabled.
 *
 * @see IWizardPageContent
 * @see IWizardPageValidator
 * @see WizardPage
 */
public interface IWizardPageValidator
{

    /**
     *
     * @return true if page can proceed to next page, false (Next button will be disabled) otherwise
     */
    public boolean canMoveForward();

    /**
     *
     * @return true if page can go back to previous page, false (Back button will be disabled) otherwise
     */
    public boolean canMoveBackward();

    /**
     *
     * @return true if page can be cancled, false (Cancel button will be disabled) otherwise
     */
    public boolean canCancel();
}
