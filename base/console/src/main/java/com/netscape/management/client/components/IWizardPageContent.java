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

import javax.swing.JComponent;

/**
 * Wizard page's contents interface which allows wizard
 * to query individule page for content wizard should
 * display when the page come up.
 *
 * @see IWizardPageContent
 * @see IWizardPageValidator
 * @see WizardPage
 */
public interface IWizardPageContent
{
    /**
     * Called by wizard to get step title
     *
     * @return step title
     */
    public String getStepName();

    /**
     * Called by wizard when "Help" button was pushed
     *
     */
    public void helpInvoked();

    /**
     * Called by wizard to get the text on 'Next' button
     *
     * @return button text (replace "Next >"/"Done" text on Next button) or null (do not replace)
     *
     */
    //public String getNextButtonText();

    /**
     * Called by wizard when next button is clicked.
     *
     * @return true if wizard may continue to next page
     */
    public boolean nextInvoked();

    /**
     * Called by wizard when back button is clicked.
     *
     * @return true if wizard may continue to previous page
     */
    public boolean backInvoked();

    /**
     *
     * Call by wizard before it attempt to bring up the page
     *
     */
    public void pageShown();

    /**
     * tell wizard whether or not help button should be shown
     *
     * @return true if help button is to be shown false otherwise.
     *
     */
    public boolean isHelpButtonVisible();



    /**
     * Call to get any advance buttons that need to be display for
     * this perticular page.
     *
     * @return component to be add to the most left side of wizard button panel.
     */
    public JComponent getExtraButtonComponent();




    /**
     * Called by wizard to get wizard image/component.  Image/component will
     * get displayed on the left hand pane, next to content pane
     *
     * @return component (to be displayed on left hand pane), or null (nothing to display)
     */
    public JComponent getGraphicComponent();


    /**
     *
     * @return max number of possible steps
     */
    public int getMaxSteps();

}
