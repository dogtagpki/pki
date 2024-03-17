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
import javax.swing.JPanel;
import javax.swing.JComponent;
/**
 * Defines the common behaviors for all wizard page.
 *
 * <br><br>
 * <img SRC="images/WizardTemplate.gif" height=360 width=483>
 * <br>
 *
 *  <b>Step Name</b> Name for the current page. (required)  <br>
 *  <b>Step Number (x of y) </b>  x = Current step number, y = total number of steps. (required) <br>
 *  <b>Graphic Area </b> pictorial representation of current step or task (optional) <br>
 *  <b>Back Button </b> goes to previous step, if available <br>
 *  <b>Next Button </b> goes to next step or completes the wizard operation.  For the last step, the button is labeled Finish <br>
 *  <b>Cancel Button </b> aborts the wizard operation, if user answers yes to cancel confirmation dialog (fig 8) <br>
 *  <b>Help Button </b> Displays context sensitive help <br>
 *  <b>Extra Button/Components</b> Extra button/components (no shown) to be added to the left most button panel.
 *
 * <br><br>
 * Controllable elements:<br>
 * 1. enable/disable back button - canMoveBackward() <br>
 * 2. enable/disalbe next button - canMoveForward() <br>
 * 3. enable/disalbe cancel button - canCancel() <br>
 * 4. show/hide help button - showHelpButton() <br>
 * 5. add graphics - getGraphicComponent() <br>
 * 6. page content - WizardPage extends JPanel, so page it self is the content <br>
 * 7. set step name - step is a required parameter for contructor <br>
 * 8. total number of step - getMaxSteps() <br>
 * 9. add extra button (Advanced button for example) - getExtraButtonComponent() <br>
 * <br><br>
 * Default value and behavior<br>
 * 1. back button are enabled by default, and will not be shown on first page <br>
 * 2. next button are disabled by default, if last page is encounter it will change to "Done" <br>
 * 3. cancel buton are enabled by default <br>
 * 4. help button are shown by default <br>
 * 5. by default there will be no garphics component. <br>
 * 6. by default there won't be any extra button added. <br>
 * 7. by default total number of step are total number of pages added to the wizard <br>
 * 8. wizard will compute current number of step, no setting is reqired or allowed <br>
 *
 * @see IWizardPageContent
 * @see IWizardPageValidator
 */
public abstract class WizardPage extends JPanel
         implements IWizardPageValidator, IWizardPageContent
{

    /* allow user to proceed to next page - default false */
    protected boolean m_canMoveForward  = false;
    /* allow user to proceed to previous page - default true */
    protected boolean m_canMoveBackward = true;
    /* allow user to cancel current wizard - default true */
    protected boolean m_canCancel       = true;
    /* show help button - default true */
    protected boolean m_showHelpButton  = true;
    //protected String  m_nextButtonText = null;
    private /*protected*/ IDataCollectionModel m_dataCollection = null;
    private /*protected*/ IWizardSequenceManager m_sequenceManager = null;
    private /*protected*/ String  m_stepName = "";

    /**
     * Create a wizard page
     *
     * @param stepName the step name
     */
    public WizardPage(String stepName) {
        super();
        m_stepName = stepName;
        getAccessibleContext().setAccessibleDescription(stepName);
    }

    /**
     *
     * @return true if wizard can proceed to next page, false otherwise.  Default false
     *
     */
    public boolean canMoveForward() {
        return m_canMoveForward;
    }

    /**
     *
     * @return true if wizard can be canceled, false otherwise.  Default true
     *
     */
    public boolean canCancel() {
        return m_canCancel;
    }

    /**
     *
     * @return true if wizard can back to previous page, false otherwise. Default true
     *
     */
    public boolean canMoveBackward() {
        return m_canMoveBackward;
    }

    /**
     * tell wizard whether or not help button should be shown
     *
     * @return true if help button is to be shown false otherwise.
     */
    public boolean isHelpButtonVisible() {
        return m_showHelpButton;
    }

    /**
     * Call by wizard to get any special purpose buttons/component that need
     * to be display for this perticular page.  The component obtained will be
     * added to the left most side of the button panel.
     *
     * @return component to be add to the most left side of wizard button panel, or null (default) if no component need to be added.
     *
     */
    public JComponent getExtraButtonComponent() {
        return null;
    }

    /**
     * Called by wizard when next button got clicked.
     *
     * This function complements IWizardPageValidator.canMoveForward();
     * It allows developer to pop dialog or do final checking
     * before wizard continues to next page.
     *
     * @return true if wizard may continue to next page
     */
    public boolean nextInvoked() {
        return true;
    }

    /**
     * Called by wizard when back button got clicked.
     *
     * @return true if wizard may continue to previous page
     */
    public void helpInvoked() {
        //System.out.println("NOT YET IMPLEMENTED");
    }

    /**
     * Called by wizard when "back" button got clicked
     *
     */
    public boolean backInvoked() {
        return true;
    }

    /**
     * Call by wizard before it attempt to bring up the page for display
     *
     */
    public void pageShown() {}

    /**
     * Called by wizard to get the text on 'Next' button
     *
     * @return button text (replace "Next >"/"Done" text on Next button) or null (do not replace/use default)
     *
     */
    /*public String getNextButtonText() {
        return m_nextButtonText;
    }*/

    /**
     * Called by wizard to get step name
     *
     * @return step name
     */
    public String getStepName() {
        return m_stepName;
    }

    /**
     * Called by wizard to get wizard image/component.  Image/component will
     * get displayed on the left hand pane, next to content pane
     *
     * @return component (to be displayed on left hand pane), or null (nothing to display)
     */
    public JComponent getGraphicComponent() {
         return null;
    }

    /**
     * Set data collection model
     *
     * @param dataCollection the data collection model
     */
    public void setDataModel(IDataCollectionModel dataCollection) {
        m_dataCollection = dataCollection;
    }


    /**
     * Set wizard sequence manager
     *
     * @param sequenceManager the sequence manager
     */
    public void setSequenceManager(IWizardSequenceManager sequenceManager) {
        m_sequenceManager = sequenceManager;
    }

    /**
     *
     * @return data collection model used by the wizard
     *
     */
    public IDataCollectionModel getDataModel() {
        return m_dataCollection;
    }


    /**
     *
     * @return sequence manager used by the wizard
     *
     */
    public IWizardSequenceManager getSequenceManager() {
        return m_sequenceManager;
    }


    /**
     *
     * @return max number of possible steps, default -1 (wizard dialog will use total number of pages added to wizard as maximum steps)
     */
    public int getMaxSteps() {
        return -1;
    }
}



