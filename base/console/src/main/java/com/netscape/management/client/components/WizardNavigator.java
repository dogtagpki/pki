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
/*
=====================================================================

        WizardNavigator.java

=====================================================================
*/

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

/**
 * This is navigator panel which contain Next, Back, Cancel, and Help.
 * Next button also act as customizable button, which will change
 * to Done if last page is reached.  If developer preferred they can
 * change the text by use the IWizardPageContent.getNextButtonText()
 * api.
 *
 * This gui work with sequence manager to manipulate it's button.
 * (enable/disable buttons)
 * It also work with WizardDialog to manipulate which page should
 * be displayed.  How page are swapped in and out, or how
 * it is display is all up to wizard dialog.
 *
 * @see WizardDialog
 * @see IWizardSequenceManager
 * @see IWizardPageContent
 * @see IWizardPageValidator
 */
class WizardNavigator extends JPanel
        implements ActionListener, ChangeListener
{
    JButton m_back, m_next, m_help, m_cancel;
    //JPanel  m_advancedPanel = new JPanel();
    IWizardSequenceManager m_sequenceManager;
    Wizard m_wizardDialog;
    int index = 1;

    ResourceSet _resource = new ResourceSet("com.netscape.management.client.components.Wizard");


    /**
     * Create a wizard navigator which contain back, next, cancel, and help button.
     *
     * @param wizard
     * @param sequenceManager
     */
    public WizardNavigator(Wizard wizard, IWizardSequenceManager sequenceManager) {
        m_wizardDialog = wizard;
        m_sequenceManager = sequenceManager;

        setOpaque(true);

        //setLayout(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        setLayout(new GridBagLayout());
        setBorder(new EmptyBorder(SuiConstants.DIFFERENT_COMPONENT_SPACE, SuiConstants.HORIZ_WINDOW_INSET, SuiConstants.VERT_WINDOW_INSET, SuiConstants.HORIZ_WINDOW_INSET));


        //add back button
        m_back = JButtonFactory.create(_resource.getString(null, "BackButtonLabel"));
        m_back.addActionListener(this);
        m_back.setActionCommand("BACK");
        add(m_back);
        //add( Box.createRigidArea(new Dimension(SuiConstants.COMPONENT_SPACE, 0)));

        //add next buton
        m_next = JButtonFactory.create(_resource.getString(null, "NextButtonLabel"));
        m_next.addActionListener(this);
        m_next.setActionCommand("NEXT");
        //add(m_next);
        //add( Box.createRigidArea(new Dimension(SuiConstants.SEPARATED_COMPONENT_SPACE, 0)));


        //add cancel button
        m_cancel = JButtonFactory.createCancelButton(this);
        /*m_cancel = JButtonFactory.create(_resource.getString(null, "CancelButtonLabel"));
        m_cancel.addActionListener(this);
        m_cancel.setActionCommand("CANCEL");*/
        //add(m_cancel);
        //add( Box.createRigidArea( new Dimension(SuiConstants.SEPARATED_COMPONENT_SPACE, 0)));


        //add help button
        m_help = JButtonFactory.createHelpButton(this);
        /*m_help = JButtonFactory.create(_resource.getString(null, "HelpButtonLabel"));
        m_help.addActionListener(this);
        m_help.setActionCommand("HELP");*/
        //add(m_help);

        //resize button to all same size
        JButtonFactory.resizeGroup(m_help, m_cancel, m_next, m_back);

        int x = 0;
        /*GridBagUtil.constrain(this, m_advancedPanel,
                              x, 0, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);*/

        GridBagUtil.constrain(this, Box.createHorizontalGlue(),
                              ++x, 0, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, m_back,
                              ++x, 0, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.NONE,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, m_next,
                              ++x, 0, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.NONE,
                              0, 0, 0, SuiConstants.SEPARATED_COMPONENT_SPACE);

        GridBagUtil.constrain(this, m_cancel,
                              ++x, 0, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.NONE,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, m_help,
                              ++x, 0, 1, 1,
                              0.0, 0.0, GridBagConstraints.WEST, GridBagConstraints.NONE,
                              0, SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0);

    }


    /**
     * Listen for button action
     *
     * @param event button events
     */
    public void actionPerformed(ActionEvent event) {
        Object source = event.getSource();

        if (source == m_back) {
            //when back button is clicked
            if (((IWizardPageContent)m_wizardDialog.getPage(m_sequenceManager.getCurrent())).backInvoked()) {
                index--;
                setPanel(m_sequenceManager.getPrevious(m_sequenceManager.getCurrent()));
            }
        } else if (source == m_next) {
            if (((IWizardPageContent)m_wizardDialog.getPage(m_sequenceManager.getCurrent())).nextInvoked()) {

                //when next button is clicked
                index++;
                if (m_next.getText().equals(_resource.getString(null, "FinishButtonLabel"))) {
                    getTopLevelAncestor().setVisible(false);
                    //Debug.println("We're done");
                } else {
                    setPanel(m_sequenceManager.getNext(m_sequenceManager.getCurrent()));
                }
            }
        } else if (source == m_cancel) {
            //when cancel button is clicked, need a final confirmation to hide the dialog
            if (JOptionPane.showConfirmDialog(m_wizardDialog,
                                              _resource.getString(null, "sure"),
                                              _resource.getString(null, "cancelConfirmTitle"),
                                              JOptionPane.YES_NO_OPTION)==JOptionPane.YES_OPTION) {
                getTopLevelAncestor().setVisible(false);
            }
            //Debug.println("User canceled");
        } else if (source == m_help) {
            //when help is clicked, tell the paga to pop up context sensitive help
            ((IWizardPageContent)m_wizardDialog.getPage(m_sequenceManager.getCurrent())).helpInvoked();
        }

    }

    /**
     * Called if an event has occure to the current page.
     *
     * @param event event that occures
     */
    public void stateChanged(ChangeEvent event) {
        checkValidation(m_sequenceManager.getCurrent());
    }

    /**
     * Validate if a page can proceed (back or next) or canceled
     * If a page can't proceed (back or next) then button
     * (back, next, cancel) button will be gray out accordingly
     *
     * This api also responsible for changing the nextbutton string
     * when page panel's getNextButtonText is not null
     *
     * @param id page id
     */
    public void checkValidation(String id) {
        if (m_wizardDialog.getPage(id) instanceof IWizardPageValidator) {
            IWizardPageValidator validator = ((IWizardPageValidator)m_wizardDialog.getPage(id));

            m_next.setEnabled(validator.canMoveForward());
            m_back.setEnabled(validator.canMoveBackward());
            m_cancel.setEnabled(validator.canCancel());

            /*if ((validator instanceof IWizardPageContent) && (((IWizardPageContent)validator).getNextButtonText() != null)) {
                m_next.setText(((IWizardPageContent)validator).getNextButtonText());
            } else {
                if (m_sequenceManager.isLast(id)) {
                    m_next.setText(_resource.getString(null, "FinishButtonLabel"));
                } else {
                    m_next.setText(_resource.getString(null, "NextButtonLabel"));
                }
            }*/

            paintAll(getGraphics());
        }
    }

    /**
     * Setups up which page get displayed next
     *
     * @param id page id
     */
    public void setPanel(String id) {
        //tell wizard to display page with specified id
        m_wizardDialog.setPanel(id, index);

        //need to determain whcih button need to enable/disable
        checkValidation(id);



        //disable back button if first page has been reached
        m_back.setVisible(!m_sequenceManager.getFirst().equals(id));
        m_back.setEnabled(!m_sequenceManager.getFirst().equals(id));


        IWizardPageContent content = null;

       //remove advanced button pane left over from previous page
        if ((m_sequenceManager.getPrevious(id) != null) && (((String)m_sequenceManager.getPrevious(id)).length() > 0)) {
            //get previous page
            content = (IWizardPageContent)m_wizardDialog.getPage(m_sequenceManager.getPrevious(id));
            if (content.getExtraButtonComponent() != null) {
                this.remove(content.getExtraButtonComponent());
            }
        }

        if ((m_sequenceManager.getNext(id) != null) && (((String)m_sequenceManager.getNext(id)).length() > 0)) {
            //get next page
            content = (IWizardPageContent)m_wizardDialog.getPage(m_sequenceManager.getNext(id));
            if (content.getExtraButtonComponent() != null) {
                this.remove(content.getExtraButtonComponent());
            }
        }


        //get current page
        content = ((IWizardPageContent)m_wizardDialog.getPage(id));

        /*if (content != null) {
            System.out.println("index:"+index);
            System.out.println("max:"+content.getMaxSteps());
        }*/
        //change Next to Done if page display is the last page
        if ((content != null) &&
            ((content.getMaxSteps()==index) ||
             ((content.getMaxSteps()<=0) && m_sequenceManager.isLast(id)))){
//(m_sequenceManager.isLast(id)) {
            //if ((content.getMaxSteps() == index) && m_sequenceManager.isLast(id)) {
            m_next.setText(_resource.getString(null, "FinishButtonLabel"));
        } else {
            m_next.setText(_resource.getString(null, "NextButtonLabel"));
        }


        //get advanced button pane and added to the button panel
        if (content.getExtraButtonComponent() != null) {
            GridBagUtil.constrain(this, content.getExtraButtonComponent(),
                                  0, 0, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                  0, 0, 0, 0);
        }

        //tell the page it is going to be shown
        content.pageShown();

        //show or hide help button
        m_help.setVisible(content.isHelpButtonVisible());

        //repaint
        paintAll(getGraphics());
    }
}
