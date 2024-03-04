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

package com.netscape.management.client.util;

import javax.swing.*;
import javax.swing.border.*;

import java.awt.*;
import java.awt.event.*;


//import com.netscape.page.*;

import com.netscape.management.nmclf.SuiConstants;


/**
 * An implementation of a generic wizard dialog.
 *
 * @see IWizardControl
 * @see IWizardControlPage
 */
public class Wizard extends AbstractDialog {

    private IWizardPageControl wizPages;

    private boolean onLastPage = false;
    private JPanel currentPage = null;
    private JPanel currentPanel = new JPanel();
    private JButton bNext, bBack, bCancel, bHelp;


    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");

    private IWizardControl wizardControl = new WizardControlListener();

    /*public Wizard(JFrame parent) {
    super(parent, "", true);
    JPanel mainPanel = new JPanel();
    mainPanel.setLayout(new BorderLayout());
    mainPanel.add("Center", currentPanel);
    mainPanel.add("South", getControlButtons());


    setSize(400,400);
    getContentPane().add(mainPanel);
}*/

    public Wizard(JFrame parent, String title, IWizardPageControl pages) {

        super(parent, title, true);

        pages.setOwner(wizardControl);

        wizPages = pages;

        currentPanel.setLayout(new BorderLayout());

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());
        mainPanel.add(currentPanel);
        mainPanel.add("South", getControlButtons());

        wizardControl.setCanGoBackword(false);

        setSize(400, 400);
        getContentPane().add(mainPanel);
    }


    private JPanel getControlButtons() {
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        controlPanel.setBorder(
                new EmptyBorder(SuiConstants.VERT_WINDOW_INSET, 0, 0, 0));

        WizardActionListener listener = new WizardActionListener();

        bBack = JButtonFactory.create(_resource.getString(null, "BackButtonLabel"));
        bBack.setToolTipText(_resource.getString(null, "BackButton_tt"));
        bBack.addActionListener(listener);
        bBack.setActionCommand("BACK");
        controlPanel.add(bBack);

        controlPanel.add( Box.createRigidArea(
                new Dimension(SuiConstants.COMPONENT_SPACE, 0)));

        bNext = JButtonFactory.create(_resource.getString(null, "NextButtonLabel"));
        bNext.setToolTipText(_resource.getString(null, "NextButton_tt"));
        bNext.addActionListener(listener);
        bNext.setActionCommand("NEXT_DONE");
        controlPanel.add(bNext);

        controlPanel.add( Box.createRigidArea(
                new Dimension(SuiConstants.SEPARATED_COMPONENT_SPACE, 0)));

        bCancel = JButtonFactory.createCancelButton(listener);
        controlPanel.add(bCancel);

        controlPanel.add( Box.createRigidArea(
                new Dimension(SuiConstants.SEPARATED_COMPONENT_SPACE, 0)));

        bHelp = JButtonFactory.createHelpButton(listener);
        controlPanel.add(bHelp);

        JButtonFactory.resizeGroup(bHelp, bCancel, bNext, bBack);

        return controlPanel;
    }

    class WizardControlListener implements IWizardControl {
        //set enable/disable next button
        public void setCanGoForward(boolean enabled) {
            try {
                bNext.setEnabled(enabled);
            } catch (Exception e) {}
        }

        //set enable/disable prev button
        public void setCanGoBackword(boolean enabled) {
            try {
                bBack.setEnabled(enabled);
            } catch (Exception e) {}
        }

        public void setIsLastPage(boolean lastPage) {
            try {
                if (lastPage) {
                    //change 'Next' to 'Done'
                    bNext.setText(_resource.getString(null, "DoneButtonLabel"));
                    onLastPage = lastPage;
                } else {
                    //change 'Done' to 'Next'
                    bNext.setText(_resource.getString(null, "NextButtonLabel"));
                    onLastPage = lastPage;
                }
            } catch (Exception e) {}
        }

        public void nextInvoked() {
            if (onLastPage) {
                wizPages.wizardCompleted();
                dispose();
            } else {
                currentPanel.remove(wizPages.getCurrentPage());
                currentPanel.add(wizPages.getNextPage());
                currentPanel.validate();
                currentPanel.repaint();
                wizPages.getCurrentPage().repaint();
            }
        }

        public void backInvoked() {
            currentPanel.remove(wizPages.getCurrentPage());
            currentPanel.add(wizPages.getPrevPage());
            currentPanel.validate();
            currentPanel.repaint();
            wizPages.getCurrentPage().repaint();
        }

        public void cancelInvoked() {
            wizPages.wizardCanceled();
            dispose();
        }
    }

    class WizardActionListener implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            if (event.getActionCommand().equals("NEXT_DONE")) {
                wizardControl.nextInvoked();
            } else if (event.getActionCommand().equals("BACK")) {
                wizardControl.backInvoked();
            } else if (event.getActionCommand().equals("CANCEL")) {
                wizardControl.cancelInvoked();
            } else if (event.getActionCommand().equals("HELP")) {
                wizPages.helpInvoked();
            }
        }
    }

    public void start() {
        currentPanel.add(wizPages.getCurrentPage());
        super.setVisible(true);
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.setSize(0,0);
     f.show();

     try {
      UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
      SwingUtilities.updateComponentTreeUI(f.getContentPane());
     } catch (Exception e) {}

     Wizard w = new Wizard(f);
     w.start();
     }*/
}
