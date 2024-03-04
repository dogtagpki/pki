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

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import com.netscape.management.client.util.*;

/**
 * <code>StatusDialog</code> reports progress of long running tasks.
 * StatusDialog is by default a modeless dialog.
 * 
 * See this document for more information.
 * http://lupine.mcom.com/console/4.5/ui/commonUI.htm#Status Dialog
 * 
 * @author Andy Hakim
 * @author Thu Le
 */
public class StatusDialog extends GenericDialog implements UIConstants
{
    /** Constant for <B>Close</B> button. */
    public final static int CLOSE = 1;
    
    /** Constant for <B>Stop</B> button. */
    public final static int STOP = 2;
    
    /** Constant representing <B>Close</B> and <B>Stop</B> buttons. */
    public final static int CLOSE_STOP = CLOSE | STOP;

    /** Used to disable confirmation dialogs. */
    public final static int CONFIRM_NONE = 0;
    
    /** Used to enable confirmation dialog on <B>Close</B> button press. */
    public final static int CONFIRM_CLOSE = 1;
    
    /** Used to enable confirmation dialog on <B>Stop</B> button press. */
    public final static int CONFIRM_STOP = 2;

    private Frame parentFrame;
    private String lblClose = i18n("close");
    private String lblStop = i18n("stop");
	private String lblDetails = i18n("details");
    private int confirmationFlags = CONFIRM_NONE;
    private JButton closeButton, stopButton, detailButton;
    private JLabel iconLabel = new JLabel();
    private JLabel descriptionLabel = new JLabel();
    private JLabel progressLabel = new JLabel();
    private JProgressBar progressBar = new JProgressBar();
    private Container contentPane;
    private JComponent detailComponent = null;
    private boolean isDetailVisible = true;
    private boolean isInitialized = false;
    private int showDelay = 0;  // minimum time to wait until popup, if progress < 100
    private int hideDelay = 0;  // minimum time to wait to hide once displayed
    private javax.swing.Timer showTimer = null;
    private javax.swing.Timer hideTimer = null;
    private long showStartTime = 0;
	private static ResourceSet resource = new ResourceSet("com.netscape.management.client.components.components");

	private static String i18n(String id)
	{
        return resource.getString("statusDialog", id);
    }
            
    /**
     * Constructs StatusDialog with specified parent frame, title and description.
     * 
     * @param parentFrame JFrame to which this dialog is positioned relative to.
     * @param dialogTitle string that appears on title bar
     * @param descriptionText string that specifies the task being performed
     */
    public StatusDialog(JFrame parentFrame, String dialogTitle, String descriptionText)
    {
        super(parentFrame, dialogTitle, NO_BUTTONS);
        setModal(false);
        this.parentFrame = parentFrame;
		descriptionLabel.setText(descriptionText);
    }
    
    /**
     * Makes the Dialog visible.
     * 
     * @see #setVisible
     */
    public void show()
	{
        if(!isInitialized)
        {
            isInitialized = true;
            initialize();
        }
        super.show();
    }

    /**
     * Shows or hides this component depending on the value of parameter b.
     * The visibility of the dialog may be delayed if setShowDelay or
     * setHideDelay are used.
     * 
     * @param b - If true, shows this dialog; otherwise, hides this dialog.
     * @see #setShowDelay
     * @see #setHideDelay
     */
    public void setVisible(boolean b)
    {
        if(b == true)
        {
            showStartTime = System.currentTimeMillis();
            if(hideTimer != null)
            {
                hideTimer.stop();
                hideTimer = null;
            }
            if(showDelay > 0 && showTimer == null && getProgressValue() < 100)
            {
                showTimer = new javax.swing.Timer(showDelay, new ActionListener()
                    {
                        public void actionPerformed(ActionEvent e)
                        {
                            setVisible(true);
                        }
                    });
                showTimer.setRepeats(false);
                showTimer.start();
                return;
            }
        }
        else        
        if(b == false)
        {
            if(showTimer != null)
            {
                showTimer.stop();
                showTimer = null;
            }
            int showElapsedTime = (int)(System.currentTimeMillis() - showStartTime);
            if(hideDelay > 0 && hideTimer == null && (showElapsedTime < hideDelay))
            {
                hideTimer = new javax.swing.Timer(hideDelay - showElapsedTime, new ActionListener()
                    {
                        public void actionPerformed(ActionEvent e)
                        {
                            setVisible(false);
                        }
                    });
                hideTimer.setRepeats(false);
                hideTimer.start();
                return;
            }
        }
        
        super.setVisible(b);
    }
    
    private void initialize()
    {
        contentPane = getContentPane();
        GridBagLayout g = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        contentPane.setLayout(g);
        
        c.insets = new Insets(0, 0, 0, 0);
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 2;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.CENTER;
        c.weightx = 0;
        c.weighty = 0;
        g.setConstraints(iconLabel, c);
        contentPane.add(iconLabel);
        
        descriptionLabel.setHorizontalAlignment(SwingConstants.CENTER);
        c.insets = new Insets(0, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.anchor = GridBagConstraints.CENTER;
        c.weightx = 1;
        c.weighty = 1;
        g.setConstraints(descriptionLabel, c);
        contentPane.add(descriptionLabel);
        
        progressLabel.setHorizontalAlignment(SwingConstants.CENTER);
        c.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        c.gridx = 1;
        c.gridy = 1;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.weightx = 1;   
        c.weighty = 0;
        c.anchor = GridBagConstraints.CENTER;
        g.setConstraints(progressLabel, c);
        contentPane.add(progressLabel);
        
        Dimension d = progressBar.getPreferredSize();
        d.width = Math.max(300, d.width);
        progressBar.setPreferredSize(d);
        
        c.gridx = 0;
        c.gridy = 2;
        c.gridwidth = 2;
        c.gridheight = 1;
        c.weightx = 1;
        c.weighty = 0;
        c.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
        g.setConstraints(progressBar, c);
        contentPane.add(progressBar);
        
        detailComponent = createDetailComponent();
        if(detailComponent != null)
        {
            c.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
            c.fill = GridBagConstraints.BOTH;
            c.gridx = 0;
            c.gridy = 3;
            c.gridwidth = 3;
            c.gridheight = 1;
            c.weightx = 1;
            c.weighty = 0;
            g.setConstraints(detailComponent, c);
            contentPane.add(detailComponent);
        }

        closeButton = JButtonFactory.create(lblClose,new CloseButtonActionListener(),"CLOSE");
        closeButton.setToolTipText(i18n("close_tt"));
        stopButton = JButtonFactory.create(lblStop, new StopButtonActionListener(),"STOP");
        stopButton.setToolTipText(i18n("stop_tt"));

        // adding "Close" button into the content pane
        c.weightx = 0;
        c.weighty = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.insets = new Insets(0, SEPARATED_COMPONENT_SPACE, 0, 0);
        c.gridx = 2;
        c.gridy = 0;
        c.anchor = GridBagConstraints.SOUTH;
        g.setConstraints(closeButton, c);
        contentPane.add(closeButton);
    
        // adding "Stop" button into the content pane
        c.gridy = 1;
        c.insets = new Insets(COMPONENT_SPACE, SEPARATED_COMPONENT_SPACE, 0, 0);
        g.setConstraints(stopButton, c);
        contentPane.add(stopButton);
        
        // adding "Detail" button into the content pane if it exists
        if(detailComponent != null)
        {
		    detailButton = JButtonFactory.create(lblDetails + " <<", new DetailButtonActionListener(),"DETAIL");
            c.insets = new Insets(COMPONENT_SPACE, SEPARATED_COMPONENT_SPACE, 0, 0);
            c.gridy = 2;
            g.setConstraints(detailButton,c);
            contentPane.add(detailButton);
        }
        
    }
    
    /**
     * Makes the detail panel visible or invisibile.  The result 
     * is similar to pressing the <B>Detail</B> button in the UI.
     * 
     * @param flag true to make the detail panel visible
     */
    public void setDetailVisible(boolean visible)
    {
        if(detailComponent != null)
        {
            // TODO: detail button should use ArrowIcon instead of <<
            // TODO: toggle detail button
            detailComponent.setVisible(visible);
            if (visible) 
                detailButton.setToolTipText(i18n("details_hide_tt"));
            else 
                detailButton.setToolTipText(i18n("details_show_tt"));
            validate();
        }
    }
    
    /**
     * Determines whether the detail panel is currently visible.
     * 
     * @return true if the detail panel is visible
     */
    public boolean isDetailVisible()
    {
        if(detailComponent != null)
            return detailComponent.isVisible();
        return false;
    }
    
    /**
     * Makes the detail panel visible or invisibile.  The result 
     * is similar to pressing the <B>Detail</B> button in the UI.
     * 
     * @param flag true to make the detail panel visible
     */
    public void setProgressBarVisible(boolean flag)
    {
        progressBar.setVisible(flag);
    }
    
    /**
     * Determines whether the detail panel is currently visible.
     * 
     * @return true if the progress bar is visible
     */
    public boolean isProgressBarVisible()
    {
        return progressBar.isVisible();
    }
    
    /**
     * Sets an icon that is displayed in the top left corner.
     *
     * @param icon the icon to be set for the Status Dialog
     */
    public void setIcon(Icon icon)
    {
       iconLabel.setIcon(icon);
    }
     
    /**
     * Indicates the specified percentage on the 
     * progress bar.
     *
     * @param percentage value in range of 0 to 100
     */
    public void setProgressValue(int percentage)
    {
        progressBar.setValue(percentage);
    } 
    
    /**
     * Retreives the current value of the progress bar
     *
     * @return progress value in the range of 0 to 100
     */
    public int getProgressValue()
    {
        return progressBar.getValue();
    }
    
    /**
     * Sets the text to be displayed on the progress line
     * 
     * @param text the text to be displayed as progress line on the Status Dialog
     */
    public void setProgressText(String text)
    {
        progressLabel.setText(text);
    }
    
    /**
     * Retreives the text that is displayed on the progress line.
     *
     * @return the current progress line text
     */
    public String getProgressText()
    {
        return progressLabel.getText();
    }

    /**
     * Returns a component to be used as the detail area.
     *
     * @return component for detail area
     */
    protected JComponent createDetailComponent()
    {
        return null;
    }
    
    /**
     * Sets the type of confirmation to appear when the
     * <B>Stop</B> or <B>Close</B> buttons are pressed.
     *
     * @param flags may be one or more CONFIRM flags
     * @see #CONFIRM_NONE
     * @see #CONFIRM_CLOSE
     * @see #CONFIRM_STOP
     */
    public void setConfirmation(int flags)
    {
        confirmationFlags = flags;
    }
    
    /**
     * Retreives confirmation flags.
     *
     * @return one or more CONFIRM bit flags
     * @see #CONFIRM_NONE
     * @see #CONFIRM_CLOSE
     * @see #CONFIRM_STOP
     */
    public int getConfirmation()
    {
        return confirmationFlags;
    }
    
    /**
     * Sets how long the dialog should wait before becoming visible.  
     * For example, a value of 500 means that after calling setVisible(true),
     * the StatusDialog will wait for 500ms before it pops up.
     * If 500ms have elapsed and the task is still continuing
     * (i.e. setVisible(false) has not been called)
     * the dialog will popup.
     * 
     * By default the show delay is set to 0.
     * 
     * @param milliseconds time to wait before showing dialog
     * @see #setVisible
     */
    public void setShowDelay(int milliseconds)
    {
        showDelay = milliseconds;
    }

    /**
     * Retrieves how long to wait before becoming visible.
     * 
     * @return delay time (in milliseconds)
     */
    public int getShowDelay()
    {
        return showDelay;
    }
    
    /**
     * Sets how long the dialog should remain visible after
     * it is displayed.  This is used to prevent the dialog
     * from dissappering if the task finishes too quickly.
     * The recommended value is 3000ms (3 seconds).
     * 
     * For example, a 3 second hide delay would remain
     * visible even if the task finishes
     * (i.e. setVisible(false) is called)
     * in 1 second.
     * 
     * By default, the hide delay is set to 0.
     * 
     * @param milliseconds time to wait before hiding dialog
     * @see #setVisible
     */
    public void setHideDelay(int milliseconds)
    {
        hideDelay = milliseconds;
    }
    
    /**
     * Retreives how long the dialog should remain visible 
     * after it is displayed.
     * 
     * @return delay time (in milliseconds)
     */
    public int getHideDelay()
    {
        return hideDelay;
    }
    
    class DetailButtonActionListener implements ActionListener
    {
        private boolean isDetailVisible = false;
        
        public void actionPerformed(ActionEvent e)
        {
            setDetailVisible(!isDetailVisible());
        }
    }
    
    class StopButtonActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent ae)
        {
            if((confirmationFlags & CONFIRM_STOP) == CONFIRM_STOP)
            {
                int choice = JOptionPane.showConfirmDialog(StatusDialog.this, 
                                                           i18n("stop_confirm"), 
                                                           i18n("warning"),
                                                           JOptionPane.YES_NO_OPTION);
                if (choice == JOptionPane.YES_OPTION)
                {
                    stopButton.setEnabled(false);
                    closeButton.setEnabled(true);
                }
            }
            else
            {
                stopButton.setEnabled(false);
                closeButton.setEnabled(true);
            }
        }
    }
    
    class CloseButtonActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent ae)
        {
            if((confirmationFlags & CONFIRM_CLOSE) == CONFIRM_CLOSE)
                {
                int choice = JOptionPane.showConfirmDialog(StatusDialog.this, 
                                                           i18n("close_confirm"),
                                                           i18n("warning"),
                                                           JOptionPane.YES_NO_OPTION);
                if (choice == JOptionPane.YES_OPTION)
                {
                    StatusDialog.this.setVisible(false);
                }
            }
            else
            {
                StatusDialog.this.setVisible(false);
            }
        }
    }
    
}
