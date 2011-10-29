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
package com.netscape.admin.certsrv.wizard;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.config.install.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * WizardWidget provides the most fundamental functionalities
 * of an wizard widget.
 *
 * @author  jpanchen
 * @version %I%, %G%
 * @date	 	12/02/97
 * @see     com.netscape.admin.certsrv.wizard
 */
public class WizardWidget extends JDialog implements ActionListener
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANELNAME = "WIZARD";
    //static final Dimension DEFAULT_SIZE = new Dimension(460,520);
    static final Dimension DEFAULT_SIZE = new Dimension(480,600);
    static final Dimension BUTTON_MIN_SIZE = new Dimension(100,30);
    static final int STRUT_SIZE = 10;

    //private variables
    private JButton mBNext_Done, mBCancel, mBBack, mBHelp;
    private Stack mPrevScreen = new Stack();
    private Stack mNextScreen = new Stack();
    protected JPanel mCurrent = null;
    protected JPanel mDisplay;
    private String mDoneLabel, mNextLabel;

    protected ResourceBundle mResource;
    private WizardInfo mInfo;
    private JFrame  mParent;
    private Dimension mSize;
    private IWizardDone mWizDone;

    /*==========================================================
     * constructors
     *==========================================================*/

    /**
     * Construct Wizard with specified title and parent frame.
     * @param parent parent frame
     * @param title string to be displayed on the dialog box title bar
     * @param size specify wizard size
     */
    public WizardWidget(JFrame parent, Dimension size, IWizardDone wizDone) {
        this(parent, wizDone);
        mSize = size;
        setSize(size.width, size.height);
    }

    /**
     * Construct Wizard with specified title and parent frame.
     * @param parent parent frame
     * @title string to be displayed on the dialog box title bar
     */
    public WizardWidget(JFrame parent) {
      this(parent, null);
    }

    public WizardWidget(JFrame parent, IWizardDone wizDone) {
        //super(parent, title, true); XXX JDK 1.1.4 Bug
        super(parent, true);
        mSize = DEFAULT_SIZE;
        mParent = parent;
        getContentPane().setLayout(new BorderLayout());
        setSize(mSize.width, mSize.height);
        getRootPane().setDoubleBuffered(true);
        setLocationRelativeTo(parent);
        mInfo = new WizardInfo();
	mWizDone = wizDone;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());

        mNextLabel = mResource.getString(CMSAdminResources.GENERAL_NEXT);
        mDoneLabel = mResource.getString(CMSAdminResources.GENERAL_DONE);

        //create display panel
        mDisplay = new JPanel();
        mDisplay.setLayout(new BorderLayout());
        mDisplay.setBorder(new EmptyBorder(CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
          CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
          0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE));
/*
        mDisplay.setBorder(new CompoundBorder(
                        new EmptyBorder(CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                                        CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                                        0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE),
                                       BorderFactory.createEtchedBorder()));
*/
        getContentPane().add("Center",mDisplay);

        //create button panel

        //buttonPanel.add(Box.createGlue());
        getContentPane().add("South", createActionPanel());
    }

	/*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * get parent frame
     * @return parent frame
     */
    public JFrame getFrame() {
        return mParent;
    }

    /**
     * Add a IWizardPanel into wizard.  Note the sequence you add
     * will the be the sequence it will appear.
     * @param page IWizardPanel to be displayed
     */
    public void addPage(JPanel page) {
        if (mCurrent == null) {
            mCurrent = page;
            mDisplay.add("Center",page);
            initializeWizardPanel();
        } else {
            mNextScreen.insertElementAt(page, 0);
        }
    }

    /**
     * Action Performed when button pressed. ActionListener implementation.
     * @param event
     */
    public void actionPerformed(ActionEvent e) {

        //DONE or NEXT Pressed
        if (e.getSource().equals(mBNext_Done)) {

            if (!validateWizardPanel()) {
                return;
            }
 
            if (concludeWizardPanel())  {

                if (mNextScreen.empty() || mBNext_Done.getText().equals("Done")) {
                    //killDaemon();
                    this.dispose();
		    if (mWizDone != null) {
		      mWizDone.notify(this);
 		    }
                    return;
                } else {
                    updateWizardInfo();
                    mPrevScreen.push(mCurrent);
                    mDisplay.remove(mCurrent);
                    mCurrent = (JPanel)(mNextScreen.pop());
                    while (!initializeWizardPanel()) {
                        //move to next
                        if (mNextScreen.empty()) {
                            this.dispose();
                            return;
                        }
                        mPrevScreen.push(mCurrent);
                        mCurrent = (JPanel)(mNextScreen.pop());
                    }
                    mDisplay.add("Center",mCurrent);
                    mDisplay.invalidate();
                    mDisplay.validate();
                    mDisplay.repaint(1);
                    getRootPane().paintImmediately(getRootPane().getVisibleRect());
                }

            } else {
                return;
            }
        }

        //Cancel Pressed
        if (e.getSource().equals(mBCancel)) {
            //prompt for confirm
            int option = CMSAdminUtil.showConfirmDialog(mParent, mResource,
                    PANELNAME, "EXIT",
                    JOptionPane.YES_NO_OPTION);
            if (option == JOptionPane.YES_OPTION) {
                //killDaemon();
                this.dispose();
            }
        }

        //Back Pressed
        if (e.getSource().equals(mBBack)) {
			back_cb(mInfo);
            //move back to previous page
            if (!(mPrevScreen.empty())) {
                mNextScreen.push(mCurrent);
                mDisplay.remove(mCurrent);
                mCurrent = (JPanel)(mPrevScreen.pop());
                while (!initializeWizardPanel()) {
                    //move to prev
                    if (mPrevScreen.empty()) {
                        return;
                    }
                    mNextScreen.push(mCurrent);
                    mCurrent = (JPanel)(mPrevScreen.pop());
                }
                mDisplay.add("Center",mCurrent);
                mDisplay.invalidate();
                mDisplay.validate();
                mDisplay.repaint(1);
                getRootPane().paintImmediately(getRootPane().getVisibleRect());
            }
        }

        //Help Pressed
        if (e.getSource().equals(mBHelp)) {
            callHelp();
        }

        changeButton();
    }

    /**
     * This method is only for installation wizard.
     */
/*
    private void killDaemon() {
        if (mInfo instanceof InstallWizardInfo) {
            InstallWizardInfo wizardInfo = (InstallWizardInfo)mInfo;
            ConsoleInfo consoleInfo = wizardInfo.getAdminConsoleInfo();
            CMSConfigCert configCertCgi = new CMSConfigCert();
            configCertCgi.initialize(wizardInfo);
            Hashtable data = new Hashtable();
            data.put(ConfigConstants.TASKID, TaskId.TASK_EXIT);
            data.put(ConfigConstants.OPTYPE, OpDef.OP_MODIFY);
            data.put(ConfigConstants.PR_CERT_INSTANCE_NAME,
              consoleInfo.get(ConfigConstants.PR_CERT_INSTANCE_NAME));
            data.put(ConfigConstants.PR_SERVER_ROOT,
              consoleInfo.get(ConfigConstants.PR_SERVER_ROOT)); 
            boolean ready = configCertCgi.configCert(data);
            data.clear();
            data = null;
        }
    }
*/

	/*==========================================================
	 * protected methods
     *==========================================================*/

    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object

        mBBack = new JButton();
        mBBack.setText(mResource.getString(CMSAdminResources.GENERAL_BACK));
        mBBack.addActionListener(this);
        mBBack.setEnabled(false);

        mBNext_Done = new JButton();
        mBNext_Done.setText(mNextLabel);
        mBNext_Done.addActionListener(this);

        mBCancel = new JButton();
        mBCancel.setText(mResource.getString(CMSAdminResources.GENERAL_CANCEL));
        mBCancel.addActionListener(this);

        mBHelp = new JButton();
        mBHelp.setText(mResource.getString(CMSAdminResources.GENERAL_HELP));
        mBHelp.addActionListener(this);

	//JButton[] buttons = {mBBack, mBNext_Done, mBCancel, mBHelp };
	JButton[] buttons = {mBBack, mBNext_Done, mBCancel};
		
		//pass the buttons reference to wizardinfo
		mInfo.setButtons(mBNext_Done, mBCancel, mBBack);
		
		return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }


    /**
     * Returns wizard data container
     */
    protected WizardInfo getWizardInfo() {
        return mInfo;
    }

    /**
     * set wizard data container
     */
    protected void setWizardInfo(WizardInfo info) {
        mInfo = info;
    }

    /**
     * Initialize currently displayed panel
     * Implemetation is delegated to initialize() method
     * of IWizardPanel. It retruns false, if the panel is
     * to be skipped.
     */
    protected boolean initializeWizardPanel() {

        if (mCurrent instanceof IWizardPanel) {
            boolean status = ((IWizardPanel)mCurrent).initializePanel(mInfo);
            setTitle( ((IWizardPanel)mCurrent).getTitle() );
            return status;
        }
        return true;
    }

    /**
     * Verify if a page is complete. It means all the
     * require fields are fill out. It delegates implementation
     * details to validate() method of the IWizardPanel obejct.
     * If failed, error dialog is displayed but not terminated.
     */
    boolean validateWizardPanel() {
        boolean complete = true;

        if (mCurrent instanceof IWizardPanel) {
            if (!( (IWizardPanel)mCurrent ).validatePanel()) {
                String msg = ((IWizardPanel)mCurrent).getErrorMessage();
                if (msg != null && !msg.equals(""))
                    CMSAdminUtil.showErrorDialog(mParent, mResource, msg,
                        JOptionPane.ERROR_MESSAGE);
                complete = false;
            }
        }

        return complete;
    }

    /**
     * Some panel may require post-processing before moving to next stage.
     * Ususally the last IWizardPanel use this method to perform
     * save/update operation on the server via cgi/rmi/ldap.
     * If error occurred, wizard will be terminated.
     */
    boolean concludeWizardPanel() {
        boolean complete = true;
        if(mCurrent instanceof IWizardPanel) {
            if (!((IWizardPanel)mCurrent).concludePanel(mInfo)) {
                CMSAdminUtil.showErrorDialog(mParent, mResource,
                        ((IWizardPanel)mCurrent).getErrorMessage(),
                        JOptionPane.ERROR_MESSAGE);
                complete = false;
            }
        }
        return complete;
    }

    /**
     * Retrieve the update information from the
     * IWizardPanel into WizardInfo.
     */
    void updateWizardInfo() {
        if(mCurrent instanceof IWizardPanel) {
            ((IWizardPanel)mCurrent).getUpdateInfo(mInfo);
        }
    }

    protected void callHelp() {
        Debug.println("Overwrite this method");
    }

    protected void back_cb(WizardInfo info) {
        Debug.println("Overwrite this method");
    }

	/*==========================================================
	 * private methods
     *==========================================================*/

    /**
     * Button enable/disable and label changes
     */
    private void changeButton() {

        if (mPrevScreen.size()==0) {
            mBBack.setEnabled(false);
            mBBack.repaint();
        } else {
            mBBack.setEnabled(true);
            mBBack.repaint();
        }

        boolean lastPage = ((IWizardPanel)mCurrent).isLastPage();
        if ((mNextScreen.size()==0) || (lastPage)) {
            mBNext_Done.setText(mDoneLabel);
            mBCancel.setEnabled(false);
            mBBack.setEnabled(false);
        } else {
            mBNext_Done.setText(mNextLabel);
            mBCancel.setEnabled(true);
        }
        mBNext_Done.repaint();
        mBCancel.repaint();
        mBBack.repaint();
    }
}


