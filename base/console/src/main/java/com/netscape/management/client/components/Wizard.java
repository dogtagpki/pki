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

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 *
 * An implementation of a generic wizard dialog.
 *
 * <br><br>
 * <img SRC="images/WizardTemplate.gif" height=360 width=483>
 * <br><br>
 *  <b>Step Name</b> Name for the current page. (required)  <br>
 *  <b>Step Number (x of y) </b>  x = Current step number, y = total number of steps. (required) <br>
 *  <b>Graphic Area </b> pictorial representation of current step or task (optional) <br>
 *  <b>Back Button </b> goes to previous step, if available <br>
 *  <b>Next Button </b> goes to next step or completes the wizard operation.  For the last step, the button is labeled Finish <br>
 *  <b>Cancel Button </b> aborts the wizard operation, if user answers yes to cancel confirmation dialog (fig 8) <br>
 *  <b>Help Button </b> Displays context sensitive help <br>
 *  <b>Extra Button/Components</b> Extra button/components (not shown) to be added to the left most button panel.
 * <br><br>
 * See <A HREF="WizardPage.html"><CODE>WizardPage</CODE></A> for more information.<br>
 *
 *
 * <p>
 * <dt>Construct a wizard (contain 3 pages), using default sequence manager and
 * default data collection model:
 * <code>
 *  <dd>Wizard wizardDialog = new Wizard(parentFrame, "WizardTest", true);<br>
 *  <dd>wizardDialog.addPage("WizardPage1", new WizardPage1());<br>
 *  <dd>wizardDialog.addPage("WizardPage2", new WizardPage2());<br>
 *  <dd>wizardDialog.addPage("WizardPage3", new WizardPage3());<br>
 *  <br>
 *  <dd>wizardDialog.setSize(640, 480);<br>
 *  <dd>wizardDialog.setVisible(true);<br>
 * </code>
 * <br><br>
 * Each page under wizard should extend WizardPage.<br>
 * Wizard class only act as a wizard page collector (use addPage API) and display agent.<br>
 * Branching decision are made by the sequence manager (default to WizardSequenceManager)<br>
 * Wizard also contain a data collection (default to WizardDataCollectionModel) where global
 * shared data are stored and can be used by all wizard page under the wizard.<br>
 *
 * @see WizardPage
 * @see IWizardSequenceManager
 * @see WizardSequenceManager
 * @see IDataCollectionModel
 * @see WizardDataCollectionModel
 */
public class Wizard extends JDialog
{

    //button panel
    WizardNavigator  m_nav;

    //sequence controller
    IWizardSequenceManager m_manager;

    //data collection model, to store global shared data accross
    //all pages.
    IDataCollectionModel m_model;

    //page list, this keep track of all the actuall pages
    private PageList m_pageList;

    //display pane, where page content is displayed
    JPanel m_displayPane;

    //display step title and "n of m" string
    JLabel m_stepName, m_stepOf;
    int m_currentStep;
    String m_stepN_of_M;

    ResourceSet m_resource = new ResourceSet("com.netscape.management.client.components.Wizard");


    /**
     * Creates a wizard dialog using default sequence manager and data collection model
     *
     * @param owner the owner of the dialog (a Frame)
     * @param title the title of the dialog. A null value will be accepted without causing a NullPointerException to be thrown.
     * @param modal if true, dialog blocks input to other app windows when shown
     * @see WizardSquenceManager
     * @see WizardDataCollectionModel
     */
    public Wizard(Frame owner, String title, boolean modal) {
        this(owner, title, modal, new WizardSequenceManager(), new WizardDataCollectionModel());
    }

    /**
     * Creates a wizard dialog using default sequence manager and data collection model
     *
     * @param owner the owner of the dialog (another Dialog)
     * @param title the title of the dialog. A null value will be accepted without causing a NullPointerException to be thrown.
     * @param modal if true, dialog blocks input to other app windows when shown
     * @see WizardSquenceManager
     * @see WizardDataCollectionModel
     */
    public Wizard(Dialog owner, String title, boolean modal) {
        this(owner, title, modal, new WizardSequenceManager(), new WizardDataCollectionModel());
    }

    /**
     * Creates a wizard dialog
     *
     * @param owner the owner of the dialog
     * @param title the title of the dialog. A null value will be accepted without causing a NullPointerException to be thrown.
     * @param modal if true, dialog blocks input to other app windows when shown
     * @param sequenceManager wizard sequence logic, control which page gets displayed
     * @param dataCollectionModel data collection model, global data shared accross all wizard pages
     * @see IWizardSquenceManager
     * @see IDataCollectionModel
     */
    /* WizardDialog's setup:
     * <code>
     * +------------------------------------------+
     * |Dialog title                             x|
     * +------------------------------------------+
     * |Step title                          N of M|  <- 'North' of border layout
     * +------------------------------------------+
     * |                                          |
     * |                                          |
     * |m_displayPanel                            |  <- 'Center' of the border layout
     * |                                          |
     * |                                          |
     * +------------------------------------------+
     * |WizardNavigator                           |  <- 'Bottom of the border layout
     * +------------------------------------------+
     * </code>
     */
    public Wizard(Frame owner, String title, boolean modal,
                  IWizardSequenceManager sequenceManager, IDataCollectionModel dataCollectionModel) {
        super(owner, title, modal);
        initialize(sequenceManager, dataCollectionModel);
    }

    /**
     * Creates a wizard dialog using another dialog as the owner.
     *
     */
    public Wizard(Dialog owner, String title, boolean modal,
                  IWizardSequenceManager sequenceManager, IDataCollectionModel dataCollectionModel) {
        super(owner, title, modal);
        initialize(sequenceManager, dataCollectionModel);
    }

    void initialize(IWizardSequenceManager sequenceManager, IDataCollectionModel dataCollectionModel) {
	
        setSize(425, 425);
        getContentPane().setLayout(new BorderLayout());

        m_manager = sequenceManager;
        m_model   = dataCollectionModel;

        m_pageList = new PageList();
        m_stepN_of_M = m_resource.getString(null, "stepN_of_M");

        m_displayPane = new JPanel();
        m_displayPane.setLayout(new GridBagLayout());

        //setup step pane.  This pane contains step title and step 'n of m'
        JPanel m_stepPane = new JPanel();
        m_stepPane.setLayout(new GridBagLayout());

        m_stepName = new JLabel();
        //m_stepName.setOpaque(true);
        //m_stepName.setBackground(Color.white);
        Font currFont = m_stepName.getFont();
	int style = currFont.getStyle();
	String locale = Locale.getDefault().getLanguage();
	// 552699: Setting the font to bold on Japanese console causes empty boxes to be shown
	if (!locale.equalsIgnoreCase("ja") && !locale.equalsIgnoreCase("zh")) {
	   style |= Font.BOLD;
	}
           m_stepName.setFont(new Font(currFont.getFamily(), style, currFont.getSize()+2));
        m_stepName.setBorder(new EmptyBorder(new Insets(SuiConstants.HORIZ_COMPONENT_INSET,
                                                         SuiConstants.HORIZ_COMPONENT_INSET,
                                                         SuiConstants.HORIZ_COMPONENT_INSET,
                                                         0)));

        m_stepOf = new JLabel("", JLabel.RIGHT);
        //m_stepOf.setOpaque(true);
        //m_stepOf.setBackground(Color.white);
        m_stepOf.setFont(new Font(currFont.getFamily(), currFont.getStyle() | Font.BOLD, currFont.getSize()+2));
        m_stepOf.setBorder(new EmptyBorder(new Insets(SuiConstants.HORIZ_COMPONENT_INSET,
                                                         0,
                                                         SuiConstants.HORIZ_COMPONENT_INSET,
                                                         SuiConstants.HORIZ_COMPONENT_INSET)));


        GridBagUtil.constrain(m_stepPane, m_stepName, 0, 0,
                              1, 1, 1.0, 1.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              SuiConstants.VERT_WINDOW_INSET, SuiConstants.HORIZ_WINDOW_INSET, SuiConstants.DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(m_stepPane, m_stepOf, 1, 0,
                              1, 1, 1.0, 1.0,
                              GridBagConstraints.EAST, GridBagConstraints.BOTH,
                              SuiConstants.VERT_WINDOW_INSET, 0, SuiConstants.DIFFERENT_COMPONENT_SPACE, SuiConstants.HORIZ_WINDOW_INSET);

        //add pane to dialog
        getContentPane().add("North", m_stepPane);
        getContentPane().add("Center", m_displayPane);
        getContentPane().add("South", m_nav = new WizardNavigator(this, m_manager));
    }

    /**
     * Adds one wizard page to the sequence queue.
     *
     * @param id page id, used to identify the page
     * @param wizardPage the page to be displayed
     * @see WizardPage
     */
    public void addPage(String id, WizardPage wizardPage) {
        wizardPage.setDataModel(m_model);
        wizardPage.setSequenceManager(m_manager);

        int index = m_pageList.getTotalPage()-1;

        if (index < 0) {
            m_manager.setFirst(id);
            m_manager.setCurrent(id);
        } else {
            m_manager.setPrevious(id, m_pageList.getID(index));
        }

        m_pageList.addPage(id, wizardPage);

        //m_nav.setPanel(m_manager.getFirst());
    }


    /**
     * Before wizard panel can be used this function must
     * be called first.  Only call this function after
     * all page has been added.
     * This will initialize the first page to be displayed.
     *
     * this function will be called automatically if show()
     * or setVisible(true) is called.
     *
     * we also want to add WizardNavigator and Wizard dialog
     * to change listener to the data model.  Reason
     * been that the listener are store in the vector
     * and we want to be the last one to get called
     * so to let other page have a chance to up date first
     * before we decide if button or max step need to
     * be changed.
     */
    void setFirst() {
        m_nav.setPanel(m_manager.getFirst());

        //add listener
        m_model.addChangeListener(m_nav);
        m_model.addChangeListener(new ChangeListener() {
            /**
             * Called if an event has occure to the current page.
             *
             * @param event event that occures
             */
            public void stateChanged(ChangeEvent event) {
                int maxStep = getPage(m_manager.getCurrent()).getMaxSteps();
                m_stepOf.setText(replace(replace(m_stepN_of_M, "$N", Integer.toString(m_currentStep)), "$M", Integer.toString(maxStep<=0?getMaxSteps():maxStep)));
            }
        });




    }


    /**
     * Replace any occurance of 'val' in 'oldStr' with 'replacement'
     *
     * @param oldStr string that contains the string to replace
     * @param val sub string in the 'oldStr' that will need to be replaced
     * @param replacement replace occurance of val with this value
     *
     */
    //This function should be put somewhere in util code.
    String replace(String oldStr, String val, String replacement) {
        String output = new String(oldStr);

        int index;

        while ((index = output.indexOf(val)) != -1) {
            output = output.substring(0, index) + replacement +
                output.substring(index + val.length());
        }

        return output;
    }

    /**
     *
     * @return max number of pages in the page list
     */
    int getMaxSteps() {
        return m_pageList.getTotalPage();
    }


    /**
     * m_displayPane represent the display of the wizard (minus the bottom button pane).
     * The display consist of 2 pane formated as left, and right.
     * left is used for wizard image, right is the content area where all the user input
     * will occure.  The page will look like this:
     * <code>
     * +------------------------------------------+
     * |           |                              |
     * |Wizard     |   Content Pane               |
     * |Image      |                              |
     * |           |                              |
     * |           |                              |
     * |           |                              |
     * |           |                              |
     * |           |                              |
     * +------------------------------------------+
     * </code>
     * This display mainly react to response send by WizardNavigator.
     *
     */
    void setPanel(String id, int nthStep) {

        if (id == "") return;
        m_manager.setCurrent(id);

        WizardPage page = getPage(id);
        WizardPage prev = getPage(m_manager.getPrevious(m_manager.getCurrent()));


        //set up n of m step
        m_stepName.setText(page.getStepName());
        m_currentStep = nthStep;
        int maxStep = page.getMaxSteps();
        m_stepOf.setText(replace(replace(m_stepN_of_M, "$N", Integer.toString(nthStep)), "$M", Integer.toString(maxStep<=0?getMaxSteps():maxStep)));

        m_displayPane.removeAll();

        int spacing = SuiConstants.HORIZ_WINDOW_INSET+SuiConstants.HORIZ_COMPONENT_INSET;
        //setup wizad image pane
        if (page.getGraphicComponent() != null) {
            GridBagUtil.constrain(m_displayPane, page.getGraphicComponent(), 0, 1,
                                  1, 1, 0.0, 0.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.NONE,
                                  0, SuiConstants.HORIZ_WINDOW_INSET+SuiConstants.HORIZ_COMPONENT_INSET, 0, 0);
        }

        //setup content pane
        GridBagUtil.constrain(m_displayPane, page, 1, 1,
                              1, 1, 1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, page.getGraphicComponent()==null?spacing:0, 0, SuiConstants.HORIZ_WINDOW_INSET);

        //refresh
        validate();
        repaint();
    }


    /**
     *
     * @param id page id
     * @return WizardPage that matches the id, null otherwise
     */
    WizardPage getPage(String id) {
        return m_pageList.getPage(id);
    }

    /**
     * Show the dialog.
     *
     */
    public void show() {
        //setup first page before display
        setFirst();
        super.show();
    }

    private boolean _busyCursorOn;

    /**
     * Override setCursor to show busy cursor correctly
     */
    public void setCursor(Cursor cursor) {
        if (_busyCursorOn && cursor.getType() != Cursor.WAIT_CURSOR) {
            Debug.println(9, "Wizard.setCursor(): Discarding change of cursor");
            return;
        }
        super.setCursor(cursor);
    }

    /**
     * Force the cursor for the whole frame to be busy.
     * See how _busyCursorOn flag is used inside setCursor
     */
    public void setBusyCursor(boolean isBusy) {
        this._busyCursorOn = isBusy;
        Cursor cursor =  Cursor.getPredefinedCursor(isBusy ?
                Cursor.WAIT_CURSOR : Cursor.DEFAULT_CURSOR);
        super.setCursor(cursor);
        setCursorOnChildren(this, cursor);
    }

	void setCursorOnChildren(Container container, Cursor cursor) {
		Component[] comps = container.getComponents();
		for (int i=0; i < comps.length; i++) {
			if (comps[i] instanceof Container) {
				setCursorOnChildren((Container)comps[i], cursor);
			}
			comps[i].setCursor(cursor);
		}
	}

    //where all the actuall wizard page are stored.
    //provide indexing and searching capability
    //search via index, id, or object
    class PageList {
        Hashtable m_stringIndex = null;
        Hashtable m_objectIndex = null;
        Vector    m_intIndex    = null;

        public PageList() {
            m_stringIndex = new Hashtable();
            m_objectIndex = new Hashtable();
            m_intIndex = new Vector();
        }

        //add a page, both id and page can be used
        //as index
        public void addPage(String id, Component page) {
            m_intIndex.addElement(page);
            m_stringIndex.put(id, page);
            m_objectIndex.put(page, id);
        }

        //return total page that has been added so far
        public int getTotalPage() {
            return m_intIndex.size();
        }

        //return component with maching id, null if it doesn't exist
        public WizardPage getPage(String id) {
            Object o = m_stringIndex.get(id);
            if (o==null) {
                return null;
            }
            return (WizardPage)o;
        }

        //return component id at given index, null if it doesn't exist
        public String getID(int index) {
            try {
                //return getID((Component)m_intIndex.elementAt(index));
                return (String)m_objectIndex.get(m_intIndex.elementAt(index));
            } catch (Exception e) {
                return null;
            }
        }

    }
}
