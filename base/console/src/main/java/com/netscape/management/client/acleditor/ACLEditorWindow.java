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
package com.netscape.management.client.acleditor;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Image;
import java.awt.Component;
import java.awt.Insets;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.util.Hashtable;

import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

/**
 * ACLEditorWindow is the asbtract class for the ACL editor framework.
 * The developer will use this class as the base and extend it to provide
 * more functionities.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 9/3/97
 */
public abstract class ACLEditorWindow extends JDialog implements ACLEditorConstants {
    protected static Image iconImage = null;

    protected String windowName;
    protected String titleArg;
    protected WindowFactory windowFactory;
    protected ResourceSet resources;
    protected Hashtable components;
    protected CallbackAction completionCallback;

    /**
     * constructor to create an acleditor dialog depend on the window factory
     *
     * @param wf define the behavour of the window
     * @param name name of the window
     */
    public ACLEditorWindow(WindowFactory wf, String name) {
        this(wf, name, null);
    }

    /**
      * constructor to create an acleditor dialog depend on the window factory
      *
      * @param wf define the behavour of the window
      * @param name name of the window
      * @param arg special argument for the window title
      */
    public ACLEditorWindow(WindowFactory wf, String name, String arg) {
        super();

        windowName = name;
        titleArg = arg;
        windowFactory = wf;
        resources = wf.getResourceSet();
        components = new Hashtable();
        completionCallback = null;

        setTitle(resources.getString(windowName, "WindowTitle", titleArg));
        getContentPane().setLayout(new GridBagLayout());
    }

    /**
      * setup the call back subroutine for the window. It is called when the ok button is clicked.
      *
      * @param cb call back function
      */
    public void setCompletionCallback(CallbackAction cb) {
        completionCallback = cb;
    }

    /**
      * reset the internal layout constraints
      *
      * @param gbc constraint
      */
    protected void resetConstraints(GridBagConstraints gbc) {
        gbc.gridx = 0;
        gbc.gridy = GridBagConstraints.RELATIVE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.ipadx = gbc.ipady = PAD;
        gbc.weightx = gbc.weighty = 0.0;
        gbc.insets = new Insets(0, 0, 0, 0);
    }

    /**
      * add a button into the window
      *
      * @param gbc constraint
      * @param name name of the button
      * @param callback call back function if the button is clicked
      */
    protected void addInstructionLineHack(GridBagConstraints gbc,
            String name, ActionListener callback) {
        // A bug/feature in GridBagLayout does not seem to allow you to specify RELATIVE for one dimension
        // and not the other (i.e. place this thing to the right of the last thing, but *not* below it
        // as well). Sheesh. However, this is only a problem for the first row (gridy=0) in the layout.
        // Double Sheesh!! So, we hack the first row to explicitly use gridy=0. This was not necessary
        // with JDK1.1.3 and Swing0.3, but it's hosed in JDK1.1.4 and Swing0.4.1. -DT

        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.ipady = PAD / 2;
        gbc.gridwidth = GridBagConstraints.RELATIVE;
        gbc.gridy = 0;
        gbc.insets = new Insets(PAD, PAD, PAD, PAD);
        _add(createInstruction(name), gbc);

        JPanel p = new JPanel(new FlowLayout(FlowLayout.RIGHT, PAD, PAD));
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.ipady = PAD / 2;
        gbc.gridx = GridBagConstraints.RELATIVE;
        gbc.gridy = 0;
        p.add(createButton(name, callback));
        _add(p, gbc);
    }

    /**
      * add a button into the window
      *
      * @param gbc constraint
      * @param name name of the button
      * @param callback call back function if the button is clicked
      */
    protected void addInstructionLine(GridBagConstraints gbc,
            String name, ActionListener callback) {
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.ipady = PAD / 2;
        gbc.gridwidth = GridBagConstraints.RELATIVE;
        gbc.insets = new Insets(PAD, PAD, PAD, PAD);
        _add(createInstruction(name), gbc);

        JPanel p = new JPanel(new FlowLayout(FlowLayout.RIGHT, PAD, PAD));
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.ipady = PAD / 2;
        gbc.gridx = GridBagConstraints.RELATIVE;
        p.add(createButton(name, callback));
        _add(p, gbc);
    }

    /**
      * create a button
      *
      * @param name name of the button
      * @param callback call back function if the button is clicked
      */
    protected JButton createButton(String name, ActionListener callback) {
        JButton button =
                new JButton(resources.getString(windowName, name + "Button"));
        button.setToolTipText(resources.getString(windowName, name + "ToolTip"));
        if (callback != null)
            button.addActionListener(callback);
        components.put(name, button);
        button.setFocusPainted(false);
        return button;
    }

    /**
      * create a textfield
      *
      * @param name name of the textfield
      * @param col maximum column size
      * @param callback call back function if the button is clicked
      */
    protected JTextField createTextField(String name, int col,
            ActionListener callback) {
        JTextField field = new JTextField(col);
        field.setToolTipText(resources.getString(windowName, name + "ToolTip"));
        if (callback != null)
            field.addActionListener(callback);
        components.put(name, field);
        return field;
    }

    /**
      * create a textfield which only accepts single byte character
      *
      * @param name name of the textfield
      * @param col maximum column size
      * @param callback call back function if the button is clicked
      */
    protected JTextField createSingleByteTextField(String name,
            int col, ActionListener callback) {
        JTextField field = new SingleByteTextField(col);
        field.setToolTipText(resources.getString(windowName, name + "ToolTip"));
        if (callback != null)
            field.addActionListener(callback);
        components.put(name, field);
        return field;
    }

    /**
      * create a text area
      *
      * @param name name of the textarea
      * @param rows maximum row size
      * @param cols maximum column size
      * @param callback call back function if the button is clicked
      */
    protected JTextArea createTextArea(String name, int rows, int cols,
            ActionListener callback) {
        JTextArea area = new JTextArea(rows, cols);
        area.setToolTipText(resources.getString(windowName, name + "ToolTip"));
        //area.addActionListener(callback);
        components.put(name, area);
        return area;
    }

    /**
      * create a text area
      *
      * @param name name of the textarea
      * @param callback call back function if the button is clicked
      */
    protected JTextArea createTextArea(String name,
            ActionListener callback) {
        JTextArea area = new JTextArea();
        area.setToolTipText(resources.getString(windowName, name + "ToolTip"));
        //area.addActionListener(callback);
        components.put(name, area);
        return area;
    }

    /**
      * create a check box
      *
      * @param name name of the checkbox
      * @param callback call back function if the button is clicked
      */
    protected JCheckBox createCheckBox(String name,
            ActionListener callback) {
        JCheckBox box =
                new JCheckBox(resources.getString(windowName, name + "CheckBox"));
        box.setToolTipText(resources.getString(windowName, name + "ToolTip"));
        if (callback != null)
            box.addActionListener(callback);
        components.put(name, box);
        box.setFocusPainted(false);
        return box;
    }

    /**
      * create a combo box
      *
      * @param name name of the combobox
      * @param callback call back function if the button is clicked
      */
    protected JComboBox createComboBox(String name,
            ActionListener callback) {
        return createComboBox(name, 0, callback);
    }

    /**
      * create a combo box
      *
      * @param name name of the combobox
      * @param width the maximum width of the combo box
      * @param callback call back function if the button is clicked
      */
    protected JComboBox createComboBox(String name, int width,
            ActionListener callback) {
        JComboBox box = new JComboBox();
        box.setToolTipText(resources.getString(windowName, name + "ToolTip"));
        if (callback != null)
            box.addActionListener(callback);
        components.put(name, box);
        if (width > 0)
            box.setMaximumSize(new Dimension(width, Integer.MAX_VALUE));
        return box;
    }

    /**
      * create a instruction label
      *
      * @param name name of the label
      */
    protected JLabel createInstruction(String name) {
        String instructionText =
                resources.getString(windowName, name + "Instruction");
        JLabel label = new JLabel(instructionText);
        components.put(name, label);
        return label;
    }

    /**
      * return the component by name
      *
      * @param name name of the component
      */
    protected JComponent getComponent(String name) {
        return ((JComponent)(components.get(name)));
    }

    /**
      * create a footer panel
      *
      */
    protected JPanel createStandardFooter() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.RIGHT, PAD, PAD));
        p.add(createButton("save", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        save(e);
                    }
                }
                ));
        p.add(createButton("cancel", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        cancel(e);
                    }
                }
                ));
        p.add(createButton("help", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        help(e);
                    }
                }
                ));
        return p;
    }

    /**
      * create a scroll panel with the specified width and height
      *
      * @param w width
      * @param h height
      */
    protected JScrollPane createScrollPane(int w, int h) {
        JScrollPane scroll = new JScrollPane() {
                    public float getAlignmentX() {
                        return JScrollPane.LEFT_ALIGNMENT;
                    }
                };
        scroll.setPreferredSize(new Dimension(w, h));
        return scroll;
    }

    /**
      * create an horizontal line
      */
    protected Component createHorizontalLine() {
        return new HorizontalLine(10, 1);
    }

    /**
      * create a standard layout panel
      */
    protected JPanel createStandardLayout() {
        GridBagConstraints gbc = new GridBagConstraints();

        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.ipady = 0;
        gbc.insets = new Insets(PAD, 3 * PAD / 2, PAD, 3 * PAD / 2);
        _add(createInstruction("main"), gbc);

        JPanel bp = new JPanel();
        bp.setLayout(new GridBagLayout());
        //bp.setBorder(BorderFactory.createTitledBorder(new BevelBorder(BevelBorder.RAISED), resources.getString(windowName, "borderText")));
        resetConstraints(gbc);
        gbc.weightx = gbc.weighty = 1.0;
        gbc.ipadx = 0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 3 * PAD / 2, 0, 3 * PAD / 2);
        _add(bp, gbc);

        JPanel p = createStandardFooter();
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.ipady = 0;
        gbc.insets = new Insets(0, PAD / 2, 0, PAD / 2);
        _add(p, gbc);

        return bp;
    }

    /**
      * display help
      *
      * @param e help event
      */
    protected void help(ActionEvent e) {
        windowFactory.getHelp().contextHelp(getWindowName(), HelpDirName);
    }

    /**
      * the save button is pressed
      *
      * @param e save event
      */
    protected void save(ActionEvent e) {
        dispose();
    }

    /**
      * kill the acl window
      *
      */
    public void dispose() {
        if (completionCallback != null)
            completionCallback.go(getWindowName());
        super.dispose();
    }

    /**
      * cancel button is pressed
      *
      * @param e button event
      */
    protected void cancel(ActionEvent e) {
        dispose();
    }

    /**
      * create a instruction label
      *
      * @param name name of the label
      */
    protected void unimplemented(ActionEvent e) {
        String cmd = e.getActionCommand();
        System.err.println(cmd + " Unimplemented");
    }

    /**
      * return the title
      *
      * @return argument of the window title
      */
    protected String getTitleArg() {
        return titleArg;
    }

    /**
      * return the name of the window
      *
      * @return window name
      */
    protected String getWindowName() {
        return windowName;
    }

    /**
      * add a component to the window using the given constraints value
      *
      * @param component component to be added
      * @param constraints layout constraint value
      */
    protected void _add(Component component, Object constraints) {
        // The brain trust of swing decided to write JFrame so
        // that it breaks add(Component, Object). Stupid...

        getContentPane().add(component, constraints);
    }

    /**
      * display the dialog
      */

    public void show() {
        ModalDialogUtil.setDialogLocation(this, null);
        super.show();
    }

    /**
      * show the error dialog
      *
      * @param msg message to be showed in the error dialog
      */
    public void showErrorDialog(String msg) {
        showErrorDialog(msg, "errorTitle");
    }

    /**
      * display the error dialog
      */
    public void showErrorDialog() {
        showErrorDialog("errorText", "errorTitle");
    }

    /**
      * display the error dialog with the given msg and title
      *
      * @param msg message to be displayed
      * @param title title of the error dialog
      */
    public void showErrorDialog(String msg, String title) {
        new PopupErrorDialog(this, resources.getString(windowName, msg),
                resources.getString(windowName, title));
    }

    /**
      * show the error dialog for a given exception error
      *
      * @param e exception message to be displayed
      */
    public void showErrorDialog(Exception e) {
        showErrorDialog(e, "errorTitle");
    }

    /**
      * show error dialog for the given exception error
      *
      * @param e exception message to be displayed
      * @param title title of the error dialog
      */
    public void showErrorDialog(Exception e, String title) {
        new PopupErrorDialog(this, e.getMessage(),
                resources.getString(windowName, title));
    }

    /**
      * display a dialog which add the user question
      *
      * @param msg question to be asked
      */
    public String showInputDialog(String msg) {
        PopupInputDialog pid = new PopupInputDialog(this,
                resources.getString(windowName, msg),
                resources.getString(windowName, "inputTitle"));
        return pid.getInput();
    }
}

class PopupInputDialog implements Runnable, ACLEditorConstants {
    protected ACLEditorWindow parent;
    protected String message;
    protected String windowTitle;
    protected String input;
    protected boolean done;

    /**
     * create a dialog to ask the user question
     *
     * @param window parent window (acleditor window)
     * @param msg message to be asked
     * @param title title of the window
     */
    public PopupInputDialog(ACLEditorWindow window, String msg,
            String title) {
        parent = window;
        message = msg;
        windowTitle = title;
        done = false;
        (new Thread(this)).start();
    }

    /**
      * execute the thread to get input from the user
      */
    public synchronized void run() {
        input = SuiOptionPane.showInputDialog(null, message,
                windowTitle, SuiOptionPane.PLAIN_MESSAGE);
        done = true;
        notifyAll();
    }

    /**
      * get the input frm the input dialog
      *
      * @return input from the end user
      */
    public synchronized String getInput() {
        while (!done) {
            try {
                wait();
            } catch (InterruptedException ie) {

            }
        }
        return input;
    }
}
