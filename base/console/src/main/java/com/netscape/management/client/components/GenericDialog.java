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
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import com.netscape.management.client.util.Help;

/**
 * GenericDialog defines a basic dialog which consists of two main areas:
 * the custom panel and button panel. The custom panel can be used to set
 * the subclass's main view area. The button panel can contain any combination
 * of buttons, OK CANCEL CLOSE HELP.  Their labels are automatically i18n'd.
 * The button panel orientation can be horizontal (default) or vertical.
 *
 * Other reasons why you'd want use this instead of JDialog:
 * - Sets up exterior dialog insets according UE specs.
 * - Sets up button sizes and spacing according to UE specs.
 * - Makes it easy to set initial focus rect on any component.
 * - Automatically sets default button highlight (dark border).
 * - Relocates dialog relative to parent when shown.
 * - BUG FIX: setting dialog to nonresizable before pack causes a ridiculous size on UNIX
 * - BUG FIX: dispose does not focus correct parent component
 * - BUG FIX: setMinimumSize() does not work
 *
 * @author Andy Hakim
 */
public class GenericDialog extends JDialog implements UIConstants 
{
    public static final int VERTICAL = SwingConstants.VERTICAL;
    public static final int HORIZONTAL = SwingConstants.HORIZONTAL;
	
    public static final int NO_BUTTONS = 0;
    public static final int OK = 1;
    public static final int CANCEL = 2;
    public static final int CLOSE = 4;
    public static final int HELP = 8;
    
    public static final int OK_CANCEL_HELP = OK | CANCEL | HELP;
    public static final int CLOSE_HELP = CLOSE | HELP;
    
    private static final int DO_NOTHING = 0;
    private static final int DO_ACTION = 1;
    private static final int DO_CANCEL = 2;
    private int actionPerformed = DO_NOTHING;
    
    private FocusListener focusListener = new ButtonFocusListener();
    private KeyListener textFieldKeyListener = new TextFieldKeyListener();
    
    private Frame parentFrame = null;
    private JComponent focusComponent = null;
    private JPanel contentPanel = new JPanel(new BorderLayout());
    private JPanel extraPanel = null;
    private JButton defaultButton = null;
    private JButton closeButton = null;
    private JButton okButton = null;
    private JButton cancelButton = null;
    private JButton helpButton = null;
    private int minWidth = 0;
    private int minHeight = 0;
    private String helpProduct = null;
    private String helpTopic = null;


    /**
     * Contructs a modal dialog with no window title.
     * The title can be set using setTitle().
     * Standard buttons are used: OK, CANCEL, and HELP.
     * Button orientation is VERTICAL: buttons appear to top right of content pane.
     *
     * @param parentFrame the parent frame; dialog is positioned relative to this
     */
    public GenericDialog(JFrame parentFrame)
    {
        this(parentFrame, "");
    }

    /**
     * Contructs a modal dialog with specified window title.
     * Standard buttons are used: OK, CANCEL, and HELP.
     * Button orientation is VERTICAL: buttons appear to top right of content pane.
     *
     * @param parentFrame the parent frame; dialog is positioned relative to this
     * @param windowTitle the text that appears on the dialog window
     */
    public GenericDialog(JFrame parentFrame, String windowTitle)
    {
        this(parentFrame, windowTitle, OK | CANCEL | HELP);
    }

    /**
     * Contructs a modal dialog with specified window title.
     * Specified buttons are used: NO_BUTTONS | OK | CANCEL | HELP
     * Button orientation is VERTICAL: buttons appear to top right of content pane.
     *
     * @param windowTitle the text that appears on the dialog window
     * @param parentFrame the parent frame; dialog is positioned relative to this
     * @param buttonTypes the buttons that appear on this dialog
     */
    public GenericDialog(JFrame parentFrame, String windowTitle, int buttonTypes)
    {
        this(parentFrame, windowTitle, buttonTypes, VERTICAL);
    }
    
    /**
     * Contructs a modal dialog with specified window title.
     * Specified buttons are used: NO_BUTTONS | OK | CANCEL | HELP
     * The button orientation is vertical: buttons appear to the right of the content pane.
     *
     * @param windowTitle the text that appears on the dialog window
     * @param parentFrame the parent frame; dialog is positioned relative to this
     * @param buttonTypes the buttons that appear on this dialog
     * @param buttonOrientation
     */
    public GenericDialog(JFrame parentFrame, String titleText, int buttonTypes, int buttonOrientation)
    {
        super(parentFrame, titleText, true);

        this.parentFrame = parentFrame;

        addComponentListener(new ResizeComponentListener());
        addWindowListener(new DialogWindowListener());
        Container c = super.getContentPane(); // don't want our override.
        GridBagLayout gbl = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        c.setLayout(gbl);
        
        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;
        
        if(buttonTypes == NO_BUTTONS)
            gbc.insets = new Insets(VERT_WINDOW_INSET, HORIZ_WINDOW_INSET, VERT_WINDOW_INSET, HORIZ_WINDOW_INSET);
        else
        {
            if(buttonOrientation == HORIZONTAL)
                gbc.insets = new Insets(VERT_WINDOW_INSET, HORIZ_WINDOW_INSET, SEPARATED_COMPONENT_SPACE, HORIZ_WINDOW_INSET);
            else
                gbc.insets = new Insets(VERT_WINDOW_INSET, HORIZ_WINDOW_INSET, VERT_WINDOW_INSET, SEPARATED_COMPONENT_SPACE);
        }
        
        gbl.setConstraints(contentPanel, gbc);
        c.add(contentPanel);

        JPanel buttonPanel = createButtonPanel(buttonTypes, buttonOrientation);
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.BOTH;
        if(buttonOrientation == HORIZONTAL)
        {
            gbc.gridx = 0;       gbc.gridy = 1;
            gbc.anchor = GridBagConstraints.SOUTH;
            gbc.insets = new Insets(0, HORIZ_WINDOW_INSET, VERT_WINDOW_INSET, HORIZ_WINDOW_INSET);
        }
        else
        {
            gbc.gridx = 1;       gbc.gridy = 0;
            gbc.anchor = GridBagConstraints.NORTHEAST;
            gbc.insets = new Insets(VERT_WINDOW_INSET, 0, VERT_WINDOW_INSET, HORIZ_WINDOW_INSET);
        }
        gbl.setConstraints(buttonPanel, gbc);
        c.add(buttonPanel);
    }

    private JPanel createButtonPanel(int buttonTypes, int buttonOrientation)
    {
        Vector v = new Vector();
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        
        extraPanel = new JPanel(new BorderLayout());
        
        GridBagConstraints gbc = new GridBagConstraints();
        ActionListener buttonListener = new DefaultActionListener();
        
        if(buttonOrientation == HORIZONTAL)
        {
            gbc.gridx = GridBagConstraints.RELATIVE;
            gbc.gridy = 0;
            gbc.gridwidth = 1;   gbc.gridheight = 1;
            gbc.weightx = 1.0;   gbc.weighty = 1.0;
            gbc.anchor = GridBagConstraints.EAST;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            JComponent extraComponent = getButtonComponent();
            gbl.setConstraints(extraPanel, gbc);
            p.add(extraPanel);
            
            // for the remainining components...
            gbc.fill = GridBagConstraints.NONE;
            gbc.weightx = 0.0;   gbc.weighty = 0.0;
            gbc.insets = new Insets(0, 0, 0, 0);
        }
        else
        {
            gbc.gridx = 0;
            gbc.gridy = GridBagConstraints.RELATIVE;
            gbc.gridwidth = 1;   gbc.gridheight = 1;
            gbc.weightx = 0.0;   gbc.weighty = 0.0;
            gbc.anchor = GridBagConstraints.NORTH;
            gbc.fill = GridBagConstraints.NONE;
            gbc.insets = new Insets(0, 0, 0, 0);
        }
        
        if((buttonTypes & OK) == OK)
        {
            okButton = ButtonFactory.createPredefinedButton(ButtonFactory.OK, buttonListener);
            okButton.addFocusListener(focusListener);
            v.addElement(okButton);
            setDefaultButton(OK);
            gbl.setConstraints(okButton, gbc);
            p.add(okButton);
        }

        if((buttonTypes & CANCEL) == CANCEL) 
        {
            if(buttonOrientation == HORIZONTAL)
                gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
            else
                gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
            
            cancelButton = ButtonFactory.createPredefinedButton(ButtonFactory.CANCEL, buttonListener);
            cancelButton.addFocusListener(focusListener);
            setFocusComponent(cancelButton);
            setDefaultButton(CLOSE);
            v.addElement(cancelButton);
            gbl.setConstraints(cancelButton, gbc);
            p.add(cancelButton);
        }

        if((buttonTypes & CLOSE) == CLOSE)
        {
            closeButton = ButtonFactory.createPredefinedButton(ButtonFactory.CLOSE, buttonListener);
            closeButton.addFocusListener(focusListener);
            setFocusComponent(closeButton);
            setDefaultButton(CLOSE);
            v.addElement(closeButton);
            gbl.setConstraints(closeButton, gbc);
            p.add(closeButton);
        }

        if((buttonTypes & HELP) == HELP) 
        {
            if(buttonOrientation == HORIZONTAL)
                gbc.insets = new Insets(0, SEPARATED_COMPONENT_SPACE, 0, 0);
            else
                gbc.insets = new Insets(SEPARATED_COMPONENT_SPACE, 0, 0, 0);
                
            helpButton = ButtonFactory.createPredefinedButton(ButtonFactory.HELP, buttonListener);
            helpButton.addFocusListener(focusListener);
            v.addElement(helpButton);
            gbl.setConstraints(helpButton, gbc);
            p.add(helpButton);
        }
        
        if(buttonOrientation == VERTICAL)
        {
            gbc.insets = new Insets(0,0,0,0);
            gbc.weightx = 1.0;   gbc.weighty = 1.0;
            gbc.fill = GridBagConstraints.BOTH;
            gbl.setConstraints(extraPanel, gbc);
            p.add(extraPanel);
        }

        JButton[] buttonGroup = new JButton[v.size()];
        v.copyInto(buttonGroup);
        ButtonFactory.resizeButtons(buttonGroup);
        
        return p;
    }
    
    /**
     * Returns a JComponent to be placed adjacent to the buttons.
     * If button orientation is VERTICAL, this component is placed after the buttons.
     * If button orientation is HORIZONTAL, this component is placed before the buttons.
     * The layout for this component expands it in both directions to fill extra space.
     * 
     * Default implementation returns an empty panel.
     * @return the JComponent to appear adjacent to buttons
     */
    protected JComponent getButtonComponent()
    {
        if(extraPanel.getComponentCount() > 0)
            return (JComponent)extraPanel.getComponent(0);
        return null;
    }
    
    /**
     * Returns a JComponent to be placed adjacent to the buttons.
     * If button orientation is VERTICAL, this component is placed after the buttons.
     * If button orientation is HORIZONTAL, this component is placed before the buttons.
     * The layout for this component expands it in both directions to fill extra space.
     * 
     * Default implementation returns an empty panel.
     * @return the JComponent to appear adjacent to buttons
     */
    protected void setButtonComponent(JComponent c)
    {
        extraPanel.removeAll();
        extraPanel.add(c);
    }
    
    /**
      * Returns the contentPane object for this dialog.
      */
    public Container getContentPane()
    {
        return contentPanel;
    }
    
    /**
    * Sets the minimum size for this dialog.  If the dialog is
    * sized to less than the minimum size, it is expanded to the
    * set minimum size.  The ideal behavior would be to prevent
    * the dragging rectangle from going below the minimum size,
    * but Java doesn't allow enough low-level control for that.
    */
    public void setMinimumSize(Dimension d) 
    {
        setMinimumSize(d.width, d.height);
    }

    /**
    * Sets the minimum size for this dialog.  If the dialog is
    * sized to less than the minimum size, it is expanded to the
    * set minimum size.  The ideal behavior would be to prevent
    * the dragging rectangle from going below the minimum size,
    * but Java doesn't allow enough low-level control for that.
    */
    public void setMinimumSize(int width, int height) 
    {
        minWidth = width;
        minHeight = height;
        super.setSize(width, height);
    }
    
    /**
     * Sets help context-sensitive help info for this dialog.
     * When the Help button is pressed, the help viewer is launched 
     * with these parameters.
     * 
     * @param productID     the product identifier, which corresponds to the manual directory on the back-end
     * @param topic         the help topic contained in tokens.map
     * @see #helpInvoked
     */
    public void setHelpTopic(String productID, String topic)
    {
        helpProduct = productID;
        helpTopic = topic;
    }
    
    /**
     * Returns the help topic used for this dialog.
     * 
     * @return the string that is help token for this dialog.
     * @see #setHelpTopic
     */
    public String getHelpTopic()
    {
        return helpTopic;
    }

    /**
     * Set cursor to busy or to the default one
     * @param busy flag
     */
    public void setBusyCursor( boolean busy) {
        
        Cursor cursor =  Cursor.getPredefinedCursor(
                          busy ? Cursor.WAIT_CURSOR : Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }

    
    /**
    * Adds a listener to provide default action for certain hot keys
    * (i.e., <CR>) to all JTextField components in the dialog.
    */
    private void addTextFieldKeyListener(Container container) 
    {
        Component c[] = container.getComponents();
        for (int i = 0; i < c.length; i++) 
        {
            if (c[i] instanceof JTextField) 
            {
                c[i].removeKeyListener(textFieldKeyListener); // In case it was added before.
                c[i].addKeyListener(textFieldKeyListener);
            } 
            else 
            if (c[i] instanceof Container)
                addTextFieldKeyListener((Container) c[i]);
        }
    }

    /**
    * Shows the dialog.  The dialog is centered relative to parent.
    */
    public void show() 
    {
        addTextFieldKeyListener(contentPanel);
        pack();
        if (parentFrame == null) 
        {
            centerDialog();
        }
        else
        {
            setLocationRelativeTo(parentFrame);
        }
        super.show();
    }

    private void centerDialog() 
    {
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        Dimension size = getSize();
        screenSize.height = screenSize.height/2;
        screenSize.width = screenSize.width/2;
        size.height = size.height/2;
        size.width = size.width/2;
        int y = screenSize.height - size.height;
        int x = screenSize.width - size.width;
        setLocation(x, y);
    }

    /**
    * Sets initial default button (button pressed on enter).
    *
    * @param buttonType OK, CANCEL, CLOSE, or HELP
    */
    public void setDefaultButton(int buttonType)
    {
        switch(buttonType)
        {
            case OK:
            setDefaultButton(okButton);
            break;
            
            case CANCEL:
            setDefaultButton(cancelButton);
            break;
            
            case CLOSE:
            setDefaultButton(closeButton);
            break;

            case HELP:
            setDefaultButton(helpButton);
            break;
        }
    }


    /**
      * Sets initial default button (button pressed on enter).
      */
    public void setDefaultButton(JButton button) 
    {
        defaultButton = button;
        getRootPane().setDefaultButton(button);
    }

    public void setFocusComponent(JComponent c) 
    {
        focusComponent = c;
    }

    public JComponent getFocusComponent() 
    {
        return focusComponent;
    }

    public void setOKButtonEnabled(boolean value)
    {
        okButton.setEnabled(value);
    }

    /**
      * Subclass to detect when cancel button is pressed.
      */
    public boolean isCancel() 
    {
        return (actionPerformed == DO_CANCEL);
    }
    
    /**
      * Subclass to detect when close button is pressed.
      */
    protected void closeInvoked() 
    {
        actionPerformed = DO_ACTION;
        setVisible(false);
    }


    /**
      * Subclass to detect when OK button is pressed.
      */
    protected void okInvoked() 
    {
        actionPerformed = DO_ACTION;
        setVisible(false);
    }


    /**
      * Subclass to detect when cancel button is pressed.
      */
    protected void cancelInvoked() 
    {
        actionPerformed = DO_CANCEL;
        setVisible(false);
    }


    /**
      * Subclass to detect when HELP button is pressed.
      * Default implementation calls Help.showContextHelp
      * with product and topic parameters specified in 
      * setHelpTopic.
      * 
      * @see #setHelpTopic
      */
    protected void helpInvoked() 
    {
        if(helpProduct == null || helpTopic == null)
            throw new IllegalStateException("Help product or token not set.");
        else
            Help.showContextHelp(helpProduct, helpTopic);
    }
    
    class ButtonFocusListener extends FocusAdapter
    {
        public void focusLost(FocusEvent e) 
        {
            setDefaultButton(defaultButton);
        }
    }

    class TextFieldKeyListener extends KeyAdapter 
    {
        public void keyPressed(KeyEvent e) 
        {
            if (e.getKeyCode() == KeyEvent.VK_ENTER) 
            {
                if (defaultButton != null)
                    defaultButton.doClick();
            }
        }
    }
    
    class ResizeComponentListener extends ComponentAdapter
    {
        public void componentResized(ComponentEvent e) 
        {
            if (isResizable()) 
            {
                boolean resizeWidth = (getSize().width < minWidth);
                boolean resizeHeight = (getSize().height < minHeight);

                if (resizeWidth || resizeHeight) {
                    setSize(resizeWidth ? minWidth : getSize().width,
                            resizeHeight ? minHeight : getSize().height);
                }
            }
        }
    }

    class DialogWindowListener extends WindowAdapter 
    {

        public void windowOpened(WindowEvent e) 
        {
            if (focusComponent != null)
                focusComponent.requestFocus();
        }

        public void windowClosing(WindowEvent e) 
        {
            cancelInvoked();
        }
    }

    class DefaultActionListener implements ActionListener 
    {
        public void actionPerformed(ActionEvent e) {
            String cmd = e.getActionCommand();
            if (cmd != null) {
                if (cmd.equals(ButtonFactory.OK)) {
                    okInvoked();
                } else if (cmd.equals(ButtonFactory.CLOSE)) {
                    closeInvoked();
                } else if (cmd.equals(ButtonFactory.CANCEL)) {
                    cancelInvoked();
                } else if (cmd.equals(ButtonFactory.HELP)) {
                    helpInvoked();
                }
            }
        }
    }
}
