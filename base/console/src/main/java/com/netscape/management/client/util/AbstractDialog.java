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

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Vector;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.UIManager;

import com.netscape.management.nmclf.SuiConstants;

/**
 * AbstractDialog defines a basic dialog which consists of two main areas:
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
 * - BUG FIX: dispose on Solaris causes segv occasionally
 * - BUG FIX: setMinimumSize() does not work
 *
 * @author  Peter Lee (phlee@netscape.com)
 * @author  Chih-Ming Shih (shihcm@netscape.com)
 * @author  Andy Hakim (ahakim@netscape.com)
 */
public abstract class AbstractDialog extends JDialog implements SwingConstants,
SuiConstants {

    // How this dialog was dismissed determines what should occur next.
    static final int DO_NOTHING = 0;
    static final int DO_ACTION = 1;
    static final int DO_CANCEL = 2;

    public static final int HORIZONTAL_BUTTONS = SwingConstants.HORIZONTAL;
    public static final int VERTICAL_BUTTONS = SwingConstants.VERTICAL;

    public static final int NO_BUTTONS = 0;
    public static final int OK = 1;
    public static final int CANCEL = 2;
    public static final int CLOSE = 4;
    public static final int HELP = 8;
    protected FocusListener _focusListener = new ButtonFocusListener();
    public JButton _defaultButton;

    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");

    /**
     * This check is needed to prevent disposing of modal dialogs on
     * Solaris which causes a segv.
     */
    private static final boolean _isSolaris =
            System.getProperty("os.name").equalsIgnoreCase("solaris");
    private static final boolean _isIrix =
            System.getProperty("os.name").equalsIgnoreCase("irix");
    private static final boolean _isWinNT =
            System.getProperty("os.name").equalsIgnoreCase("windows nt");

    private Component _buttonComponent;
    private JPanel _customPanel;
    private JButton _closeButton = null;
    private JButton _okButton = null;
    private JButton _cancelButton = null;
    private JButton _helpButton = null;
    private int _buttons = 0;
    private int _buttonOrientation = HORIZONTAL;
    private JComponent _focusComponent = null;
    private Frame _parentFrame = null;
    private int minWidth = 0;
    private int minHeight = 0;
    protected int _actionPerformed;


    /**
     * Contructs a non-Modal dialog with no title, but no buttons.
    * Use this if you want to create your own buttons, but still
    * want the other benefits of AbstractDialog.
    *
    * @param parentFrame the parent Frame
     */
    public AbstractDialog(Frame parentFrame) {
        this(parentFrame, null, false);
    }


    /**
      * Contructs a Modal dialog with no title, but no buttons.
     * Use this if you want to create your own buttons, but still
     * want the other benefits of AbstractDialog.
     *
     * @param parentFrame the parent Frame
     * @param modal true if dialog should have modal behavior
      */
    public AbstractDialog(Frame parentFrame, boolean modal) {
        this(parentFrame, null, modal);
    }


    /**
      * Contructs a non-Modal dialog with specified title, but no buttons.
     * Use this if you want to create your own buttons, but still
     * want the other benefits of AbstractDialog.
     *
     * @param parentFrame the parent Frame
     * @param title window title
      */
    public AbstractDialog(Frame parentFrame, String title) {
        this(parentFrame, title, false);
    }

    /**
      * Contructs a non-Modal dialog with specified title and no buttons.
     * Use this if you want to create your own buttons, but still
     * want the other benefits of AbstractDialog.
     *
     * @param parentFrame the parent Frame
     * @param title window title
     * @param buttons NO_BUTTONS | OK | CANCEL | CLOSE | HELP
     * @param modal true if dialog should have modal behavior
      */
    public AbstractDialog(Frame parentFrame, String title, boolean modal) {
        this(parentFrame, title, modal, NO_BUTTONS, HORIZONTAL);
    }


    /**
      * Contructs a non-Modal dialog with specified title and buttons
     * that are layed out horizontally.
     * Use this if you want to create your own buttons, but still
     * want the other benefits of AbstractDialog.
     *
     * @param parentFrame the parent Frame
     * @param title window title
     * @param buttons NO_BUTTONS | OK | CANCEL | CLOSE | HELP
      */
    public AbstractDialog(Frame parentFrame, String title, int buttons) {
        this(parentFrame, title, false, buttons);
    }


    /**
      * Contructs a non-Modal dialog with specified title and buttons
     * that are layed out horizontally.
     * Use this if you want to create your own buttons, but still
     * want the other benefits of AbstractDialog.
     *
     * @param parentFrame the parent Frame
     * @param title window title
     * @param buttons NO_BUTTONS | OK | CANCEL | CLOSE | HELP
     * @param modal true if dialog should have modal behavior
      */
    public AbstractDialog(Frame parentFrame, String title,
            boolean modal, int buttons) {
        this(parentFrame, title, modal, buttons, HORIZONTAL);
    }


    /**
      * Contructs a non-Modal dialog with specified title and buttons.
     * Use this if you want to create your own buttons, but still
     * want the other benefits of AbstractDialog.
     *
     * @param parentFrame the parent Frame
     * @param title window title
     * @param modal true if dialog should have modal behavior
     * @param buttons NO_BUTTONS | OK | CANCEL | CLOSE | HELP
     * @param buttonOrientation HORIZONTAL_BUTTONS or VERTICAL_BUTTONS
      */
    public AbstractDialog(Frame parentFrame, String title,
            boolean modal, int buttons, int buttonOrientation) {
        super(parentFrame == null ?
                UtilConsoleGlobals.getActivatedFrame() : parentFrame,
                title, modal);

        Debug.println(Debug.TYPE_GC,
                Debug.KW_CREATE +
                Debug.getShortClassName(getClass().getName()) + " " +
                getName());

        this._parentFrame = (parentFrame == null ?
                UtilConsoleGlobals.getActivatedFrame() : parentFrame);
        addComponentListener(new ResizeComponentListener());
        addWindowListener(new DialogWindowListener());
        Container c = super.getContentPane(); // We don't want our override.
        c.setLayout(new GridBagLayout());
        _buttons = buttons;
        _buttonOrientation = buttonOrientation;
        _actionPerformed = DO_NOTHING;
        //_customPanel = new JPanel(new BorderLayout(0, 0));
        _customPanel = new JPanel(new BorderLayout());
        GridBagUtil.constrain(c, _customPanel, 0, 0, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                VERT_WINDOW_INSET, // top
                HORIZ_WINDOW_INSET, // left
                _buttonOrientation == HORIZONTAL ?
                SEPARATED_COMPONENT_SPACE : VERT_WINDOW_INSET, // bottom
                _buttonOrientation == HORIZONTAL ?
                HORIZ_WINDOW_INSET : SEPARATED_COMPONENT_SPACE); // right
                if (_buttons != 0) {
            if (_buttonOrientation == HORIZONTAL) {
                _buttonComponent = new HorizontalButtonPanel(
                        new DialogActionListener());
                GridBagUtil.constrain(c, _buttonComponent, 0, 1, 1, 1,
                        1.0, 0.0, GridBagConstraints.WEST,
                        GridBagConstraints.HORIZONTAL, 0,
                        HORIZ_WINDOW_INSET, VERT_WINDOW_INSET,
                        HORIZ_WINDOW_INSET);
            } else {
                _buttonComponent = new VerticalButtonPanel(
                        new DialogActionListener());
                GridBagUtil.constrain(c, _buttonComponent, 1, 0, 1, 1,
                        0.0, 0.0, GridBagConstraints.NORTH,
                        GridBagConstraints.NONE, VERT_WINDOW_INSET, 0,
                        VERT_WINDOW_INSET, HORIZ_WINDOW_INSET);
            }
        }

        c.setBackground(UIManager.getColor("control"));
        c.setForeground(UIManager.getColor("textText"));
    }

    protected void finalize() throws Throwable {
        Debug.println(Debug.TYPE_GC,
                Debug.KW_FINALIZE +
                Debug.getShortClassName(getClass().getName()) + " " +
                getName());
        super.finalize();
    }

    /**
      * Returns the button panel container.  Used when customizing the
     * button panel with some other non-button like widget.
      */
    protected Component getButtonComponent() {
        return _buttonComponent;
    }


    /**
      * Inner class which handles component resize events. Basically, this
     * listener prevents the dialog from being resized smaller than its
     * minimum size.
      */
    class ResizeComponentListener implements ComponentListener {
        public void componentResized(ComponentEvent e) {
            if (isResizable()) {
                boolean resizeWidth = (getSize().width < minWidth);
                boolean resizeHeight = (getSize().height < minHeight);

                if (resizeWidth || resizeHeight) {
                    setSize(resizeWidth ? minWidth : getSize().width,
                            resizeHeight ? minHeight : getSize().height);
                }
            }
        }

        public void componentMoved(ComponentEvent e) {
        }

        public void componentShown(ComponentEvent e) {
        }

        public void componentHidden(ComponentEvent e) {
        }
    }


    /**
      * Sets the minimum size for this dialog.  If the dialog is
     * sized to less than the minimum size, it is expanded to the
     * set minimum size.  The ideal behavior would be to prevent
     * the dragging rectangle from going below the minimum size,
     * but Java doesn't allow enough low-level control for that.
      */
    public void setMinimumSize(Dimension d) {
        setMinimumSize(d.width, d.height);
    }

    /**
      * Sets the minimum size for this dialog.  If the dialog is
     * sized to less than the minimum size, it is expanded to the
     * set minimum size.  The ideal behavior would be to prevent
     * the dragging rectangle from going below the minimum size,
     * but Java doesn't allow enough low-level control for that.
      */
    public void setMinimumSize(int width, int height) {
        minWidth = width;
        minHeight = height;
        super.setSize(width, height);
    }


    /**
      * Shows the dialog.  The dialog is centered relative to parent.
      */
    public void show() {
        if (_parentFrame != null && _parentFrame.isVisible()) {
            setDialogLocation(_parentFrame);
        } else {
            center();
        }
        super.show();
        this.toFront();
    }

    /**
     * Needed to show dialog centered on a parent frame that is not
     * necessarily the same parent frame that was created.
     */
    protected void setParentFrame(JFrame parent) {
        _parentFrame = parent;
    }


    /**
      * This makes it easy to subclass and reposition dialog.
      */
    protected void setDialogLocation(Frame parentFrame) {
        ModalDialogUtil.setDialogLocation(this, parentFrame);
    }


    /**
      * Shows dialog as modal, regardless of what modallity was set
     * during construction.
      */
    public void showModal() {
        setModal(true);
        show();
    }

    /**
     * Center the dialog on the screen
     */
    protected void center() {
        Dimension screenSize =
            Toolkit.getDefaultToolkit().getScreenSize();
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
      * disposes resources used by this dialog.  Automatically called
     * on hide() or setVisible(false);
      */
    public void dispose() {
        // Work around to prevent disposing of modal dialogs on Solaris
        // which causes a segv.
        if ((_isIrix || _isSolaris) && isModal()) {
            super.setVisible(false);
        } else {
            if (_parentFrame != null) {
                super.dispose();
            }
        }
    }

    /**
      * TODO: this should be private
      */
    public void disposeAndRaise() {
        setVisible(false);
        if (_parentFrame != null) {
            ModalDialogUtil.raise(_parentFrame);
        }
    }

    /**
      * fixes bug nonresizable size bug on UNIX
     * see http://developer.javasoft.com/developer/bugParade/bugs/4041679.html
      */
    public void pack() {
        // http://developer.javasoft.com/developer/bugParade/bugs/4041679.html
        // Setting dialog nonresizable before pack causes a ridiculous dialog size on UNIX
        boolean old = isResizable();
        setResizable(true);
        super.pack();
        setResizable(old);
    }

    /**
      * Inner class used to handle window events.
      */
    class DialogWindowListener extends WindowAdapter {

        public void windowActivated(WindowEvent e) {
            if (_focusComponent != null)
                _focusComponent.requestFocus();

            if (Debug.timeTraceEnabled()) {
                Debug.println(Debug.TYPE_RSPTIME,
                        Debug.getShortClassName(
                        AbstractDialog.this.getClass().getName()) + " shown");
            }
        }

        public void windowClosing(WindowEvent e) {
            cancelInvoked();
        }
    }

    /**
      * Inner class used to implement ActionListener.
      */
    class DialogActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            String cmd = e.getActionCommand();
            if (cmd != null) {
                if (cmd.equals("OK")) {
                    okInvoked();
                } else if (cmd.equals("CLOSE")) {
                    closeInvoked();
                } else if (cmd.equals("CANCEL")) {
                    cancelInvoked();
                } else if (cmd.equals("HELP")) {
                    helpInvoked();
                }
            }
        }
    }


    /**
      * Inner class used to layout the dialog buttons in accordance with
      * the L&F spec.
      */
    class HorizontalButtonPanel extends Box {
        HorizontalButtonPanel(ActionListener listener) {
            super(BoxLayout.X_AXIS);
            Vector v = new Vector();

            add(Box.createHorizontalGlue());

            if ((_buttons & OK) == OK) {
                _okButton = JButtonFactory.createOKButton(listener);
                _okButton.addFocusListener(
                        AbstractDialog.this._focusListener);
                add(_okButton);
                v.addElement(_okButton);
                setDefaultButton(OK);
            }

            if ((_buttons & CANCEL) == CANCEL) {
                _cancelButton = JButtonFactory.createCancelButton(listener);
                _cancelButton.addFocusListener(
                        AbstractDialog.this._focusListener);
                _focusComponent = _cancelButton;
                add(Box.createHorizontalStrut(COMPONENT_SPACE));
                add(_cancelButton);
                if ((_buttons & OK) != OK) {
                    setDefaultButton(CANCEL);
                }
                v.addElement(_cancelButton);
            }

            if ((_buttons & CLOSE) == CLOSE) {
                _closeButton = JButtonFactory.createCloseButton(listener);
                _closeButton.addFocusListener(
                        AbstractDialog.this._focusListener);
                _focusComponent = _closeButton;
                add(_closeButton);
                setDefaultButton(CLOSE);
                v.addElement(_closeButton);
            }

            if ((_buttons & HELP) == HELP) {
                _helpButton = JButtonFactory.createHelpButton(listener);
                _helpButton.addFocusListener(
                        AbstractDialog.this._focusListener);
                add(Box.createHorizontalStrut(SEPARATED_COMPONENT_SPACE));
                add(_helpButton);
                v.addElement(_helpButton);
            }

            JButton[] buttonGroup = new JButton[v.size()];
            v.copyInto(buttonGroup);
            if (buttonGroup != null) {
                JButtonFactory.resize(buttonGroup);
            }
        }
    }


    /**
      * Inner class used to layout the dialog buttons in accordance with
      * the L&F spec.
      */
    class VerticalButtonPanel extends JPanel {
        VerticalButtonPanel(ActionListener listener) {
            int y = 0;
            setLayout(new GridBagLayout());
            Vector v = new Vector();

            if ((_buttons & OK) == OK) {
                _okButton = JButtonFactory.createOKButton(listener);
                _okButton.addFocusListener(
                        AbstractDialog.this._focusListener);
                GridBagUtil.constrain(this, _okButton, 0, y++, 1, 1,
                        1.0, 0.0, GridBagConstraints.NORTH,
                        GridBagConstraints.NONE, 0, 0, 0, 0);
                v.addElement(_okButton);
                setDefaultButton(OK);
            }

            if ((_buttons & CANCEL) == CANCEL) {
                _cancelButton = JButtonFactory.createCancelButton(listener);
                _cancelButton.addFocusListener(
                        AbstractDialog.this._focusListener);
                _focusComponent = _cancelButton;
                GridBagUtil.constrain(this, _cancelButton, 0, y++, 1,
                        1, 1.0, 0.0, GridBagConstraints.NORTH,
                        GridBagConstraints.NONE, COMPONENT_SPACE, 0, 0, 0);
                v.addElement(_cancelButton);
                if ((_buttons & OK) != OK) {
                    setDefaultButton(CANCEL);
                }
            }

            if ((_buttons & CLOSE) == CLOSE) {
                _closeButton = JButtonFactory.createCloseButton(listener);
                _closeButton.addFocusListener(
                        AbstractDialog.this._focusListener);
                _focusComponent = _closeButton;
                GridBagUtil.constrain(this, _closeButton, 0, y++, 1, 1,
                        1.0, 0.0, GridBagConstraints.NORTH,
                        GridBagConstraints.NONE, 0, 0, 0, 0);
                setDefaultButton(CLOSE);
                v.addElement(_closeButton);
            }

            if ((_buttons & HELP) == HELP) {
                _helpButton = JButtonFactory.createHelpButton(listener);
                _helpButton.addFocusListener(
                        AbstractDialog.this._focusListener);
                GridBagUtil.constrain(this, _helpButton, 0, y++, 1, 1,
                        1.0, 0.0, GridBagConstraints.NORTH,
                        GridBagConstraints.NONE,
                        SEPARATED_COMPONENT_SPACE, 0, 0, 0);
                v.addElement(_helpButton);
            }

            JButton[] buttonGroup = new JButton[v.size()];
            v.copyInto(buttonGroup);
            if (buttonGroup != null) {
                JButtonFactory.resize(buttonGroup);
            }
        }
    }


    /**
      * Sets initial default button (button pressed on enter).
     *
     * @param button OK or CANCEL or CLOSE or HELP
      */
    public void setDefaultButton(int button) {

        if (button == OK) {
            setDefaultButton(_okButton);
        } else if (button == CANCEL) {
            setDefaultButton(_cancelButton);
        } else if (button == CLOSE) {
            setDefaultButton(_closeButton);
        } else if (button == HELP) {
            setDefaultButton(_helpButton);
        }
    }


    /**
      * Sets initial default button (button pressed on enter).
      */
    public void setDefaultButton(JButton button) {
        _defaultButton = button;
        // If another button has a focus then it is automatically the defaut button
        if (_focusComponent != null && _focusComponent instanceof JButton) {
            setFocusComponent(button);
        }
        getRootPane().setDefaultButton(button);
    }


    /**
      * Tests if dialog ended because of a CANCEL action
      */
    public boolean isCancel() {
        return (_actionPerformed == DO_CANCEL);
    }


    /**
      * Called when CLOSE button is pressed
      */
    protected void closeInvoked() {
        _actionPerformed = DO_ACTION;
        setVisible(false);
    }


    /**
      * Called when OK button is pressed
      */
    protected void okInvoked() {
        _actionPerformed = DO_ACTION;
        setVisible(false);
    }


    /**
      * Called when CANCEL button is pressed
      */
    protected void cancelInvoked() {
        _actionPerformed = DO_CANCEL;
        setVisible(false);
    }


    /**
      * Called when HELP button is pressed
      */
    protected void helpInvoked() {
        Debug.println(0, "Help not implemented for " + getClass().getName());
    }


    /**
      * Returns a panel that will be used as the custom panel.
      */
    public Container getContentPane() {
        return _customPanel;
    }


    /**
      * Set custom panel.  This is the area that contains the
     * 'meat' of the dialog.
     * @deprecated use setComponent
      */
    @Deprecated
    public void setPanel(JPanel panel) {
        setComponent(panel);
    }


    /**
      * Set custom component.
      */
    public void setComponent(Component panel) {
        _customPanel.add("Center", panel);
        pack();
        super.getContentPane().validate();
    }


    /**
      * Set which component has initial focus
      */
    public void setFocusComponent(JComponent c) {

        // This is a workaround for what appears to be a JDK bug;  if a
        // button loses the focus as a result of setFocus() call, it might
        // still paint the focus (multiple buttons are painted with the focus)
        if (_focusComponent != null && _focusComponent instanceof JButton) {
           ((JButton)_focusComponent).setFocusPainted(false);
        }

        _focusComponent = c;

        if (_focusComponent != null && _focusComponent instanceof JButton) {
           ((JButton)_focusComponent).setFocusPainted(true);
        }
    }


    /**
      * Set OK button label.
      */
    public void setOKButtonText(String text) {
        _okButton.setText(text);
        JButtonFactory.resizeGroup(_okButton, _closeButton,
                _cancelButton, _helpButton);
        super.getContentPane().validate();
    }


    /**
      * Enable or disable OK button.
      */
    public void setOKButtonEnabled(boolean value) {
        _okButton.setEnabled(value);
    }


    /**
      * Make the OK button visible or invisible.
     * @deprecated no longer needed because button panel can be customized
      */
    @Deprecated
    public void setOKButtonVisible(boolean value) {
        _okButton.setVisible(value);
    }


    /**
      * Set Cancel button label.
      */
    public void setCancelButtonText(String text) {
        _cancelButton.setText(text);
        JButtonFactory.resizeGroup(_okButton, _closeButton,
                _cancelButton, _helpButton);
        super.getContentPane().validate();
    }


    /**
      * Enable or disable Cancel button.
     * @deprecated should ALWAYS be able to cancel!
      */
    @Deprecated
    public void setCancelButtonEnabled(boolean value) {
        _cancelButton.setEnabled(value);
    }


    /**
      * Make the Cancel button visible or invisible.
     * @deprecated no longer needed because button panel can be customized
      */
    @Deprecated
    public void setCancelButtonVisible(boolean value) {
        _cancelButton.setVisible(value);
    }

    private boolean _busyCursorOn;

    /**
     * Override setCursor to show busy cursor correctly
     */
    public void setCursor(Cursor cursor) {
        if (_busyCursorOn && cursor.getType() != Cursor.WAIT_CURSOR) {
            Debug.println(9, "AbstractDialog.setCursor(): Discarding change of cursor");
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
        if (_cancelButton != null) {
        	_cancelButton.setCursor(Cursor.getDefaultCursor());
        }
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

    /**
     * Set Close button label.
     */
    public void setCloseButtonText(String text) {
        _closeButton.setText(text);
        JButtonFactory.resizeGroup(_okButton, _closeButton,
                _cancelButton, _helpButton);
        super.getContentPane().validate();
    }


    /**
      * Enable or disable Close button.
     * @deprecated help should always be available, else don't use HELP button
      */
    @Deprecated
    public void setCloseButtonEnabled(boolean value) {
        _closeButton.setEnabled(value);
    }


    /**
      * Make the Close button visible or invisible.
     * @deprecated no longer needed because button panel can be customized
      */
    @Deprecated
    public void setCloseButtonVisible(boolean value) {
        _closeButton.setVisible(value);
    }


    /**
      * Set Help button label.
     * @deprecated help should always be available, else don't use HELP button
      */
    @Deprecated
    public void setHelpButtonText(String text) {
        _helpButton.setText(text);
        JButtonFactory.resizeGroup(_okButton, _closeButton,
                _cancelButton, _helpButton);
        super.getContentPane().validate();
    }


    /**
      * Enable or disable Help button.
      */
    public void setHelpButtonEnabled(boolean value) {
        _helpButton.setEnabled(value);
    }


    /**
      * Make the Help button visible or invisible.
     * @deprecated no longer needed because button panel can be customized
      */
    @Deprecated
    public void setHelpButtonVisible(boolean value) {
        _helpButton.setVisible(value);
    }


    /**
      * Inner class which handles focus events for buttons.
      */
    class ButtonFocusListener implements FocusListener {
        public void focusGained(FocusEvent e) {
        }

        public void focusLost(FocusEvent e) {
            setDefaultButton(_defaultButton);
        }
    }
}
