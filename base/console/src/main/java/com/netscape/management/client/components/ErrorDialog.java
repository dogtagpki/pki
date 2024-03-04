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
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.util.*;
/**
 * This <B> ErrorDialog </B> is used that displays three types of 
 * information: Description, Tip, and Detail.
 *
 */
public class ErrorDialog extends JDialog 
{   public final static int DEFAULT = -1;
    public final static int OK = 1;
    public final static int CANCEL = 2;
    public final static int YES = 3;
    public final static int NO = 4;
    public final static int OK_CANCEL = 5;
    public final static int YES_NO = 6;
    public final static int DETAIL = 7;
    
    public final static String ERROR_ICON = "OptionPane.errorIcon";
    public final static String WARNING_ICON = "OptionPane.warningIcon";
    public final static String INFORMATION_ICON = "OptionPane.informationIcon";
    public final static String QUESTION_ICON = "OptionPane.questionIcon";
    
    String _lblOk = i18n("ok");
    String _lblYes = i18n("yes");
    String _lblCancel = i18n("cancel");
    String _lblNo = i18n("no");
	String _lblDetails = i18n("details");
    
    private int _minWidth ,_minHeight, _minHeightDetail;
    private int _minButtonWidth, _minButtonHeight;
    private JButton _okYesButton, _cancelNoButton, _detailButton;
    private MultilineLabel _detailLabel, _errorLabel, _tipLabel;
    private JLabel _iconLabel;
    private JPanel _buttonPanel;
    private Component _invisibleButton;
    private ImageIcon _icon;
    private int _defaultButton, buttonOption;
    private int buttonClicked;
    private boolean _detailShown;
    private Container _contentPane;
    private JScrollPane _scrollPane;
    private static int DEFAULT_TEXT_WIDTH = 35;
    private int lastWidth, lastHeight;
    private FocusListener _focusListener = new ButtonFocusListener();
    private JComponent _focusComponent = null;
    private boolean _windowCloseButtonInvoked = false;
    private Window _parentWindow;
    private static final boolean _isSolaris =
            System.getProperty("os.name").equalsIgnoreCase("solaris");
    private static final boolean _isIrix =
            System.getProperty("os.name").equalsIgnoreCase("irix");
    private static final boolean _isWinNT =
            System.getProperty("os.name").equalsIgnoreCase("windows nt");
	
	public static ResourceSet _resource = new ResourceSet("com.netscape.management.client.components.components");    
	public static String i18n(String id) {
        return _resource.getString("errorDialog", id);
    }
	
    /**
    *
    * Constructs a modal ErrorDialog with a parent frame, a title for the ErrorDialog,
    * an error description and a default OK button
    */
    public ErrorDialog(Frame parent, String title, String errorText)
    {
        this(parent, title, errorText, null, null, DEFAULT, DEFAULT);
    }

    /**
    *
    * Constructs a modal ErrorDialog with a parent dialog, a title for the ErrorDialog,
    * an error description and a default OK button
    */
    public ErrorDialog(Dialog parent, String title, String errorText)
    {
        this(parent, title, errorText, null, null, DEFAULT, DEFAULT);
    }
    
    /**
     *
     * Constructs a modal ErrorDialog with a parent frame, a title for the ErrorDialog,
     * an error message, a tip text, and a default OK button
     */
    public ErrorDialog(Frame parent, String title, String errorText, String tipText)
    {
        this(parent, title, errorText, tipText, null, DEFAULT, DEFAULT);
    }

    /**
     *
     * Constructs a modal ErrorDialog with a parent dialog, a title for the ErrorDialog,
     * an error message, a tip text, and a default OK button
     */
    public ErrorDialog(Dialog parent, String title, String errorText, String tipText)
    {
        this(parent, title, errorText, tipText, null, DEFAULT, DEFAULT);
    }
    
    /**
     *
     * Constructs a modal ErrorDialog with a parent frame, a title for the ErrorDialog, 
     * an error description, a tip text, a detail text, a specified button option
     * (whether the ErrorDialog has the OK and Cancel buttons or Yes and No buttons or
     * whether it has the Detail button in it), and a specified default focused button
     */
    public ErrorDialog(Frame parent, String title, String errorText, String tipsText, 
                       String detailText, int buttonOption, int defaultButton)
    {
        super(parent, title, true);
        initialize(parent, errorText, tipsText, detailText, buttonOption, defaultButton);        
    }
   
    /**
     *
     * Constructs a modal ErrorDialog with a parent dialog, a title for the ErrorDialog, 
     * an error description, a tip text, a detail text, a specified button option
     * (whether the ErrorDialog has the OK and Cancel buttons or Yes and No buttons or
     * whether it has the Detail button in it), and a specified default focused button
     */
    public ErrorDialog(Dialog parent, String title, String errorText, String tipsText, 
                       String detailText, int buttonOption, int defaultButton)
    {
        super(parent, title, true);
        initialize(parent, errorText, tipsText, detailText, buttonOption, defaultButton);
    }

    private void initialize(Window parent, String errorText, String tipsText, 
                       String detailText, int buttonOption, int defaultButton)
    {
        _parentWindow = parent;
        createLayout(errorText, tipsText, detailText, buttonOption, defaultButton);
        _detailShown = true;
        _detailButton.setToolTipText(i18n("details_hide_tt"));
         pack();
        setMinimumSize(getPreferredSize().width, getPreferredSize().height);
        _scrollPane.setBorder(new BevelBorder(BevelBorder.LOWERED));
        _scrollPane.setVisible(true);
        _detailLabel.setVisible(true);
        
        Dimension size = getPreferredSize();
        _minHeightDetail = size.height;
        lastHeight = size.height;
        lastWidth = size.width;
        
        _defaultButton = defaultButton;
        setDefaultButton(_defaultButton);
        
        addWindowListener(new DialogWindowListener());
        
        if (parent != null)
        {
            setLocationRelativeTo(parent);
        }
    }

    /**
     *
     * Creates the layout for all components of the ErrorDialog
     */
    private void createLayout(String errorText, String tipText, String detailText, int buttonOption, int defaultButton)
    {
        _defaultButton = defaultButton;
        addComponentListener(new ResizeComponentListener());
        _contentPane = getContentPane();
        GridBagLayout g = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        _contentPane.setLayout(g);
       
        _iconLabel = new JLabel(UIManager.getIcon(ERROR_ICON), JLabel.CENTER);
        
        c.insets = new Insets(SuiConstants.VERT_WINDOW_INSET,SuiConstants.HORIZ_WINDOW_INSET,SuiConstants.SEPARATED_COMPONENT_SPACE / 2,SuiConstants.SEPARATED_COMPONENT_SPACE / 2);       
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 2;
        c.anchor = GridBagConstraints.NORTH;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.weighty = 0;
        g.setConstraints(_iconLabel,c);
        _contentPane.add(_iconLabel);
        
        
    //This is for error label
                
        _errorLabel = new MultilineLabel(errorText,1,DEFAULT_TEXT_WIDTH);
        c.insets = new Insets(SuiConstants.VERT_WINDOW_INSET,SuiConstants.SEPARATED_COMPONENT_SPACE / 2,SuiConstants.COMPONENT_SPACE,SuiConstants.SEPARATED_COMPONENT_SPACE / 2);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.anchor = GridBagConstraints.NORTH;
        c.weightx = 1;
        g.setConstraints(_errorLabel, c);
        _contentPane.add(_errorLabel);
        
     //This is for solution label
     
        if (tipText != null)
        {               
            _tipLabel = new MultilineLabel (tipText,1,DEFAULT_TEXT_WIDTH);
            c.insets = new Insets(0,SuiConstants.SEPARATED_COMPONENT_SPACE / 2,SuiConstants.SEPARATED_COMPONENT_SPACE / 2,SuiConstants.SEPARATED_COMPONENT_SPACE);
            c.gridx = 1;
            c.gridy = 1;
            c.gridwidth = 1;
            c.gridheight = 1;
            c.weightx = 1;
            g.setConstraints(_tipLabel, c);
            _contentPane.add(_tipLabel);

        }
     //This is for detail label
         if (detailText != null)
         {
            _detailLabel = new MultilineLabel(detailText,6,DEFAULT_TEXT_WIDTH);
         }
         else
         {
             _detailLabel = new MultilineLabel("",6,DEFAULT_TEXT_WIDTH);
         }
         _detailLabel.setBorder(new CompoundBorder(new EmptyBorder(0,0,0,0), new EmptyBorder(5,5,5,5)));
         _scrollPane = new JScrollPane(_detailLabel,ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
         _scrollPane.setBorder(new EmptyBorder(0,0,0,0));
         c.insets = new Insets(0,SuiConstants.HORIZ_WINDOW_INSET ,SuiConstants.VERT_WINDOW_INSET,SuiConstants.HORIZ_WINDOW_INSET);
         c.fill = GridBagConstraints.BOTH;
         c.gridx = 0;
         c.gridy = 2;
         c.gridwidth = 3;
         c.gridheight = 1;
         c.weightx = 1;
         c.weighty = 1;
         g.setConstraints(_scrollPane, c);
         _contentPane.add(_scrollPane);
         _detailLabel.setVisible(false);
         _scrollPane.setVisible(false);
           
        
        // This is for buttons
        _buttonPanel = createButtonPanel(buttonOption);
      // _buttonPanel.setBackground(Color.cyan);
        c.insets = new Insets(SuiConstants.VERT_WINDOW_INSET,SuiConstants.SEPARATED_COMPONENT_SPACE / 2,SuiConstants.SEPARATED_COMPONENT_SPACE / 2,SuiConstants.HORIZ_WINDOW_INSET);
        c.gridx = 2;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 2;
        c.anchor = GridBagConstraints.NORTH;
        
        c.fill = GridBagConstraints.VERTICAL;
        c.weightx = 0;
        c.weighty = 0;
        g.setConstraints(_buttonPanel,c);
        _contentPane.add(_buttonPanel);
    }
    
    /**
     *
     * Creates a panel containing buttons using gridbag layout
     *
     * @param buttonOption the default button option
     */
    private JPanel createButtonPanel(int buttonOption) 
    {
        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        
        _buttonPanel = new JPanel();
        _buttonPanel.setLayout(gridBag);
        
        if (buttonOption == OK || buttonOption == DEFAULT)
        {
            _okYesButton = new JButton(_lblOk);
            setMinimumButtonSize(_okYesButton);
            _okYesButton.addActionListener(new OKButtonActionListener());
            _okYesButton.addFocusListener(
                        ErrorDialog.this._focusListener);
        }
        else if (buttonOption == OK_CANCEL)
        {
            _okYesButton = new JButton(_lblOk);
            setMinimumButtonSize(_okYesButton);
            _okYesButton.addActionListener(new OKButtonActionListener());
            _okYesButton.addFocusListener(
                        ErrorDialog.this._focusListener);
            _cancelNoButton = new JButton(_lblCancel);
            setMinimumButtonSize(_cancelNoButton);
            _cancelNoButton.addActionListener(new CancelButtonActionListener());
            _cancelNoButton.addFocusListener(
                        ErrorDialog.this._focusListener);
        }
        else if (buttonOption == YES)
        {
            _okYesButton = new JButton(_lblYes);
            setMinimumButtonSize(_okYesButton);
            _okYesButton.addActionListener(new OKButtonActionListener());
            _okYesButton.addFocusListener(
                        ErrorDialog.this._focusListener);
        }
        else if (buttonOption == YES_NO)
        {
            _okYesButton = new JButton(_lblYes);
            setMinimumButtonSize(_okYesButton);
            _okYesButton.addActionListener(new OKButtonActionListener());
            _okYesButton.addFocusListener(
                        ErrorDialog.this._focusListener);
            _cancelNoButton = new JButton(_lblNo);
            setMinimumButtonSize(_cancelNoButton);
            _cancelNoButton.addActionListener(new CancelButtonActionListener());
            _cancelNoButton.addFocusListener(
                        ErrorDialog.this._focusListener);
        }
        
        _detailButton = new JButton(_lblDetails + " <<");
        setMinimumButtonSize(_detailButton);
        _detailButton.addFocusListener(
                        ErrorDialog.this._focusListener);
        _detailButton.addActionListener(new DetailButtonActionListener());
        c.weightx = 0;
        c.weighty = 0;
        c.insets = new Insets(0,0,SuiConstants.COMPONENT_SPACE,0);
        
        _okYesButton.setMinimumSize(new Dimension(_minButtonWidth, _minButtonHeight));
        _okYesButton.setMaximumSize(new Dimension(_minButtonWidth, _minButtonHeight));
        _okYesButton.setPreferredSize(new Dimension(_minButtonWidth, _minButtonHeight));
        
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.NORTH;
        if (buttonOption == DEFAULT)
        {
            c.weighty = 1;
        }
        gridBag.setConstraints(_okYesButton, c);
        _buttonPanel.add(_okYesButton);
        
        if (buttonOption != DEFAULT)
        {
            c.gridy = 1;
            if (buttonOption == OK || buttonOption == YES)
            {
            
                _detailButton.setMinimumSize(new Dimension(_minButtonWidth, _minButtonHeight));
                _detailButton.setMaximumSize(new Dimension(_minButtonWidth, _minButtonHeight));
                _detailButton.setPreferredSize(new Dimension(_minButtonWidth, _minButtonHeight));
            
                c.insets = new Insets(0,0,0,0);
                c.weighty = 1;
                c.anchor = GridBagConstraints.SOUTH;
                gridBag.setConstraints(_detailButton,c);
                _buttonPanel.add(_detailButton);
            } 
            else
            {
                _cancelNoButton.setMinimumSize(new Dimension(_minButtonWidth, _minButtonHeight));
                _cancelNoButton.setMaximumSize(new Dimension(_minButtonWidth, _minButtonHeight));
                _cancelNoButton.setPreferredSize(new Dimension(_minButtonWidth, _minButtonHeight));
            
                gridBag.setConstraints(_cancelNoButton, c);
                _buttonPanel.add(_cancelNoButton);
            
        
                _detailButton.setMinimumSize(new Dimension(_minButtonWidth, _minButtonHeight));
                _detailButton.setMaximumSize(new Dimension(_minButtonWidth, _minButtonHeight));
                _detailButton.setPreferredSize(new Dimension(_minButtonWidth, _minButtonHeight));
            
                c.insets = new Insets(0,0,0,0);
                c.gridy = 2;
                c.weighty = 1;
                c.anchor = GridBagConstraints.SOUTH;
                gridBag.setConstraints(_detailButton,c);
                _buttonPanel.add(_detailButton);
            }
        }
        return _buttonPanel;
    }
    
    /**
     *
     * Checks if the size of a button is bigger than the default button size
     *
     * @param button a button that needs to be set
     */
    private void setMinimumButtonSize(JButton button)
    {
        Dimension size = button.getPreferredSize();
        if (size.width > _minButtonWidth) {
            _minButtonWidth = size.width;
        }            
        if (size.height > _minButtonHeight)
            _minButtonHeight = size.height;
    }        
    
    /**
     * Hides and shows the detail label when the Detail button is clicked
     */
    private void adjustDetail()
    {
        
        if (_detailShown)
        {
            hideDetail();
            _detailButton.setToolTipText(i18n("details_show_tt"));
        }
        else 
        {
            showDetail();
            _detailButton.setToolTipText(i18n("details_hide_tt"));
        }
    }
    
    /**
     * Hides the detail panel the "Details <<" button is clicked
     */
    public void hideDetail()
    {
        _detailShown = false;
        StringTokenizer tokens = new StringTokenizer(_detailButton.getText(),"<<");
		String label = tokens.nextToken();
        _detailButton.setText(label + ">>");
        _scrollPane.setBorder(new EmptyBorder(0,0,0,0));
        _scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER); 
        _detailLabel.setVisible(false);
        setSize(lastWidth,_minHeight);
        validate();
    }
    
    /**
     * Shows the detail panel when the "Details >>" button is clicked
     */
    public void showDetail()
    {
        _detailShown = true;
		StringTokenizer tokens = new StringTokenizer(_detailButton.getText(),">>");
		String label = tokens.nextToken();
        _detailButton.setText(label + "<<");
        _detailLabel.setVisible(true);
        _scrollPane.setBorder(new BevelBorder(BevelBorder.LOWERED));
        _scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
          
        setSize(getPreferredSize().width, getPreferredSize().height);
        validate();
    }
    /**
     * Sets the minimum values for the height and the width
     *
     * @param width the new minimum width value
     * @param height the new minimum height value
     */
    public void setMinimumSize(int width, int height)
    {
        _minHeight = height;
        _minWidth = width;       
    }            
    
    /**
      * Sets initial default button (button pressed on enter).
     *
     * @param button OK or CANCEL or CLOSE or HELP
      */
    public void setDefaultButton(int button) {

        if (button == OK || button == YES || button == DEFAULT) {
            setDefaultButton(_okYesButton);
            _focusComponent = _okYesButton;
        } else if (button == CANCEL || button == NO) {
            setDefaultButton(_cancelNoButton);
            _focusComponent = _cancelNoButton;
        }
    }
    
    /**
     *
     * Sets the default button to the specified button
     *
     * @param button the button to be set as default
     */
    public void setDefaultButton(JButton button) 
    {
        getRootPane().setDefaultButton(button);
    }
    
    /**
     * Gets the button that was clicked last
     *
     * @return buttonClicked the int value of the button that was last clicked
     */
    public int getButtonClicked()
    {
        return buttonClicked;
    }
    
    /**
     * Sets the icon of the ErrorDialog to the specifed icon
     *
     * @param icon the icon to be displayed in the ErrorDialog
     */
    public void setIcon(String icon)
    {
        _iconLabel.setIcon(UIManager.getIcon(icon));
    }
    
    /**
    * fixes bug nonresizable size bug on UNIX
    * see http://developer.javasoft.com/developer/bugParade/bugs/4041679.html
    */
    public void pack()
    {
        // http://developer.javasoft.com/developer/bugParade/bugs/4041679.html
        // Setting dialog nonresizable before pack causes a ridiculous dialog size on UNIX
        boolean old = isResizable();
        setResizable(true);
        super.pack();
        setResizable(old);
    }
    
    /**
      * disposes resources used by this dialog.  Automatically called
      * on hide() or setVisible(false);
      */
    public void dispose() {
        if (!_isWinNT || _windowCloseButtonInvoked) {
            dispose_();
        } else {
            //335493: A workaround for the AWT Container.LightweightDispatcher memory leak bug.
            _windowCloseButtonInvoked = false;
            Debug.println(4, "AbstractDialog: post MOUSE_EXITED event as a workaround for AWT mem leak");
            MouseEvent e = new MouseEvent(this, MouseEvent.MOUSE_EXITED, 0,
                    0, 0, 0, 0, false);
            try {
                Toolkit.getDefaultToolkit().getSystemEventQueue().
                        postEvent(e);
                SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                ErrorDialog.this.dispose_();
                            }
                        }
                        );
            } catch (Exception ex) {
                Debug.println(1,
                       "AbstractDialog: can not post MOUSE_EXITED event " +
                        ex);
                dispose_();
            }
        }
    }

    private void dispose_() {
        // Work around to prevent disposing of modal dialogs on Solaris
        // which causes a segv.
        if ((_isIrix || _isSolaris) && isModal()) {
            super.setVisible(false);
        } else {
            if (_parentWindow != null) {
                super.dispose();
            }
        }
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

    /**
     * Listens when the Detail button is clicked
     */
    class DetailButtonActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            ErrorDialog.this.adjustDetail();
            ErrorDialog.this.buttonClicked = DETAIL;
        }
    }
    
    /**
     * Listens when the OK button is clicked
     */
    class OKButtonActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent ae)
        {
            if (ErrorDialog.this.buttonOption == OK_CANCEL | ErrorDialog.this.buttonOption == DEFAULT)
            {
                ErrorDialog.this.buttonClicked = OK;
            }
            else
            {
                ErrorDialog.this.buttonClicked = YES;
            }
            ErrorDialog.this.setVisible(false);
        }
    }
    
    class CancelButtonActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent ae)
        {
            if (ErrorDialog.this.buttonOption == OK_CANCEL)
            {
                ErrorDialog.this.buttonClicked = CANCEL;
            }
            else
            {
                ErrorDialog.this.buttonClicked = NO;
            }
           
            ErrorDialog.this.setVisible(false);
        }
    }
    /**
     *
     * This class automatically resizes the ErrorDialog to its default minimum 
     * size when the ErrorDialog is sized smaller than its default minimum size.
     */
    class ResizeComponentListener implements ComponentListener 
    {
        public void componentResized(ComponentEvent e) 
        {
            boolean resizeWidth;
            boolean resizeHeight;
                    
            if (_detailShown) 
            {
                resizeHeight = (getSize().height < _minHeightDetail);
                resizeWidth = (getSize().width < _minWidth);   
                lastHeight = resizeHeight ? _minWidth : getPreferredSize().height;
                lastWidth = resizeWidth ? _minHeightDetail : getSize().width;
            }
            else 
            {
                resizeHeight = (getSize().height != _minHeight);
                resizeWidth = (getSize().width < _minWidth);   
            }
                
            if (resizeWidth || resizeHeight) 
            {
                if (_detailShown)
                {
                    setSize(resizeWidth ? _minWidth : getSize().width,
                    resizeHeight ? _minHeightDetail : getSize().height);
                }
                else 
                {
                    setSize(resizeWidth ? _minWidth : getSize().width,
                    resizeHeight ? _minHeight : getSize().height);
                }
                
            }
        }
        
        /**
        * Do nothing
        */
        public void componentMoved(ComponentEvent e) 
        {}
        
        /**
        * Do nothing
        */
        public void componentShown(ComponentEvent e) 
        {}

        /**
        * Do nothing
        */
        public void componentHidden(ComponentEvent e) 
        {}
    }
    
    /**
      * Inner class used to handle window events.
      */
    class DialogWindowListener extends WindowAdapter {

        public void windowOpened(WindowEvent e) {
            if (_focusComponent != null)
                _focusComponent.requestFocus();
        }
    }
}
       
