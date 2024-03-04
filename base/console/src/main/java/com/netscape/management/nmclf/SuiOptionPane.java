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
package com.netscape.management.nmclf;

import java.awt.Component;

import javax.swing.Icon;
import javax.swing.JDialog;
import javax.swing.JOptionPane;

/**
 * This is an extension of JOptionPane to fix various bugs in it.
 * Since this class was written newer versions of JFC or JDK
 * have fixed these problems.  Therefore, this class is
 * no longer necessary.
 *
 * @deprecated use JOptionPane instead
 */
@Deprecated
public class SuiOptionPane extends JOptionPane {
    public SuiOptionPane(Object message, int messageType,
            int optionType, Icon icon, Object[] options,
            Object initialValue) {
        super(message, messageType, optionType, icon, options,
                initialValue);
    }

    public static int showOptionDialog(Component parentComponent,
            Object message, String title, int optionType,
            int messageType, Icon icon, Object[] options,
            Object initialValue) {
        JOptionPane pane =
                new SuiOptionPane(message, messageType, optionType,
                icon, options, initialValue);

        pane.setInitialValue(initialValue);

        JDialog dialog = pane.createDialog(parentComponent, title);

        pane.selectInitialValue();
        dialog.show();

        Object selectedValue = pane.getValue();

        if (selectedValue == null)
            return CLOSED_OPTION;
        if (options == null) {
            if (selectedValue instanceof Integer)
                return ((Integer) selectedValue).intValue();
            return CLOSED_OPTION;
        }
        for (int counter = 0, maxCounter = options.length;
                counter < maxCounter; counter++) {
            if (options[counter].equals(selectedValue))
                return counter;
        }
        return CLOSED_OPTION;
    }

    /**
      * Prompts the user for input in a blocking dialog where the
      * initial selection, possible selections, and all other options can
      * be specified. The user will able to choose from
      * <code>selectionValues</code>, where null implies the user can input
      * whatever they wish, usually by means of a JTextField.
      * <code>initialSelectionValue</code> is the initial value to prompt
      * the user with. It is up to the UI to decide how best to represent
      * the <code>selectionValues</code>, but usually a JComboBox, JList, or
      * JTextField will be used.
      *
      * @param parentComponent  the parent Component for the dialog
      * @param message  the Object to display
      * @param title    the String to display in the dialog title bar
      * @param messageType the type of message to be displayed:
      *                    ERROR_MESSAGE, INFORMATION_MESSAGE, WARNING_MESSAGE,
      *                    QUESTION_MESSAGE, or PLAIN_MESSAGE.
      * @param icon     the Icon image to display
      * @param selectionValues an array of Objects that gives the possible
      *                        selections
      * @param initialSelectionValue the value used to initialize the input
      *                              field
      * @return users input, or null meaning the user canceled the input
      */
    public static Object showInputDialog(Component parentComponent,
            Object message, String title, int messageType, Icon icon,
            Object[] selectionValues, Object initialSelectionValue) {
        SuiOptionPane pane = new SuiOptionPane(message, messageType,
                OK_CANCEL_OPTION, icon, null, null);

        pane.setWantsInput(true);
        pane.setSelectionValues(selectionValues);
        pane.setInitialSelectionValue(initialSelectionValue);

        JDialog dialog = pane.createDialog(parentComponent, title);
        dialog.setTitle(title);

        pane.selectInitialValue();
        dialog.show();

        Object value = pane.getInputValue();

        if (value == UNINITIALIZED_VALUE)
            return null;
        return value;
    }

    /**
      * Brings up a confirmation dialog -- a modal information-message dialog
      * titled "Confirm".
      *
      * @param parentComponent Determines the Frame in which the dialog is displayed.
      *                  If null, or if the parentComponent has no Frame, a
      *                  default Frame is used.
      * @param message   The Object to display
      */
    public static void showMessageDialog(Component parentComponent,
            Object message) {
        showMessageDialog(parentComponent, message, "Message",
                INFORMATION_MESSAGE);
    }

    /**
      * Brings up a dialog that displays a message using a default
      * icon determined by the messageType parameter.
      *
      * @param parentComponent Determines the Frame in which the dialog is displayed.
      *                  If null, or if the parentComponent has no Frame, a
      *                  default Frame is used.
      * @param message   The Object to display
      * @param title     the title string for the dialog
      * @param messageType the type of message to be displayed:
      *                    ERROR_MESSAGE, INFORMATION_MESSAGE, WARNING_MESSAGE,
      *                    QUESTION_MESSAGE, or PLAIN_MESSAGE.
      */
    public static void showMessageDialog(Component parentComponent,
            Object message, String title, int messageType) {
        showMessageDialog(parentComponent, message, title, messageType,
                null);
    }

    /**
      * Brings up a dialog displaying a message, specifying all parameters.
      *
      * @param parentComponent Determines the Frame in which the dialog is displayed.
      *                  If null, or if the parentComponent has no Frame, a
      *                  default Frame is used.
      * @param message   The Object to display
      * @param title     the title string for the dialog
      * @param messageType the type of message to be displayed:
      *                    ERROR_MESSAGE, INFORMATION_MESSAGE, WARNING_MESSAGE,
      *                    QUESTION_MESSAGE, or PLAIN_MESSAGE.
      * @param icon      an icon to display in the dialog that helps the user
      *                  identify the kind of message that is being displayed.
      */
    public static void showMessageDialog(Component parentComponent,
            Object message, String title, int messageType, Icon icon) {
        showOptionDialog(parentComponent, message, title,
                DEFAULT_OPTION, messageType, icon, null, null);
    }

    /**
      * Brings up a modal dialog with the options Yes, No and Cancel; with the
      * title, "Select an Option".
      *
      * @param parentComponent Determines the Frame in which the dialog is displayed.
      *                  If null, or if the parentComponent has no Frame, a
      *                  default Frame is used.
      * @param message   The Object to display
      * @return an int indicating the option selected by the user
      */
    public static int showConfirmDialog(Component parentComponent,
            Object message) {
        return showConfirmDialog(parentComponent, message, "Select an Option",
                YES_NO_CANCEL_OPTION);
    }

    /**
      * Brings up a modal dialog where the number of choices is determined
      * by the <code>optionType</code> parameter.
      *
      * @param parentComponent Determines the Frame in which the dialog is displayed.
      *                  If null, or if the parentComponent has no Frame, a
      *                  default Frame is used.
      * @param message   The Object to display
      * @param title     the title string for the dialog
      * @param optionType an int designating the options available on the dialog:
      *                   YES_NO_OPTION, or YES_NO_CANCEL_OPTION
      * @return an int indicating the option selected by the user
      */
    public static int showConfirmDialog(Component parentComponent,
            Object message, String title, int optionType) {
        return showConfirmDialog(parentComponent, message, title,
                optionType, QUESTION_MESSAGE);
    }

    /**
      * Brings up a modal dialog where the number of choices is determined
      * by the <code>optionType</code> parameter, where the <code>messageType</code>
      * parameter determines the icon to display.
      * The <code>messageType</code> parameter is primarily used to supply
      * a default icon from the look and feel.
      *
      * @param parentComponent Determines the Frame in which the dialog is displayed.
      *                  If null, or if the parentComponent has no Frame, a
      *                  default Frame is used.
      * @param message   The Object to display
      * @param title     the title string for the dialog
      * @param optionType an int designating the options available on the dialog:
      *                   YES_NO_OPTION, or YES_NO_CANCEL_OPTION
      * @param messageType an int designating the kind of message this is,
      *                    primarily used to determine the icon from the pluggable
      *                    look and feel: ERROR_MESSAGE, INFORMATION_MESSAGE,
      *                    WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE.
      * @return an int indicating the option selected by the user
      */
    public static int showConfirmDialog(Component parentComponent,
            Object message, String title, int optionType, int messageType) {
        return showConfirmDialog(parentComponent, message, title,
                optionType, messageType, null);
    }

    /**
      * Brings up a modal dialog with a specified icon, where the number of
      * choices is determined by the <code>optionType</code> parameter.
      * The <code>messageType</code> parameter is primarily used to supply
      * a default icon from the look and feel.
      *
      * @param parentComponent Determines the Frame in which the dialog is displayed.
      *                  If null, or if the parentComponent has no Frame, a
      *                  default Frame is used.
      * @param message   The Object to display
      * @param title     the title string for the dialog
      * @param optionType an int designating the options available on the dialog:
      *                   YES_NO_OPTION, or YES_NO_CANCEL_OPTION
      * @param messageType an int designating the kind of message this is,
      *                    primarily used to determine the icon from the pluggable
      *                    look and feel: ERROR_MESSAGE, INFORMATION_MESSAGE,
      *                    WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE.
      * @param icon      the icon to display in the dialog
      * @return an int indicating the option selected by the user
      */
    public static int showConfirmDialog(Component parentComponent,
            Object message, String title, int optionType,
            int messageType, Icon icon) {
        return showOptionDialog(parentComponent, message, title,
                optionType, messageType, icon, null, null);
    }

}
