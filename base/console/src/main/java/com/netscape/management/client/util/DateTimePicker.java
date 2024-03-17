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

import java.awt.*;
import java.util.*;
import java.awt.event.*;
import java.text.*;
import javax.swing.*;
import com.netscape.management.nmclf.*;

/**
 * A dialog that allows selection of Date and Time.
 * The following code invokes the DateTimePicker
 * and prints the selected date and time upon pressing OK.
 * <code>
 *		DateTimePicker dtp = new DateTimePicker();
 *		dtp.show()
 *		if(!dtp.isCancel())
 *		{
 *			System.out.println(dtp);
 *		}
 * </code>
 */
public class DateTimePicker extends AbstractDialog {
    Calendar calendar;
    DatePicker datePicker;
    TimePicker timePicker;

    public static void main(String argv[]) {
        try {
            SuiLookAndFeel nmclf = new SuiLookAndFeel();
            UIManager.setLookAndFeel(nmclf);
        } catch (Exception e) {
        }

        JFrame frame = new JFrame();
        frame.addWindowListener (new WindowAdapter() {
                    public void windowClosing(WindowEvent e) {
                        System.exit(0);
                    }
                }
                );
        frame.pack();

        DateTimePicker dtp = new DateTimePicker(frame);
        dtp.show();
        System.out.println(dtp);
        System.exit(0);
    }

    /**
      * Called when dialog is dismissed by pressing OK
      */
    public void okInvoked() {
        super.okInvoked();
    }

    /**
      * Called when dialog is dismissed by pressing Cancel
      */
    public void cancelInvoked() {
        super.cancelInvoked();
    }

    /**
      * Constructs DateTimePicker
      * @param frame parent Frame
      * @param calendar initial date and time
      */
    public DateTimePicker(Frame frame, Calendar calendar) {
        super(frame, "Date - Time", true, OK | CANCEL /* | HELP*/,
                VERTICAL_BUTTONS); // TODO: i18n
                this.calendar = calendar;
        setComponent(createDialogPanel());
        setMinimumSize(getPreferredSize());
        setResizable(false);
    }

    /**
      * Constructs DateTimePicker initialized with current system date and time
      * @param frame parent Frame
      */
    public DateTimePicker(Frame frame) {
        this(frame, new GregorianCalendar());
    }

    /**
      * @return Calendar object with selected date and time
      */
    public Calendar getCalendar() {
        return calendar;
    }

    /**
      * @return hour in range of 1 to 12
      * @see isAM()
      */
    public int getHour() {
        return timePicker.getHour();
    }

    /**
      * @return hour in range of 0 to 23
      */
    public int getHourOfDay() {
        return timePicker.getHourOfDay();
    }

    /**
      * @return integer minute in range of 0 to 59
      */
    public int getMinute() {
        return timePicker.getMinute();
    }

    /**
      * @return integer second in range of 0 to 59
      */
    public int getSecond() {
        return timePicker.getSecond();
    }

    /**
      * @return true if AM, false if PM
      */
    public boolean isAM() {
        return timePicker.isAM();
    }

    /**
      * @return integer year
      */
    public int getYear() {
        return datePicker.getYear();
    }

    /**
      * @return integer month in range of 0 to 11
      */
    public int getMonth() {
        return datePicker.getMonth();
    }

    /**
      * @return integer day in range of 1 to 31
      */
    public int getDay() {
        return datePicker.getDay();
    }

    /**
      * @return formatted string representing selected Date and Time in system locale
      */
    public String toString() {
        return DateFormat.getDateTimeInstance().format(
                getCalendar().getTime());
    }

    /**
      * @return panel with date and time picker widgets.  usefull for embedding in another widget
      */
    public JPanel createDialogPanel() {
        JPanel panel = new JPanel();
        GridBagLayout gridbag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        panel.setLayout(gridbag);

        datePicker = new DatePicker(calendar);
        GridBagUtil.constrain(panel, datePicker, 0, 1, 3, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                0, 0, 0, 0);

        timePicker = new TimePicker(calendar);
        GridBagUtil.constrain(panel, timePicker, 0, 2, 3, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                COMPONENT_SPACE, 0, 0, 0);

        return panel;
    }
}
