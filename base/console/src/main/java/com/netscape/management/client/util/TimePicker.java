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

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.Calendar;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.Border;

import com.netscape.management.nmclf.SuiConstants;

/**
 * A panel that displays the time (hour, minute, second)
 * and allows it to be changed.
 */
class TimePicker extends JPanel implements SuiConstants {
    TimeField hourField;
    TimeField minuteField;
    TimeField secondField;
    AmPmTimeField ampmField;
    TimeField activeField;

    Calendar calendar;
    Border emptyBorder = BorderFactory.createEmptyBorder(1, 6, 1, 6);

    static private final ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");

    /**
     * @return Calendar object representing currently selected time
     */
    public Calendar getCalendar() {
        return calendar;
    }

    /**
      * @return hour in range of 1 to 12
      * @see isAM()
      */
    public int getHour() {
        return calendar.get(Calendar.HOUR);
    }

    /**
      * @return hour in range of 0 to 23
      */
    public int getHourOfDay() {
        return calendar.get(Calendar.HOUR_OF_DAY);
    }

    /**
      * @return minute in range of 0 to 59
      */
    public int getMinute() {
        return calendar.get(Calendar.MINUTE);
    }

    /**
      * @return second in range of 0 to 59
      */
    public int getSecond() {
        return calendar.get(Calendar.SECOND);
    }

    /**
      * @return true if AM, false if PM
      */
    public boolean isAM() {
        return calendar.get(Calendar.AM_PM) == Calendar.AM;
    }

    /**
      * Contructs TimePicker using specified Calendar
      * @param calendar specifies initial time
      */
    public TimePicker(Calendar calendar) {
        this.calendar = calendar;
        setLayout(new GridBagLayout());

        JPanel timePanel = new JPanel();
        timePanel.setLayout(new GridBagLayout());
        timePanel.setBackground(Color.white);
        timePanel.setOpaque(true);
        timePanel.setBorder( BorderFactory.createCompoundBorder(
                UITools.createLoweredBorder(),
                BorderFactory.createEmptyBorder(1, 3, 1, 3)));

        hourField = new HourTimeField();
        hourField.getAccessibleContext().setAccessibleDescription(_resource.getString("TimePicker","hours"));
        hourField.setHorizontalAlignment(JTextField.RIGHT);
        activeField = hourField;

        minuteField = new TimeField(Calendar.MINUTE);
        minuteField.getAccessibleContext().setAccessibleDescription(_resource.getString("TimePicker","minutes"));
        minuteField.setHorizontalAlignment(JTextField.CENTER);

        secondField = new TimeField(Calendar.SECOND);
        secondField.getAccessibleContext().setAccessibleDescription(_resource.getString("TimePicker","seconds"));

        ampmField = new AmPmTimeField();
        ampmField.getAccessibleContext().setAccessibleDescription(_resource.getString("TimePicker","ampm"));

        GridBagUtil.constrain(timePanel, hourField, 0, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        JLabel colon = new JLabel(":");
        colon.setBorder(BorderFactory.createEmptyBorder(0, 0, 2, 3));
        GridBagUtil.constrain(timePanel, colon, 1, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.VERTICAL, 0, 0, 0, 0);
        GridBagUtil.constrain(timePanel, minuteField, 2, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        colon = new JLabel(":");
        colon.setBorder(BorderFactory.createEmptyBorder(0, 0, 2, 3));

        GridBagUtil.constrain(timePanel, colon, 3, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.VERTICAL, 0, 0, 0, 0);

        GridBagUtil.constrain(timePanel, secondField, 4, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(timePanel, ampmField, 5, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(this, timePanel, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                0, 0, 0, 0);

        SpinControl spinner = new SpinControl(timePanel);
        spinner.setToolTipText(_resource.getString("TimePicker","time_tt"));
        spinner.addSpinListener(new TimeSpinListener());
        GridBagUtil.constrain(this, spinner, 1, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                0, 0, 0, 0);

        GridBagUtil.constrain(this, new JLabel(), 2, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                0, 0, 0, 0);

        updateFields();
    }

    private int getIntFromString(String text) {
        Integer integer = Integer.valueOf(text);
        return integer.intValue();
    }

    private void updateFields() {
        int hour = calendar.get(Calendar.HOUR);
        if (hour == 0)
            hour = 12;
        hourField.setText(String.valueOf(hour));
        minuteField.setText(
                getZeroPrefixedString(calendar.get(Calendar.MINUTE)));
        secondField.setText(
                getZeroPrefixedString(calendar.get(Calendar.SECOND)));
        ampmField.setAmPm(calendar.get(Calendar.AM_PM));
    }

    private String getZeroPrefixedString(int number) {
        String text = String.valueOf(number);
        if (number < 10)
            text = "0" + text;
        return text;
    }

    class TimeField extends JTextField implements FocusListener {
        int fieldID;
        public TimeField(int calendarFieldID) {
            super(2);
            fieldID = calendarFieldID;
            setBackground(Color.white);
            setForeground(Color.black);
            setBorder(BorderFactory.createEmptyBorder());
            setOpaque(true);
            addFocusListener(this);
        }

        public int getCalendarFieldID() {
            return fieldID;
        }

        public void focusGained(FocusEvent event) {
            activeField = (TimeField) event.getSource();
        }

        public void focusLost(FocusEvent event) {
            String text = getText();
            if (text != null && text.length() > 0)
                calendar.set(getCalendarFieldID(),
                        getIntFromString(getText()));
            updateFields();
        }
    }

    class AmPmTimeField extends TimeField {
        public AmPmTimeField() {
            super(Calendar.AM_PM);
        }

        public void setAmPm(int ampmState) {
            if (ampmState == Calendar.AM)
                setText("AM");
            else
                setText("PM");
        }

        public void focusLost(FocusEvent event) {
            String text = getText();
            if (text != null && text.length() > 0) {
                int hourOffset = 0;
                if (text.equalsIgnoreCase("pm")) {
                    if (calendar.get(Calendar.HOUR_OF_DAY) < 12)
                        hourOffset = 12;
                } else {
                    if (calendar.get(Calendar.HOUR_OF_DAY) >= 12)
                        hourOffset = -12;
                }
                calendar.add(Calendar.HOUR_OF_DAY, hourOffset);
            }
            updateFields();
        }
    }

    class HourTimeField extends TimeField {
        public HourTimeField() {
            super(Calendar.HOUR_OF_DAY);
        }

        public void setText(String text) {
            if (text.equals("0"))
                super.setText("12");
            else
                super.setText(text);
        }

        public void focusLost(FocusEvent event) {
            String text = getText();
            if (text != null && text.length() > 0) {
                if (text.equals("12") && isAM())
                    text = "0";
                calendar.set(getCalendarFieldID(), getIntFromString(text));
            }
            updateFields();
        }
    }

    class TimeSpinListener implements ISpinListener {
        public void actionUp(SpinEvent e) {
            int field = activeField.getCalendarFieldID();
            if (field == Calendar.AM_PM) {
				for(int i=0; i < 12; i++) // calendar.roll(Calendar.Calendar.AM_PM, true) does not work
					calendar.roll(Calendar.HOUR_OF_DAY, true);
            } else {
                calendar.roll(activeField.getCalendarFieldID(), true);
            }
            updateFields();
        }

        public void actionDown(SpinEvent e) {
            int field = activeField.getCalendarFieldID();
            if (field == Calendar.AM_PM) {
				for(int i=0; i < 12; i++) // calendar.roll(Calendar.Calendar.AM_PM, false) does not work
					calendar.roll(Calendar.HOUR_OF_DAY, false);
            } else {
                calendar.roll(activeField.getCalendarFieldID(), false);
            }
            updateFields();
        }
    }
}
