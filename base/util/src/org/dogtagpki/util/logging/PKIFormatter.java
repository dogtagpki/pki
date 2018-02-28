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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.util.logging;

import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;

public class PKIFormatter extends Formatter {

    public String format(LogRecord record) {

        // 2018-02-23 10:18:51 [main] INFO: Log message

        return String.format(
                "%1$tF %1$tT [%2$s] %3$s: %4$s%n",
                new Date(record.getMillis()),
                Thread.currentThread().getName(),
                record.getLevel(),
                formatMessage(record));
    }

    public static void main(String[] args) {

        PKIFormatter formatter = new PKIFormatter();

        LogRecord record = new LogRecord(Level.INFO, "Log message");
        record.setSourceClassName(PKIFormatter.class.getName());

        System.out.println(formatter.format(record));
    }
}
