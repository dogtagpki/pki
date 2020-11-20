//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme;

import org.apache.commons.lang3.time.FastDateFormat;

/**
 * @author Endi S. Dewata
 * @author Alexander M. Scheel
 */
public class ACME {
    // e.g. 2020-01-01T00:00:00.00-00:00
    public final static FastDateFormat DATE_FORMAT = FastDateFormat.getInstance("yyyy-MM-dd'T'HH:mm:ssXXX");
}
