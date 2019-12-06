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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.kra;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.kra.KRAClient;

/**
 * @author Endi S. Dewata
 */
public class KRACertCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRACertCLI.class);

    public KRACLI kraCLI;
    public KRAClient kraClient;

    public KRACertCLI(KRACLI kraCLI) {
        super("cert", "KRA certificate management commands", kraCLI);
        this.kraCLI = kraCLI;

        addModule(new KRACertTransportExportCLI(this));
        addModule(new KRACertTransportShowCLI(this));
    }
}
