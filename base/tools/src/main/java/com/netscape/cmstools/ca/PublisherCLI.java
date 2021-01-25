//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.ca;

import org.dogtagpki.cli.CLI;

public class PublisherCLI extends CLI {

    public CACLI caCLI;

    public PublisherCLI(CACLI caCLI) {
        super("publisher", "Publisher management commands", caCLI);
        this.caCLI = caCLI;

        addModule(new PublisherOCSPCLI(this));
    }
}
