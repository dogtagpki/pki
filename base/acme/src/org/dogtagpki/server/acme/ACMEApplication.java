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
package org.dogtagpki.server.acme;

import java.io.File;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;

@ApplicationPath("")
public class ACMEApplication extends Application {

    ACMEConfiguration config;

    private Set<Class<?>> classes = new LinkedHashSet<Class<?>>();
    private Set<Object> singletons = new LinkedHashSet<Object>();

    public ACMEApplication() throws Exception {

        String catalinaBase = System.getProperty("catalina.base");
        String confDir = catalinaBase + File.separator + "conf";
        String acmeConfDir = confDir + File.separator + "acme";
        File acmeConfigFile = new File(acmeConfDir + File.separator + "ACME.conf");

        if (acmeConfigFile.exists()) {

            System.out.println("Loading " + acmeConfigFile);

            XmlMapper mapper = new XmlMapper();
            config = mapper.readValue(acmeConfigFile, ACMEConfiguration.class);

        } else {
            config = new ACMEConfiguration();
        }

        classes.add(ACMEDirectoryService.class);
        classes.add(ACMENewNonceService.class);
        classes.add(ACMENewAccountService.class);
        classes.add(ACMENewOrderService.class);
        classes.add(ACMEAuthorizationService.class);
        classes.add(ACMEChallengeService.class);
        classes.add(ACMEOrderService.class);

        ACMEFinalizeOrderService finalizeOrderService = new ACMEFinalizeOrderService();
        finalizeOrderService.setACMEConfig(config);
        singletons.add(finalizeOrderService);

        ACMECertificateService certificateService = new ACMECertificateService();
        certificateService.setACMEConfig(config);
        singletons.add(certificateService);
    }

    public Set<Class<?>> getClasses() {
        return classes;
    }

    public Set<Object> getSingletons() {
        return singletons;
    }
}
