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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.tomcat;

import java.io.File;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Host;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.Server;
import org.apache.catalina.Service;
import org.apache.commons.lang.StringUtils;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class PKIListener implements LifecycleListener {

    final static Logger logger = LoggerFactory.getLogger(PKIListener.class);

    @Override
    public void lifecycleEvent(LifecycleEvent event) {

        String type = event.getType();
        logger.info("PKIListener: " + event.getLifecycle().getClass().getName() + " [" + type + "]");

        if (type.equals(Lifecycle.BEFORE_INIT_EVENT)) {

            String wdPipeName = System.getenv("WD_PIPE_NAME");
            if (StringUtils.isNotEmpty(wdPipeName)) {
                logger.info("PKIListener: Initializing the watchdog");
            }

            logger.info("PKIListener: Initializing TomcatJSS");

            try {
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                DocumentBuilder builder = factory.newDocumentBuilder();

                String catalinaBase = System.getProperty("catalina.base");
                File file = new File(catalinaBase + "/conf/server.xml");
                Document doc = builder.parse(file);

                XPathFactory xPathfactory = XPathFactory.newInstance();
                XPath xpath = xPathfactory.newXPath();

                Element connector = (Element)xpath.evaluate(
                        "/Server/Service[@name='Catalina']/Connector[@name='Secure']",
                        doc, XPathConstants.NODE);

                TomcatJSS tomcatjss = TomcatJSS.getInstance();

                String certDb = connector.getAttribute("certdbDir");
                if (certDb != null) tomcatjss.setCertdbDir(certDb);

                String passwordClass = connector.getAttribute("passwordClass");
                if (passwordClass != null) tomcatjss.setPasswordClass(passwordClass);

                String passwordFile = connector.getAttribute("passwordFile");
                if (passwordFile != null) tomcatjss.setPasswordFile(passwordFile);

                String serverCertNickFile = connector.getAttribute("serverCertNickFile");
                if (serverCertNickFile != null) tomcatjss.setServerCertNickFile(serverCertNickFile);

                String enableOCSP = connector.getAttribute("enableOCSP");
                if (enableOCSP != null) tomcatjss.setEnableOCSP(Boolean.parseBoolean(enableOCSP));

                String ocspResponderURL = connector.getAttribute("ocspResponderURL");
                if (ocspResponderURL != null) tomcatjss.setOcspResponderURL(ocspResponderURL);

                String ocspResponderCertNickname = connector.getAttribute("ocspResponderCertNickname");
                if (ocspResponderCertNickname != null) tomcatjss.setOcspResponderCertNickname(ocspResponderCertNickname);

                String ocspCacheSize = connector.getAttribute("ocspCacheSize");
                if (ocspCacheSize != null) tomcatjss.setOcspCacheSize(Integer.parseInt(ocspCacheSize));

                String ocspMinCacheEntryDuration = connector.getAttribute("ocspMinCacheEntryDuration");
                if (ocspMinCacheEntryDuration != null) tomcatjss.setOcspMinCacheEntryDuration(Integer.parseInt(ocspMinCacheEntryDuration));

                String ocspMaxCacheEntryDuration = connector.getAttribute("ocspMaxCacheEntryDuration");
                if (ocspMaxCacheEntryDuration != null) tomcatjss.setOcspMaxCacheEntryDuration(Integer.parseInt(ocspMaxCacheEntryDuration));

                String ocspTimeout = connector.getAttribute("ocspTimeout");
                if (ocspTimeout != null) tomcatjss.setOcspTimeout(Integer.parseInt(ocspTimeout));

                String strictCiphers = connector.getAttribute("strictCiphers");
                if (strictCiphers != null) tomcatjss.setStrictCiphers(strictCiphers);

                String sslVersionRangeStream = connector.getAttribute("sslVersionRangeStream");
                if (sslVersionRangeStream != null) tomcatjss.setSslVersionRangeStream(sslVersionRangeStream);

                String sslVersionRangeDatagram = connector.getAttribute("sslVersionRangeDatagram");
                if (sslVersionRangeDatagram != null) tomcatjss.setSslVersionRangeDatagram(sslVersionRangeDatagram);

                String sslRangeCiphers = connector.getAttribute("sslRangeCiphers");
                if (sslRangeCiphers != null) tomcatjss.setSslRangeCiphers(sslRangeCiphers);

                String sslOptions = connector.getAttribute("sslOptions");
                if (sslOptions != null) tomcatjss.setSslOptions(sslOptions);

                String ssl2Ciphers = connector.getAttribute("ssl2Ciphers");
                if (ssl2Ciphers != null) tomcatjss.setSsl2Ciphers(ssl2Ciphers);

                String ssl3Ciphers = connector.getAttribute("ssl3Ciphers");
                if (ssl3Ciphers != null) tomcatjss.setSsl3Ciphers(ssl3Ciphers);

                String tlsCiphers = connector.getAttribute("tlsCiphers");
                if (tlsCiphers != null) tomcatjss.setTlsCiphers(tlsCiphers);

                tomcatjss.init();

            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        } else if (type.equals(Lifecycle.AFTER_START_EVENT)) {

            verifySubsystems((Server)event.getLifecycle());
        }
    }

    public void verifySubsystems(Server server) {

        Service service = server.findService("Catalina");
        Engine engine = (Engine)service.getContainer();
        String defaultHost = engine.getDefaultHost();
        Host host = (Host)engine.findChild(defaultHost);

        File instanceDir = new File(System.getProperty("catalina.base"));
        String instanceName = instanceDir.getName();

        for (File file : instanceDir.listFiles()) {

            if (!file.isDirectory()) continue;

            File csCfg = new File(file, "conf" + File.separator + "CS.cfg");
            if (!csCfg.exists()) continue;

            String subsystemName = file.getName();

            File contextXml = new File(
                    instanceDir,
                    "conf" + File.separator + "Catalina" + File.separator +
                    defaultHost + File.separator + subsystemName + ".xml");

            if (!contextXml.exists()) {

                logger.warn("PKIListener: Subsystem " + subsystemName.toUpperCase() + " is disabled.");

                String selftestsLog = "/var/log/pki/" + instanceName + "/" + subsystemName + "/selftests.log";
                logger.warn("PKIListener: Check " + selftestsLog + " for possible errors.");

                logger.warn("PKIListener: To enable the subsystem:");
                logger.warn("PKIListener:   pki-server subsystem-enable -i " + instanceName + " " + subsystemName);

                continue;
            }

            Context context = (Context)host.findChild("/" + subsystemName);

            if (context == null) {

                logger.warn("PKIListener: " + "Subsystem " + subsystemName.toUpperCase() + " is not deployed.");

                String catalinaLog = "/var/log/pki/" + instanceName + "/catalina.*.log";
                logger.warn("PKIListener: Check " + catalinaLog);
                logger.warn("PKIListener: and Tomcat's standard output and error for possible errors:");
                logger.warn("PKIListener:   journalctl -u pki-tomcatd@" + instanceName + ".service");

                continue;
            }

            logger.info("PKIListener: Subsystem " + subsystemName.toUpperCase() + " is running.");
        }
    }
}
