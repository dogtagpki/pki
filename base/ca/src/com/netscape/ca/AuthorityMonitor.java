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
package com.netscape.ca;

import java.util.Arrays;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.cmsutil.ldap.LDAPUtil;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.controls.LDAPEntryChangeControl;
import netscape.ldap.controls.LDAPPersistSearchControl;
import netscape.ldap.util.DN;

public class AuthorityMonitor implements Runnable {

    public final static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthorityMonitor.class);

    private CertificateAuthority certificateAuthority;
    private boolean running = true;

    /**
     * @param certificateAuthority
     */
    AuthorityMonitor(CertificateAuthority certificateAuthority) {
        this.certificateAuthority = certificateAuthority;
    }

    public void run() {

        int op = LDAPPersistSearchControl.ADD
            | LDAPPersistSearchControl.MODIFY
            | LDAPPersistSearchControl.DELETE
            | LDAPPersistSearchControl.MODDN;

        LDAPPersistSearchControl persistCtrl =
            new LDAPPersistSearchControl(op, false, true, true);

        CAEngine engine = CAEngine.getInstance();
        String lwcaContainerDNString = engine.getAuthorityBaseDN();
        DN lwcaContainerDN = new DN(lwcaContainerDNString);

        logger.debug("AuthorityMonitor: starting.");

        while (running) {

            LDAPConnection conn = null;

            try {
                conn = CAEngine.connectionFactory.getConn();
                LDAPSearchConstraints cons = conn.getSearchConstraints();
                cons.setServerControls(persistCtrl);
                cons.setBatchSize(1);
                cons.setServerTimeLimit(0 /* seconds */);
                String[] attrs = {"*", "entryUSN", "nsUniqueId", "numSubordinates"};

                LDAPSearchResults results = conn.search(
                    lwcaContainerDNString, LDAPConnection.SCOPE_SUB,
                    "(objectclass=*)", attrs, false, cons);

                /* Wait until the last possible moment before taking
                 * the load lock so that we can continue to service
                 * requests while LDAP is down.
                 */
                CAEngine.loader.startLoading();

                while (running && results.hasMoreElements()) {

                    LDAPEntry entry = results.next();
                    DN entryDN = new DN(entry.getDN());

                    if (entryDN.countRDNs() == lwcaContainerDN.countRDNs()) {
                        /* This must be the base entry of the search, i.e. the
                         * LWCA container.  Read numSubordinates to get the
                         * expected number of LWCA entries to read.
                         *
                         * numSubordinates is not reliable; it may be too high
                         * due to objects we cannot see (e.g. replication
                         * conflict entries).  In that case AsyncLoader has a
                         * watchdog timer to interrupt waiting threads after it
                         * times out.
                         */
                        CAEngine.loader.setNumItems(new Integer(
                            entry.getAttribute("numSubordinates")
                                .getStringValueArray()[0]));
                        continue;
                    }

                    if (entryDN.countRDNs() > lwcaContainerDN.countRDNs() + 1) {
                        /* This entry is unexpectedly deep.  We ignore it.
                         * numSubordinates only counts immediate subordinates
                         * (https://tools.ietf.org/html/draft-boreham-numsubordinates-01)
                         * so don't increment() the AsyncLoader.
                         */
                        continue;
                    }

                    /* This entry is at the expected depth.  Is it a LWCA entry? */
                    String[] objectClasses =
                        entry.getAttribute("objectClass").getStringValueArray();

                    if (!Arrays.asList(objectClasses).contains("authority")) {
                        /* It is not a LWCA entry; ignore it.  But it does
                         * contribute to numSubordinates so increment the loader. */
                        CAEngine.loader.increment();
                        continue;
                    }

                    LDAPEntryChangeControl changeControl = (LDAPEntryChangeControl)
                        LDAPUtil.getControl(
                            LDAPEntryChangeControl.class, results.getResponseControls());

                    logger.debug("AuthorityMonitor: Processed change controls.");

                    if (changeControl != null) {

                        int changeType = changeControl.getChangeType();

                        switch (changeType) {
                        case LDAPPersistSearchControl.ADD:
                            logger.debug("AuthorityMonitor: ADD");
                            this.certificateAuthority.readAuthority(entry);
                            break;
                        case LDAPPersistSearchControl.DELETE:
                            logger.debug("AuthorityMonitor: DELETE");
                            handleDELETE(entry);
                            break;
                        case LDAPPersistSearchControl.MODIFY:
                            logger.debug("AuthorityMonitor: MODIFY");
                            // TODO how do we handle authorityID change?
                            this.certificateAuthority.readAuthority(entry);
                            break;
                        case LDAPPersistSearchControl.MODDN:
                            logger.debug("AuthorityMonitor: MODDN");
                            handleMODDN(new DN(changeControl.getPreviousDN()), entry);
                            break;
                        default:
                            logger.debug("AuthorityMonitor: unknown change type: " + changeType);
                            break;
                        }

                    } else {
                        logger.debug("AuthorityMonitor: immediate result");
                        this.certificateAuthority.readAuthority(entry);
                        CAEngine.loader.increment();
                    }
                }

            } catch (ELdapException e) {

                logger.warn("AuthorityMonitor: Failed to get LDAPConnection: " + e.getMessage(), e);
                logger.warn("AuthorityMonitor: Retrying in 1 second.");

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }

            } catch (LDAPException e) {

                if (running) {
                    logger.warn("AuthorityMonitor: Failed to execute LDAP search for lightweight CAs: " + e, e);
                } else {
                    logger.info("AuthorityMonitor: Shutting down: " + e.getMessage());
                }

            } catch (Exception e) {
                throw new RuntimeException(e);

            } finally {
                try {
                    CAEngine.connectionFactory.returnConn(conn);
                } catch (Exception e) {
                    logger.warn("AuthorityMonitor: Error releasing the LDAPConnection" + e.getMessage(), e);
                }
            }
        }

        logger.debug("AuthorityMonitor: stopping.");
    }

    private synchronized void handleMODDN(DN oldDN, LDAPEntry entry) throws Exception {

        CAEngine engine = CAEngine.getInstance();
        DN authorityBase = new DN(engine.getAuthorityBaseDN());

        boolean wasMonitored = oldDN.isDescendantOf(authorityBase);
        boolean isMonitored = (new DN(entry.getDN())).isDescendantOf(authorityBase);

        if (wasMonitored && !isMonitored) {
            LDAPAttribute attr = entry.getAttribute("authorityID");
            if (attr != null) {
                AuthorityID aid = new AuthorityID(attr.getStringValueArray()[0]);
                engine.removeCA(aid);
            }

        } else if (!wasMonitored && isMonitored) {
            this.certificateAuthority.readAuthority(entry);
        }
    }

    private synchronized void handleDELETE(LDAPEntry entry) {

        LDAPAttribute attr = entry.getAttribute("nsUniqueId");
        String nsUniqueId = null;

        if (attr != null)
            nsUniqueId = attr.getStringValueArray()[0];

        if (CAEngine.deletedNsUniqueIds.remove(nsUniqueId)) {
            logger.debug("handleDELETE: delete was already effected");
            return;
        }

        CAEngine engine = CAEngine.getInstance();
        AuthorityID aid = null;
        attr = entry.getAttribute("authorityID");

        if (attr != null) {

            aid = new AuthorityID(attr.getStringValueArray()[0]);
            CertificateAuthority ca = engine.getCA(aid);

            if (ca == null)
                return;  // shouldn't happen

            try {
                ca.deleteAuthorityNSSDB();
            } catch (ECAException e) {
                // log and carry on
                logger.warn("Caught exception attempting to delete NSSDB material "
                    + "for authority '" + aid + "': " + e.getMessage(), e);
            }

            engine.removeCA(aid);
        }
    }

    /**
     * Stop the activityMonitor thread
     *
     * connectionFactory.reset() will disconnect all connections,
     * causing the current conn.search() to throw.
     * The search will not be restarted because 'running' has
     * been set to false, and the monitor thread will exit.
     */
    public void shutdown() {
        running = false;
    }
}
