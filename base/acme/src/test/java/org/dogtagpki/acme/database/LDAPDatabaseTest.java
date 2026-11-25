//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.dogtagpki.acme.ACME;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEIdentifier;
import org.junit.jupiter.api.Test;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPModificationSet;

/**
 * Exercises LDAP entry serialization without requiring a directory server.
 * The fixture replaces LDAP I/O while retaining the database's readers and writers.
 */
public class LDAPDatabaseTest {

    @Test
    public void successfulChallengeRetainsValidationTimeAfterAuthorizationUpdate() throws Exception {
        EntryDatabase database = new EntryDatabase();
        ACMEAuthorization authorization = authorization("http-01");
        database.addAuthorization(authorization);

        // Successful validation updates an existing authorization. LDAP replaces
        // its challenge entries, so the replacement must include the timestamp.
        ACMEChallenge challenge = authorization.getChallenges().iterator().next();
        challenge.setStatus("valid");
        challenge.setValidationTime(Date.from(Instant.parse("2026-11-24T14:23:45.678Z")));
        authorization.setStatus("valid");
        database.updateAuthorization(authorization);

        ACMEChallenge stored = database.getAuthorization(authorization.getID())
                .getChallenges().iterator().next();

        // LDAP's existing Generalized Time format preserves whole seconds.
        Date expected = Date.from(Instant.parse("2026-11-24T14:23:45Z"));
        assertEquals("valid", stored.getStatus());
        assertEquals(expected, stored.getValidationTime());
        assertEquals(ACME.DATE_FORMAT.format(expected), stored.getValidated());
        assertEquals("20261124142345+0000", database.challengeEntry()
                .getAttribute(LDAPDatabase.ATTR_VALIDATED_AT).getStringValueArray()[0]);
    }

    @Test
    public void pendingChallengeHasNoValidationTime() throws Exception {
        EntryDatabase database = new EntryDatabase();
        ACMEAuthorization authorization = authorization("dns-01");
        database.addAuthorization(authorization);

        ACMEChallenge stored = database.getAuthorization(authorization.getID())
                .getChallenges().iterator().next();

        assertEquals("pending", stored.getStatus());
        assertNull(database.challengeEntry().getAttribute(LDAPDatabase.ATTR_VALIDATED_AT));
        assertNull(stored.getValidationTime());
        assertNull(stored.getValidated());
    }

    private static ACMEAuthorization authorization(String challengeType) {
        ACMEChallenge challenge = new ACMEChallenge();
        challenge.setID("challenge-1");
        challenge.setAuthzID("authorization-1");
        challenge.setType(challengeType);
        challenge.setToken("test-token");
        challenge.setStatus("pending");

        ACMEAuthorization authorization = new ACMEAuthorization();
        authorization.setID(challenge.getAuthzID());
        authorization.setAccountID("account-1");
        authorization.setCreationTime(Date.from(Instant.parse("2026-11-24T14:00:00Z")));
        authorization.setIdentifier(new ACMEIdentifier("dns", "example.test"));
        authorization.setStatus("pending");
        authorization.setChallenges(List.of(challenge));
        return authorization;
    }

    /** Stores LDAP entries rather than Java authorization or challenge objects. */
    private static class EntryDatabase extends LDAPDatabase {

        private final Map<String, LDAPEntry> entries = new HashMap<>();

        EntryDatabase() {
            baseDN = "dc=example,dc=test";
        }

        LDAPEntry challengeEntry() {
            return entries.get(ATTR_CHALLENGE_ID + "=challenge-1," + RDN_CHALLENGE + "," + baseDN);
        }

        @Override
        void ldapAdd(LDAPEntry entry) {
            entries.put(entry.getDN(), entry);
        }

        @Override
        LDAPEntry ldapGet(String dn) {
            return entries.get(dn);
        }

        @Override
        void ldapDelete(String dn, OnNoSuchObject action) {
            entries.remove(dn);
        }

        @Override
        void ldapModify(String dn, LDAPModificationSet modifications) {
            LDAPEntry entry = entries.get(dn);
            for (int i = 0; i < modifications.size(); i++) {
                LDAPAttribute attribute = modifications.elementAt(i).getAttribute();
                entry.getAttributeSet().remove(attribute.getName());
                if (attribute.size() > 0) {
                    entry.getAttributeSet().add(attribute);
                }
            }
        }

        @Override
        List<LDAPEntry> ldapSearch(String searchBase, String filter) {
            // These tests use one authorization. Its challenge entries are the
            // only entries below this search base, so no filter parser is needed.
            return entries.values().stream()
                    .filter(entry -> entry.getDN().endsWith("," + searchBase))
                    .toList();
        }
    }
}
