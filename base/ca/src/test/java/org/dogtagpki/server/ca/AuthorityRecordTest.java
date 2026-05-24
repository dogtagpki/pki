// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AuthorityRecordTest {

    private AuthorityRecord record;

    @BeforeEach
    public void setUp() {
        record = new AuthorityRecord();
    }

    @Test
    public void testIsExternalKey_withSentinelPrefix() {
        record.setKeyNickname(
                AuthorityRecord.EXTERNAL_KEY_NICKNAME_PREFIX + "abc-123");
        assertTrue(record.isExternalKey(),
                "Expected isExternalKey() == true for sentinel nickname");
    }

    @Test
    public void testIsExternalKey_withNormalNickname() {
        record.setKeyNickname("HSM:CA signing cert");
        assertFalse(record.isExternalKey(),
                "Expected isExternalKey() == false for a real token:nickname");
    }

    @Test
    public void testIsExternalKey_withInternalSoftwareNickname() {
        record.setKeyNickname("caSigningCert cert-pki-ca");
        assertFalse(record.isExternalKey(),
                "Expected isExternalKey() == false for a software-token nickname");
    }

    @Test
    public void testIsExternalKey_withNullNickname() {
        record.setKeyNickname(null);
        assertFalse(record.isExternalKey(),
                "Expected isExternalKey() == false when keyNickname is null");
    }

    @Test
    public void testIsExternalKey_sentinelPrefixConstantValue() {
        // The constant must start with '#' so it can never be mistaken for a
        // valid NSS token name (which uses alphanumerics and spaces only).
        assertTrue(AuthorityRecord.EXTERNAL_KEY_NICKNAME_PREFIX.startsWith("#"),
                "Sentinel prefix must start with '#'");
    }

    @Test
    public void testIsExternalKey_prefixAloneIsExternal() {
        // An edge case: just the prefix with no UUID suffix should still be
        // detected as external so it does not accidentally reach the NSS token
        // lookup code.
        record.setKeyNickname(AuthorityRecord.EXTERNAL_KEY_NICKNAME_PREFIX);
        assertTrue(record.isExternalKey(),
                "Bare sentinel prefix should still be detected as external");
    }
}
