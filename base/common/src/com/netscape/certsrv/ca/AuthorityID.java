package com.netscape.certsrv.ca;

import java.util.UUID;

/**
 * Identifier for a CertificateAuthority.
 */
public class AuthorityID implements Comparable<AuthorityID> {

    protected UUID uuid;

    /**
     * Parse a AuthorityID from the given string
     */
    public AuthorityID(String s) {
        if (s == null)
            throw new IllegalArgumentException("null AuthorityID string");
        uuid = UUID.fromString(s);
    }

    /**
     * Construct a random AuthorityID
     */
    public AuthorityID() {
        uuid = UUID.randomUUID();
    }

    public String toString() {
        return uuid.toString();
    }

    public int compareTo(AuthorityID aid) {
        return uuid.compareTo(aid.uuid);
    }

}
