/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "secoid.h"
#include "secmodt.h" /* for CKM_INVALID_MECHANISM */

#define OI(x)                                  \
    {                                          \
        siDEROID, (unsigned char *)x, sizeof x \
    }
#define OD(oid, tag, desc, mech, ext) \
    {                                 \
        OI(oid)                       \
        , tag, desc, mech, ext        \
    }
#define ODN(oid, desc)                                           \
    {                                                            \
        OI(oid)                                                  \
        , 0, desc, CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION \
    }

#define OIDT static const unsigned char


/* USGov algorithm OID space: { 2 16 840 1 101 } */
#define USGOV 0x60, 0x86, 0x48, 0x01, 0x65
#define NISTALGS USGOV, 3, 4
#define AES NISTALGS, 1

/* AES_KEY_WRAP_KWP oids */

OIDT aes128_KEY_WRAP_KWP[] = { AES, 8 };
OIDT aes192_KEY_WRAP_KWP[] = { AES, 28 };
OIDT aes256_KEY_WRAP_KWP[] = { AES, 48 };

/* ------------------------------------------------------------------- */
static const SECOidData oids[] = {
    /* AES_KEY_WRAP_KWP oids */

    OD(aes128_KEY_WRAP_KWP,0,"AES-128 Key Wrap Kwp", CKM_AES_KEY_WRAP_KWP, INVALID_CERT_EXTENSION),
    OD(aes192_KEY_WRAP_KWP,0,"AES-192 Key Wrap Kwp", CKM_AES_KEY_WRAP_KWP, INVALID_CERT_EXTENSION),
    OD(aes256_KEY_WRAP_KWP,0,"AES-256 Key Wrap Kwp", CKM_AES_KEY_WRAP_KWP, INVALID_CERT_EXTENSION), 

};

static const unsigned int numOids = (sizeof oids) / (sizeof oids[0]);

static SECOidTag newOIDTags[3];
/* Fetch and register an oid if it hasn't been done already */
void
SECU_cert_fetchOID(SECOidTag *data, const SECOidData *src)
{
    if (*data == SEC_OID_UNKNOWN) {
        /* AddEntry does the right thing if someone else has already
         * added the oid. (that is return that oid tag) */
        *data = SECOID_AddEntry(src);
    }
}

SECOidTag SECU_GetNewTagFromOffset(unsigned int offset) {
    if(offset >= numOids) {
        return SEC_OID_UNKNOWN;
    }
    return newOIDTags[offset];
}

SECStatus
SECU_RegisterDynamicOids(void)
{
    unsigned int i;
    SECStatus rv = SECSuccess;

    for (i = 0; i < numOids; ++i) {
        SECOidTag tag = SECOID_AddEntry(&oids[i]);
        if (tag == SEC_OID_UNKNOWN) {
            rv = SECFailure;
        } else {
	    newOIDTags[i] = tag;
        }
    }
    return rv;
}
