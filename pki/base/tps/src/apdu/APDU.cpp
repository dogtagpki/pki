// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>
#include "apdu/APDU.h"
#include "engine/RA.h"
#include "main/Util.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs an APDU.
 *
 * ==============
 * APDU:
 * APDU are commands that can be sent from an authorized entity
 * (such as RA) to the token.  It takes the following form:
 * ---------------------------------------------------
 * | CLA | INS | P1  | P2  | lc  | data...
 * ---------------------------------------------------
 *
 * The values for the APDU header: CLA, INS, P1, P2 and lc are defined
 * in each individual APDU class.
 *
 * ==============
 * Status Words (response):
 * When APDUs are sent to the token, a response is returned.  The following
 * is a list of all possible Return Codes (Status Words):
 *
 * <I'm hoping not having to type this out...waiting for Bob to get back
 * to me with an electronic copy of his file...>
 *
 * ==============
 * ObjectID:
 *    byte[0] - an ASCII letter, 
 *          'c' - An object containing PKCS11 attributes for a certificate
 *          'k' - An object containing PKCS11 attributes for a public or private key
 *          'r' - An object containing PKCS11 attributes for a "reader"
 *          <upper case letters signify objects containing raw data 
 *           corresponding to lower cases objects above
 *    byte[1] - an ASCII numeral, in the range '0' - '9'
 *    byte[2] - binary zero
 *    byte[3] - binary zero
 *
 * ==============
 * ACLs:
 *    Each key or object on the card is associated with an ACL.
 *
 * ACL for objects:
 * [2-byte] Read Permissions;
 * [2-byte] Write Permissions;
 * [2-byte] Delete Permissions;
 *
 * Each permission is a 2-byte word.  A 1 in a bit grants permission
 * to it's corresponding identity if pass authentication.
 * permission 2-byte word format:
 * Bit 15 - reserved
 * Bit 14 - Identity #14 (strong - Secure Channel required)
 * Bit 13 - reserved
 * ...
 * Bit  7 - Identity #7 (PIN identity)
 * ...
 * Bit  1 - Identity #1 (PIN identity)
 * Bit  0 - Identity #0 (PIN identity)
 *
 * All 0 means operation never allowed
 */
TPS_PUBLIC APDU::APDU ()
{
	m_data = Buffer(0, (BYTE)0);
	m_mac = Buffer(0, (BYTE)0);
} /* APDU */

/**
 * Destroys an APDU.
 */ 
TPS_PUBLIC APDU::~APDU ()
{
} /* ~APDU */

/**
 * Copy constructor.
 */
TPS_PUBLIC APDU::APDU (const APDU &cpy)
{
    *this = cpy;
} /* APDU */

/**
 * Operator for simple assignment.
 */
TPS_PUBLIC APDU& APDU::operator=(const APDU &cpy)
{
    if (this == &cpy) 
      return *this;
    m_cla = cpy.m_cla;
    m_ins = cpy.m_ins;
    m_p1 = cpy.m_p1;
    m_p2 = cpy.m_p2;
    m_data = cpy.m_data;
    return *this;
} /* operator= */

TPS_PUBLIC APDU_Type APDU::GetType()
{
	return APDU_UNDEFINED;
}

/**
 * Sets APDU's CLA parameter.
 */
TPS_PUBLIC void APDU::SetCLA(BYTE cla)
{
    m_cla = cla;
} /* SetCLA */

/**
 * Sets APDU's INS parameter.
 */
TPS_PUBLIC void APDU::SetINS(BYTE ins)
{
    m_ins = ins;
} /* SetINS */

/**
 * Sets APDU's P1 parameter.
 */
TPS_PUBLIC void APDU::SetP1(BYTE p1)
{
    m_p1 = p1;
} /* SetP1 */

/**
 * Sets APDU's P2 parameter.
 */
TPS_PUBLIC void APDU::SetP2(BYTE p2)
{
    m_p2 = p2;
} /* SetP2 */


TPS_PUBLIC BYTE APDU::GetCLA()
{
	return m_cla;
}

TPS_PUBLIC BYTE APDU::GetINS()
{
	return m_ins;
}

TPS_PUBLIC BYTE APDU::GetP1()
{
	return m_p1;
}

TPS_PUBLIC BYTE APDU::GetP2()
{
	return m_p2;
}

TPS_PUBLIC Buffer &APDU::GetData()
{
	return m_data;
}

TPS_PUBLIC Buffer &APDU::GetMAC()
{
	return m_mac;
}

/**
 * Sets APDU's data parameter.
 */
TPS_PUBLIC void APDU::SetData(Buffer &data)
{
    m_data = data;
} /* SetData */

TPS_PUBLIC void APDU::SetMAC(Buffer &mac)
{
    m_mac = mac;
} /* SetMAC */

/**
 * populates "data" with data that's to be mac'd.
 * note: mac is not handled in here
 *
 * @param data results buffer
 */
TPS_PUBLIC void APDU::GetDataToMAC(Buffer &data)
{
    data += Buffer(1, m_cla);
    data += Buffer(1, m_ins);
    data += Buffer(1, m_p1);
    data += Buffer(1, m_p2);
    data += Buffer(1, (BYTE)m_data.size() + 8);
    data += Buffer(m_data, m_data.size());
}

/*
 * pad the message, if needed, and then
 * encrypt it with the encryption session key
 * and then set data
 *
 */
TPS_PUBLIC PRStatus APDU::SecureMessage(PK11SymKey *encSessionKey)
{
    PRStatus rv = PR_SUCCESS;
    Buffer data_to_enc;
    Buffer padding;
    Buffer data_encrypted;
    int pad_needed = 0;
#ifdef ENC_DEBUG
    m_plainText = m_data;
    // developer debugging only, not for production
//    RA::DebugBuffer("APDU::SecureMessage", "plaintext (pre padding) = ", &m_plainText);
#endif

    if (encSessionKey == NULL) {
 //     RA::Debug("APDU::SecureMessage", "no encryption session key");
      rv = PR_FAILURE;
      goto done;
    }
//    RA::Debug(LL_ALL_DATA_IN_PDU, "APDU::SecureMessage", "plaintext data length = %d", m_data.size());

    data_to_enc +=  (BYTE)m_data.size();
    data_to_enc += m_data;

    if ((data_to_enc.size() % 8) == 0)
      pad_needed = 0;
    else if (data_to_enc.size() < 8) {
      pad_needed = 8 - data_to_enc.size();
    } else { // data size > 8 and not divisible by 8
      pad_needed = 8 - (data_to_enc.size() % 8);
    }
    if (pad_needed) {
//      RA::Debug(LL_ALL_DATA_IN_PDU, "APDU::SecureMessage", "padding needed =%d", pad_needed);
      data_to_enc += Buffer(1, 0x80);
      pad_needed --;

      if (pad_needed) {
//	RA::Debug(LL_ALL_DATA_IN_PDU, "APDU::SecureMessage", "padding needed =%d", pad_needed);
	padding = Buffer(pad_needed, (BYTE)0);
	for (int i = 0; i < pad_needed; i++) {
	    ((BYTE*)padding)[i] = 0x00;
	} /* for */
      } // pad needed

    } else {
 //     RA::Debug(LL_ALL_DATA_IN_PDU, "APDU::SecureMessage", "padding not needed");
    }

    if (padding.size() > 0) {
        data_to_enc += Buffer(padding, padding.size());
    }

#ifdef ENC_DEBUG
//    RA::DebugBuffer("APDU::SecureMessage", "data to encrypt (post padding)= ",&data_to_enc);
#endif

    // now, encrypt "data_to_enc"
    rv = Util::EncryptData(encSessionKey, data_to_enc, data_encrypted);
    if (rv == PR_FAILURE) {
 //     RA::Error("APDU::SecureMessage", "encryption failed");
      goto done;
    } else {
 //     RA::Debug(LL_PER_PDU, "APDU::SecureMessage", "encryption succeeded");
 //      RA::Debug(LL_PER_PDU, "APDU::SecureMessage", "encrypted data length = %d",
//	      data_encrypted.size());
      // set "m_data"
      m_data = data_encrypted;
    }

    // lc should be automatically set correctly when getEncoding is called

 done:
    return rv;

}


/**
 * Retrieves APDU's encoding. 
 * The encoding of APDU is as follows:
 *
 *   CLA            1 byte
 *   INS            1 byte
 *   P1             1 byte
 *   P2             1 byte
 *   <Data Size>    1 byte
 *   <Data>         <Data Size> byte(s)
 *   0              1 byte
 * 
 * @param data the result buffer which will contain the actual data
 *        including the APDU header, data, and pre-calculated mac.
 */
TPS_PUBLIC void APDU::GetEncoding(Buffer &data)
{
    data += Buffer(1, m_cla);
    data += Buffer(1, m_ins);
    data += Buffer(1, m_p1);
    data += Buffer(1, m_p2);
    data += Buffer(1, (BYTE)m_data.size() + m_mac.size());
    data += Buffer(m_data, m_data.size());
    if (m_mac.size() > 0) {
      data += Buffer(m_mac, m_mac.size());
    }
} /* Encode */
