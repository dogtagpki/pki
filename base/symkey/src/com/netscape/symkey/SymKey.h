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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#ifndef _TKSSYMKEY_H_
#define _TKSSYMKEY_H_

extern PK11SlotInfo *defaultSlot;

typedef enum {
	enc,		
	mac,		
	kek		
	} keyType;
#define KEYLENGTH 16	
#define PREFIXLENGHT  128
#define DES2_LENGTH 16
#define DES3_LENGTH 24
#define EIGHT_BYTES 8
#define KEYNAMELENGTH PREFIXLENGHT+7
#define TRANSPORT_KEY_NAME "sharedSecret"
#define DEFKEYSET_NAME "defKeySet"

extern char masterKeyPrefix[PREFIXLENGHT];
extern char sharedSecretSymKeyName[KEYNAMELENGTH];

void GetDiversificationData(jbyte *cuidValue,BYTE *KDC,keyType keytype);
PK11SymKey * ReturnSymKey( PK11SlotInfo *slot, char *keyname);
void GetKeyName(jbyte *keyVersion,char *keyname);
PK11SymKey * ComputeCardKeyOnToken(PK11SymKey *masterKey, BYTE* data);
PRStatus EncryptData(const Buffer &kek_key, PK11SymKey *card_key, Buffer &input, Buffer &output);
PK11SlotInfo *ReturnSlot(char *tokenNameChars);
PK11SymKey *ComputeCardKey(PK11SymKey *masterKey, unsigned char *data, PK11SlotInfo *slot);
PK11SymKey *CreateUnWrappedSymKeyOnToken( PK11SlotInfo *slot, PK11SymKey * unWrappingKey, BYTE *keyToBeUnWrapped, int sizeOfKeyToBeUnWrapped, PRBool isPerm);
PK11SymKey *ReturnDeveloperSymKey(PK11SlotInfo *slot, char *keyType, char *keySet, Buffer &inputKey);
PK11SymKey *CreateDesKey24Byte(PK11SlotInfo *slot, PK11SymKey *origKey);

char *GetSharedSecretKeyName(char *newKeyName);

#define DES2_WORKAROUND
#endif /* _TKSSYMKEY_H_ */

