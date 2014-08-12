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

#include <string.h>
#include "prmem.h"
#include "pk11func.h"
#include "main/Buffer.h"
#include "main/ObjectSpec.h"
#include "engine/RA.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

ObjectSpec::ObjectSpec ()
{
        for (int i = 0; i < MAX_ATTRIBUTE_SPEC; i++) {
              m_attributeSpec[i] = NULL;
        }
	m_fixedAttributes = 0;
}

ObjectSpec::~ObjectSpec ()
{
    for (int i = 0; i < MAX_ATTRIBUTE_SPEC; i++) {
	      if (m_attributeSpec[i] != NULL) {
	          delete m_attributeSpec[i];  
	          m_attributeSpec[i] = NULL;
	      }
	}
}

#define DATATYPE_STRING       0
#define DATATYPE_INTEGER      1
#define DATATYPE_BOOL_FALSE   2
#define DATATYPE_BOOL_TRUE    3

/**
 * Parse 'c' object.
 */
void ObjectSpec::ParseAttributes(char *objectID, ObjectSpec *ObjectSpec, Buffer *b)
{
	int curpos = 7;
	unsigned long fixedAttrs = 0;
	unsigned int xclass = 0;
	unsigned int id = 0;

	/* skip first 7 bytes */

	while (curpos < ((int)(b->size()))) {
		unsigned long attribute_id = 
			(((BYTE*)*b)[curpos] << 24) +
			(((BYTE*)*b)[curpos+1] << 16) +
			(((BYTE*)*b)[curpos+2] << 8) +
			((BYTE*)*b)[curpos+3];
		unsigned short attribute_size = 
			(((BYTE*)*b)[curpos+4] << 8) +
			((BYTE*)*b)[curpos+5];
		BYTE type = 0;
		Buffer data;
		int found = 0;
		/* modify fixed attributes */

		switch (attribute_id) {
		case CKA_TOKEN:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00000080;
			}
			break;
		case CKA_PRIVATE:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00000100;
			} else {
			}
			break;
		case CKA_MODIFIABLE:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00000200;
			}
			break;
		case CKA_DERIVE:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00000400;
			}
			break;
		case CKA_LOCAL:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00000800;
			}
			break;
		case CKA_ENCRYPT:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00001000;
			}
			break;
		case CKA_DECRYPT:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00002000;
			}
			break;
		case CKA_WRAP:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00004000;
			}
			break;
		case CKA_UNWRAP:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00008000;
			}
			break;
		case CKA_SIGN:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00010000;
			}
			break;
		case CKA_SIGN_RECOVER:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00020000;
			}
			break;
		case CKA_VERIFY:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00040000;
			}
			break;
		case CKA_VERIFY_RECOVER:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00080000;
			}
			break;
		case CKA_SENSITIVE:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00100000;
			}
			break;
		case CKA_ALWAYS_SENSITIVE:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00200000;
			}
			break;
		case CKA_EXTRACTABLE:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00400000;
			}
			break;
		case CKA_NEVER_EXTRACTABLE:
			if (((BYTE*)*b)[curpos+6]) {
				fixedAttrs |= 0x00800000;
			}
			break;
		case CKA_SUBJECT:
			type = DATATYPE_STRING;
			data = b->substr(curpos+6, attribute_size);
			/* build by PKCS11 */
			break;
		case CKA_LABEL:
			type = DATATYPE_STRING;
			data = b->substr(curpos+6, attribute_size);
			found = 1;
			break;
		case CKA_MODULUS:
			type = DATATYPE_STRING;
			data = b->substr(curpos+6, attribute_size);
			/* build by PKCS11 */
			break;
		case CKA_ID:
			type = DATATYPE_STRING;
			data = b->substr(curpos+6, attribute_size);
			/* build by PKCS11 */
			break;
		case CKA_KEY_TYPE:
			type = DATATYPE_INTEGER;
			data = b->substr(curpos+6, 4);
                        found = 1;
			/* build by PKCS11 */
			break;
		case CKA_CLASS:
			type = DATATYPE_INTEGER;
			data = b->substr(curpos+6, 4);
			xclass = ((BYTE*)data)[0];
			/* build by PKCS11 */
			break;
		case CKA_PUBLIC_EXPONENT:
			type = DATATYPE_STRING;
			data = b->substr(curpos+6, attribute_size);
			/* build by PKCS11 */
			break;
		case CKA_CERTIFICATE_TYPE:
			type = DATATYPE_INTEGER;
			data = b->substr(curpos+6, 4);
			/* build by PKCS11 */
			break;

        case CKA_EC_PARAMS:
            type = DATATYPE_STRING;
            data = b->substr(curpos+6, attribute_size);
            found = 1;
            break;

        case CKA_EC_POINT:
            type = DATATYPE_STRING;
            data = b->substr(curpos+6, attribute_size);
            found = 1;
            break;
		default:
			RA::Debug("ObjectSpec::ParseKeyBlob", 
				"skipped attribute_id = %lx", 
			attribute_id);
			break;
		}


		if (found) {
			/* add attribute spec */
			AttributeSpec *attrSpec = new AttributeSpec();
			attrSpec->SetAttributeID(attribute_id);
			attrSpec->SetType(type);

			switch (type) {
			case DATATYPE_STRING:
				attrSpec->SetData(data);
				break;
			case DATATYPE_INTEGER:
				attrSpec->SetData(data);
				break;
			case DATATYPE_BOOL_FALSE:
				break;
			case DATATYPE_BOOL_TRUE:
				break;
			default:
				break;
			}

			ObjectSpec->AddAttributeSpec(attrSpec);
		}


		curpos += 4 + 2 + attribute_size;
	}

        //Here the objectID fixed attribute gets massaged. Here's how:
        // The objectID becomes the cert container id, ex: 01
        // Each key pair associated with the cert must have the same ID.
        // This is done by math using the following formula:
        // Given a cert id of "2", the keyAttrIds of the keys are originally
        // configured as k4 and k5. Note that one is twice the cert id, and
        // the other is twice the cert id plus 1. In order to map the key ids
        // down to the cert's id, the code below changes both "4" and "5" back
        // to "2".

	int val = (objectID[1] - '0');
	switch (objectID[0]) {
        case 'c':		
		id = val;
#if 0
		fixedAttrs |= 
				0x00000080 /* CKA_TOKEN */
			;
#endif
		break;
        case 'k':		
		if (val % 2) {
			id = (val-1)/2;
		} else {
			id = (val/2);
		}
#if 0
		if (xclass == CKO_PUBLIC_KEY) {
			fixedAttrs |= 
				0x00000800 /* CKA_LOCAL */ |
				0x00000080 /* CKA_TOKEN */ 
				;
		} 
		if (xclass == CKO_PRIVATE_KEY) {
			fixedAttrs |= 
				0x00000800 /* CKA_LOCAL */ |
				0x00000080 /* CKA_TOKEN */ 
				;
		} 
#endif
		break;
	}

	ObjectSpec->SetFixedAttributes(fixedAttrs | (xclass << 4) | id);
}

/**
 * Parse 'c' object.
 */
void ObjectSpec::ParseCertificateAttributes(char *objectID, ObjectSpec *ObjectSpec, Buffer *b)
{
	ParseAttributes(objectID, ObjectSpec, b);
}

/**
 * Parse 'k' object.
 */
void ObjectSpec::ParseKeyAttributes(char *objectID, ObjectSpec *ObjectSpec, Buffer *b)
{
	ParseAttributes(objectID, ObjectSpec, b);
}

/**
 * Parse 'C' object.
 */
void ObjectSpec::ParseCertificateBlob(char *objectID, ObjectSpec *ObjectSpec, Buffer *b)
{
	unsigned long fixedAttrs = 0;
	unsigned int xclass = 0;
	unsigned int id = 0;

	AttributeSpec *value = new AttributeSpec();
	value->SetAttributeID(CKA_VALUE);
	value->SetType(DATATYPE_STRING);
	value->SetData(*b);
	ObjectSpec->AddAttributeSpec(value);

	fixedAttrs = 0x00000080; /* CKA_TOKEN */
	xclass = CKO_CERTIFICATE;
	id = objectID[1] - '0';

	ObjectSpec->SetFixedAttributes(fixedAttrs| (xclass << 4) | id);
}

/**
 * Convert object from token into object spec.
 *
 * Reference:
 * http://netkey/design/applet_readable_object_spec-0.1.txt
 * http://netkey/design/pkcs11obj.txt
 */
ObjectSpec *ObjectSpec::ParseFromTokenData(unsigned long objid, Buffer *b)
{
        char objectID[4];

        ObjectSpec *o = new ObjectSpec();
	o->SetObjectID(objid);

	objectID[0] = (char)((objid >> 24) & 0xff); 
	objectID[1] = (char)((objid >> 16) & 0xff); 
	objectID[2] = (char)((objid >> 8) & 0xff); 
	objectID[3] = (char)((objid) & 0xff); 

	switch (objectID[0]) {
		case 'c': /* certificate attributes */
			ParseCertificateAttributes(objectID, o, b);
			break;
		case 'k': /* public key or private key attributes */
			ParseKeyAttributes(objectID, o, b);
			break;
		case 'C': /* certificate in DER */
			ParseCertificateBlob(objectID, o, b);
			break;
		default: 
			RA::Debug("ObjectSpec::ParseKeyBlob", 
				"unknown objectID = %c", objectID[0]);
			/* error */
			break;
	}

	return o;
}

ObjectSpec *ObjectSpec::Parse(Buffer *b, int offset, int *nread)
{
	int sum = 0;


        if((b->size() - offset) < 10)
            return NULL;
        
        ObjectSpec *o = new ObjectSpec();
	unsigned long id = 
		(((unsigned char *)*b)[offset + 0] << 24) + 
		(((unsigned char *)*b)[offset + 1] << 16) + 
		(((unsigned char *)*b)[offset + 2] << 8) + 
		(((unsigned char *)*b)[offset + 3]);

	o->SetObjectID(id);
	unsigned long attribute = 
		(((unsigned char *)*b)[offset + 4] << 24) + 
		(((unsigned char *)*b)[offset + 5] << 16) + 
		(((unsigned char *)*b)[offset + 6] << 8) + 
		(((unsigned char *)*b)[offset + 7]);
	o->SetFixedAttributes(attribute);
	unsigned short count = (((unsigned char *)*b)[offset + 8] << 8) + 
		((unsigned char *)*b)[offset + 9];
	sum += 10;
	int curpos = offset + 10;
	for (int i = 0; i < count; i++) {
		int len = 0;
		switch (((unsigned char *)*b)[curpos+4]) {
                case DATATYPE_STRING:
			len = 4 + 1 + 2 + (((unsigned char *)*b)[curpos+5]<<8) + ((unsigned char *)*b)[curpos+6];
			break;
                case DATATYPE_INTEGER:
			len = 4 + 1 + 4;
			break;
                case DATATYPE_BOOL_FALSE:
			len = 4 + 1;
			break;
                case DATATYPE_BOOL_TRUE:
			len = 4 + 1;
			break;
		}
		Buffer attr = b->substr(curpos, len);
		AttributeSpec *attrSpec = AttributeSpec::Parse(&attr, 0);
		o->AddAttributeSpec(attrSpec);
		curpos += len;
		sum += len;
	}
	*nread = sum;
        return o;
}

void ObjectSpec::SetObjectID(unsigned long v)
{
	m_objectID = v;
}

unsigned long ObjectSpec::GetObjectID()
{
	return m_objectID;
}

void ObjectSpec::SetFixedAttributes(unsigned long v)
{
	m_fixedAttributes = v;
}

unsigned long ObjectSpec::GetFixedAttributes()
{
	return m_fixedAttributes;
}


int ObjectSpec::GetAttributeSpecCount()
{
        for (int i = 0; i < MAX_ATTRIBUTE_SPEC; i++) {
                if (m_attributeSpec[i] == NULL) {
                        return i;
                }
        }
        return 0;
}

AttributeSpec *ObjectSpec::GetAttributeSpec(int p)
{
        if (p < MAX_ATTRIBUTE_SPEC) {
                if (m_attributeSpec[p] != NULL) {
                        return m_attributeSpec[p];
                }
        }
        return NULL;
}

void ObjectSpec::AddAttributeSpec(AttributeSpec *p)
{
        for (int i = 0; i < MAX_ATTRIBUTE_SPEC; i++) {
                if (m_attributeSpec[i] == NULL) {
                        m_attributeSpec[i] = p;
                        return;
                }
        }
}

void ObjectSpec::RemoveAttributeSpec(int p)
{
        if (p < MAX_ATTRIBUTE_SPEC) {
                if (m_attributeSpec[p] != NULL) {
                        delete m_attributeSpec[p];
                        m_attributeSpec[p] = NULL;
                }
                // fill hole
                int empty = p;
                for (int x = p+1; x < MAX_ATTRIBUTE_SPEC; x++) {
                        if (m_attributeSpec[x] != NULL) {
                                m_attributeSpec[empty] = m_attributeSpec[x];
                                m_attributeSpec[x] = NULL;
                                empty++;
                        }
                }
        }

}

Buffer ObjectSpec::GetData()
{
	Buffer data = Buffer();

	data += Buffer(1, (BYTE)(m_objectID >> 24) & 0xff);
	data += Buffer(1, (BYTE)(m_objectID >> 16) & 0xff);
	data += Buffer(1, (BYTE)(m_objectID >> 8) & 0xff);
	data += Buffer(1, (BYTE)(m_objectID & 0xff));
	data += Buffer(1, (BYTE)(m_fixedAttributes >> 24) & 0xff);
	data += Buffer(1, (BYTE)(m_fixedAttributes >> 16) & 0xff);
	data += Buffer(1, (BYTE)(m_fixedAttributes >> 8) & 0xff);
	data += Buffer(1, (BYTE)(m_fixedAttributes & 0xff));

	unsigned short attributeCount = GetAttributeSpecCount();
	data += Buffer(1, (attributeCount >> 8) & 0xff);
	data += Buffer(1, attributeCount & 0xff);
	for (int i = 0; i < attributeCount; i++) {
		AttributeSpec *spec = GetAttributeSpec(i);
		data += spec->GetData();
	}

	return data;
}
