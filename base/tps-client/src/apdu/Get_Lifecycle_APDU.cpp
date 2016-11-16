#include <stdio.h>
#include "apdu/APDU.h"
#include "apdu/Get_Lifecycle_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Get Lifecycle APDU.
 */

TPS_PUBLIC Get_Lifecycle_APDU::Get_Lifecycle_APDU ()
{
    SetCLA(0xB0);
    SetINS(0xF2);
    SetP1(0x00);
    SetP2(0x00);
}

TPS_PUBLIC Get_Lifecycle_APDU::~Get_Lifecycle_APDU ()
{
}

TPS_PUBLIC APDU_Type Get_Lifecycle_APDU::GetType()
{
        return APDU_GET_LIFECYCLE;
}

TPS_PUBLIC void Get_Lifecycle_APDU::GetEncoding(Buffer &data){

	data += Buffer(1, m_cla);
	data += Buffer(1, m_ins);
	data += Buffer(1, m_p1);
	data += Buffer(1, m_p2);
	data += Buffer(1, 0x01);

}
