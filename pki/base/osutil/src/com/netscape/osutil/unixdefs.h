/* ====================================================== 
* Copyright (c) 1997 Netscape Communications Corporation 
* This file contains proprietary information of Netscape Communications. 
* Copying or reproduction without prior written approval is prohibited. 
* ====================================================== */ 

/* Handy shared values */

#define ILLARG "java/lang/IllegalArgumentException"
#define SECURITY "java/lang/SecurityException"
#define RUNTIME "java/lang/Runtime"

void unix_throw_exception(JNIEnv *env, const char *exception, const char *reason);

