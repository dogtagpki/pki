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
// Copyright (C) 2010 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#ifndef LOGFILE_H
#define LOGFILE_H

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include "main/RA_Context.h"
#include "main/Util.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class LogFile {
  protected:
    PRFileDesc *m_fd;
    char* m_fname;
    volatile bool m_signed_log; 
    volatile size_t m_bytes_written;
    volatile bool m_signed;  
    PRMonitor *m_monitor;
    RA_Context *m_ctx;

  public:
    TPS_PUBLIC LogFile();  
    TPS_PUBLIC virtual ~LogFile() {} 

    /* startup and shutdown */
    virtual int startup(RA_Context* ctx, const char* prefix, const char *fname, bool sign_audit);
    virtual void shutdown();
    virtual void child_init() {}

    /* open/close the file */
    int open();
    int close();
    bool isOpen();

    /* read and write */
    virtual int write(char * msg);
    int printf(const char* fmt, ...);
    int write(char *msg, size_t n);
    int vfprintf(const char* fmt, va_list ap);
    int ReadLine(char *buf, int buf_len, int *removed_return);

    /* accessor and setters */
    void setSigned(bool val);
    bool getSigned();
    int get_bytes_written(); 
    void set_bytes_written(int val);
    RA_Context * get_context();
    void set_context(RA_Context *ctx);
};

#endif
