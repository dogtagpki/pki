@ECHO OFF
REM  --- BEGIN COPYRIGHT BLOCK ---
REM  This program is free software; you can redistribute it and/or modify
REM  it under the terms of the GNU General Public License as published by
REM  the Free Software Foundation; version 2 of the License.
REM
REM  This program is distributed in the hope that it will be useful,
REM  but WITHOUT ANY WARRANTY; without even the implied warranty of
REM  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
REM  GNU General Public License for more details.
REM
REM  You should have received a copy of the GNU General Public License along
REM  with this program; if not, write to the Free Software Foundation, Inc.,
REM  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
REM
REM  Copyright (C) 2007 Red Hat, Inc.
REM  All rights reserved.
REM  --- END COPYRIGHT BLOCK ---

REM
REM  This script converts a normalized <Source CMS Version> ldif
REM  text file (e. g. - created via a <Source CMS Version>ToTxt
REM  script) into a CMS 6.2 ldif data file.
REM
REM  This CMS 6.2 ldif data file can then be imported into the
REM  internal database of the desired CMS 6.2 server using a
REM  utility such as ldif2db.
REM


SETLOCAL


REM
REM  SERVER_ROOT - fully qualified path of the location of the server
REM

REM SET SERVER_ROOT=C:\cms62


REM
REM  INSTANCE  - if the CMS instance directory is called 'cert-ca',
REM              set the CMS instance to 'ca'
REM
REM              NOTE:  When a single SERVER_ROOT contains more than
REM                     one CMS instance, this script must be run multiple
REM                     times.  To do this, there is only a need to change
REM                     the INSTANCE parameter.
REM

REM SET INSTANCE=ca


REM
REM             *** DON'T CHANGE ANYTHING BELOW THIS LINE ***
REM


REM
REM  Script-defined constants
REM

SET CMS="CMS 6.2"


REM
REM  Perform a usage check for the appropriate number of arguments:
REM

IF "%1" == "" GOTO USAGE
IF "%3" == "" GOTO CHECK_INPUT_FILE


:USAGE
ECHO.
ECHO Usage:  "%0 input [errors] > output"
ECHO.
ECHO         where:  input  - the specified %CMS% ldif data file,
ECHO                 errors - an optional errors file containing
ECHO                          skipped attributes, and
ECHO                 output - the normalized %CMS% ldif text file.
ECHO.
ECHO                 NOTE:  If no redirection is provided to
ECHO                        'output', then the normalized
ECHO                        %CMS% ldif text will merely
ECHO                        be echoed to stdout.
ECHO.
GOTO EXIT_PROCESS


REM
REM  Check that the specified "input" file exists
REM

:CHECK_INPUT_FILE
IF EXIST %1 GOTO CHECK_ERRORS_FILE


ECHO ERROR:  The specified input file, %1, does not exist!
ECHO.
GOTO EXIT_PROCESS


REM
REM  If an "errors" file is specified, then check that it does not already
REM  exist.
REM

:CHECK_ERRORS_FILE
IF "%2" == "" GOTO CHECK_ENVIRONMENT_VARIABLES
IF EXIST %2 GOTO ERRORS_FILE_ERROR
GOTO CHECK_ENVIRONMENT_VARIABLES


:ERRORS_FILE_ERROR
ECHO ERROR:  The specified errors file, %2, already exists!
ECHO         Please specify a different file!
ECHO.
GOTO EXIT_PROCESS


REM
REM  Check presence of user-defined variables
REM

:CHECK_ENVIRONMENT_VARIABLES
IF !%SERVER_ROOT%==! GOTO ENVIRONMENT_VARIABLES_ERROR
IF !%INSTANCE%==! GOTO ENVIRONMENT_VARIABLES_ERROR
GOTO CHECK_SERVER_ROOT


:ENVIRONMENT_VARIABLES_ERROR
ECHO ERROR:  Please specify the SERVER_ROOT and INSTANCE
ECHO         environment variables for this script!
ECHO.
GOTO EXIT_PROCESS


REM
REM  Check that the specified SERVER_ROOT exists
REM

:CHECK_SERVER_ROOT
IF EXIST %SERVER_ROOT% GOTO CHECK_INSTANCE


ECHO ERROR:  The specified SERVER_ROOT does not exist!
ECHO.
GOTO EXIT_PROCESS


REM
REM  Check that the specified INSTANCE exists
REM

:CHECK_INSTANCE
IF EXIST %SERVER_ROOT%\cert-%INSTANCE% GOTO SET_LIBRARY_PATH


ECHO ERROR:  The specified INSTANCE does not exist!
ECHO.
GOTO EXIT_PROCESS


REM
REM  Setup the appropriate library path environment variable
REM  based upon the platform (WINNT)
REM

:SET_LIBRARY_PATH
SET PATH=%SERVER_ROOT%\bin\cert\lib;%SERVER_ROOT%\bin\cert\jre\bin;%SERVER_ROOT\bin\cert\jre\bin\server;%PATH%


REM
REM  Convert the specified %CMS% ldif data file
REM  into a normalized %CMS% ldif text file.
REM

%SERVER_ROOT%\bin\cert\jre\bin\java.exe -classpath .\classes;%SERVER_ROOT%\cert-%INSTANCE%\classes;%SERVER_ROOT%\bin\cert\classes;%SERVER_ROOT%\bin\cert\jars\certsrv.jar;%SERVER_ROOT%\bin\cert\jars\cmscore.jar;%SERVER_ROOT%\bin\cert\jars\nsutil.jar;%SERVER_ROOT%\bin\cert\jars\jss3.jar;%SERVER_ROOT%\bin\cert\jre\lib\rt.jar Main %1 %2


:EXIT_PROCESS


ENDLOCAL

