@ECHO OFF
REM  --- BEGIN COPYRIGHT BLOCK ---
REM  Copyright (C) 2007 Red Hat, Inc.
REM  All rights reserved.
REM  --- END COPYRIGHT BLOCK ---

REM
REM  This script creates the "TxtTo60/classes/Main.class",
REM  "TxtTo60/classes/CMS60LdifParser.class", and
REM  "TxtTo60/classes/DummyAuthManager.class" which are
REM  used to create a CMS 6.0/6.01 ldif data file.
REM


SETLOCAL


REM
REM  Set SERVER_ROOT - identify the CMS <server_root> used to compile TxtTo60
REM

REM SET SERVER_ROOT=C:\cms601


REM
REM  Set JDK_VERSION - specify the JDK version used by this version of CMS
REM
REM                    CMS 6.0 NOTE:   "WINNT" - 1.3.1_02
REM
REM                    CMS 6.01 NOTE:  "WINNT" - 1.3.1_02
REM

REM SET JDK_VERSION=CMS_6.01


REM 
REM  Set JAVA_HOME - specify the complete path to the JDK
REM 
REM                  example:  \\bermuda.redhat.com\sbc mounted as Y:
REM 

REM SET JAVA_HOME=Y:\cms_jdk\WINNT\%JDK_VERSION%


REM
REM             *** DON'T CHANGE ANYTHING BELOW THIS LINE ***
REM


REM
REM  Script-defined constants
REM

SET CMS="CMS 6.0"


REM
REM  Perform a usage check for the appropriate number of arguments:
REM

IF "%1" == "" GOTO CHECK_ENVIRONMENT_VARIABLES


:USAGE
ECHO.
ECHO Usage:  "%0"
ECHO.
ECHO          NOTE:  No arguments are required to build the
ECHO                 %CMS% ldif data classes.
ECHO.
GOTO EXIT_PROCESS


REM
REM  Check presence of user-defined variables
REM

:CHECK_ENVIRONMENT_VARIABLES
IF !%SERVER_ROOT%==! GOTO ENVIRONMENT_VARIABLES_ERROR
IF !%JAVA_HOME%==! GOTO ENVIRONMENT_VARIABLES_ERROR
GOTO CHECK_SERVER_ROOT


:ENVIRONMENT_VARIABLES_ERROR
ECHO ERROR:  Please specify the SERVER_ROOT and JAVA_HOME
ECHO         environment variables for this script!
ECHO.
GOTO EXIT_PROCESS


REM
REM  Check that the specified SERVER_ROOT exists
REM

:CHECK_SERVER_ROOT
IF EXIST %SERVER_ROOT% GOTO CHECK_JAVA_HOME


ECHO ERROR:  The specified SERVER_ROOT does not exist!
ECHO.
GOTO EXIT_PROCESS


REM
REM  Check that the specified JAVA_HOME exists
REM

:CHECK_JAVA_HOME
IF EXIST %JAVA_HOME% GOTO SET_LIBRARY_PATH


ECHO ERROR:  The specified JAVA_HOME does not exist!
ECHO.
GOTO EXIT_PROCESS


REM
REM  Setup the appropriate library path environment variable
REM  based upon the platform (WINNT)
REM

:SET_LIBRARY_PATH
SET PATH=%SERVER_ROOT%\bin\cert\lib;%JAVA_HOME%\bin;%JAVA_HOME%\lib;%PATH%


REM
REM  Set TARGET - identify the complete path to the new classes target directory
REM

SET TARGET=..\classes


REM
REM  Create the new classes target directory (if it does not already exist)
REM

IF EXIST %TARGET% goto COMPILE_CLASSES
MKDIR %TARGET%


REM
REM  Compile TxtTo60 - create "CMS60LdifParser.class", "DummyAuthManager.class",
REM                    and "Main.class"
REM

:COMPILE_CLASSES
%JAVA_HOME%\bin\javac.exe -d %TARGET% -classpath %JAVA_HOME%\jre\lib\rt.jar;%SERVER_ROOT%\bin\cert\jars\nsutil.jar;%SERVER_ROOT%\bin\cert\jars\certsrv.jar;%SERVER_ROOT%\bin\cert\jars\cmscore.jar;%SERVER_ROOT%\bin\cert\jars\jss3.jar Main.java


:EXIT_PROCESS


ENDLOCAL

