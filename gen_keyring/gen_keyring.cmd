@echo off
REM -----------------------------------------------------------------
REM Description: generate keyring for package validation
REM $Id: gen_keyring.cmd,v 1.1 2011-04-23 12:34:45 jyliu Exp $
REM -----------------------------------------------------------------

@gpg.exe --no-default-keyring --keyring .\cygwin.gpg --import cygwin.sig
rem gpgv --keyring .\test.pgp setup.ini.sig