@echo off

@gpg.exe --no-default-keyring --keyring .\cygwin.gpg --import cygwin.sig
rem gpgv --keyring .\test.pgp setup.ini.sig