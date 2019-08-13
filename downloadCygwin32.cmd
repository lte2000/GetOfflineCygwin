@echo off

C:\Python27\python.exe do_cygwin.py --source http://135.251.50.10/mirrors/cygwin/ --target "d:\temp\cygwin32" --aria2c .\aria2c.exe --setupproxy 127.0.0.1:7070 --skip64 --skipdlexist --validatedigest -vvv

