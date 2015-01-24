@echo off
if exist biba.exe (
	del /F biba.exe
)

if [%1] neq [] (
	set gcc=%1
) else (
	set gcc=gcc
)

if not exist %gcc% (
	echo Error: GCC compiler at path '%gcc%' not found. Please, use %0% ^<gcc.exe path^>
) else (
	%gcc% biba.c -o biba -llibeay32
	dir /L /B biba.exe
	echo ^|
	echo done.
)
