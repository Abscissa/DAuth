@echo off

rem Usage:
rem   run_unittests -I[path to dauth]\src -I[path to mysqln]\source -I[path to vibed]\source -I[path to deimos libevent2] -I[path to deimos openssl] -version=Vibe*Driver [-g|-gc]

rem Example:
rem   run_unittests -I..\dauth\src -I..\mysqln\source -I..\vibed-0.7.19\source -I..\deimos\libevent2 -I..\deimos\openssl -version=VibeLibeventDriver -g

echo Building/Running non-Vibe.d tests (Phobos sockets)
rdmd -unittest -version=InstaUserStore_Unittest -Isrc -main --force -ofbin\unittests-phobos -version=Have_mysql_native -m32 %* src\instauser\store\package.d

echo Building/Running full Vibe.d tests (Vibe.d sockets)
rdmd -unittest -version=InstaUserStore_Unittest -Isrc -main --force -ofbin\unittests-vibed -version=Have_mysql_native -version=Have_vibe_d ..\vibed-0.7.19\lib\win-i386\eay.lib ..\vibed-0.7.19\lib\win-i386\event2.lib -m32 %* src\instauser\store\package.d
