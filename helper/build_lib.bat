@echo off

rem Ensure dub-data-mod is built
cd /D %2
dub build

rem Ensure safearg is built
cd /D %3
dub build

rem Compile
cd /D %1
%2bin\dub-data-mod describe -q --compiler=dmd --config=library --data-0 --data=options --data=versions --data=import-paths | %3bin\safearg --post=src\instauser\basic\package.d rdmd --build-only -lib -od. -of%1lib\instauser-basic.lib --force
