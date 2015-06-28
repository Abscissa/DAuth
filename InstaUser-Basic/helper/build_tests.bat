@echo off

rem Ensure dub-data-mod is built
cd /D %2
dub build

rem Ensure safearg is built
cd /D %3
dub build

rem Compile
cd /D %1
%2bin\dub-data-mod describe --compiler=dmd --config=tests --data-0 --data=options --data=versions --data=import-paths | %3bin\safearg --post=src\instauser\basic\package.d rdmd -unittest -main --force
