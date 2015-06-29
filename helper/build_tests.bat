@echo off

rem Ensure dub-data-mod is built
cd /D %3
dub build

rem Ensure safearg is built
cd /D %4
dub build

rem Compile
echo Compiling/Running instauser-%1 tests...
cd /D %2
%3bin\dub-data-mod describe --compiler=dmd --config=tests --data-0 --data=options --data=versions --data=import-paths | %4bin\safearg --post=src\instauser\%1\package.d rdmd -unittest -main --force
