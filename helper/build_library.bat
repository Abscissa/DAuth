@echo off

rem Ensure safearg is built
cd /D %3
dub build

rem Compile
echo Compiling instauser-%1 library...
cd /D %2
dub describe --nodeps -q --compiler=dmd --config=library --data-0 --data=options --data=versions --data=import-paths | %3bin\safearg --post=src\instauser\%1\package.d rdmd --build-only -lib -Ires -Jres -od. -of%2lib\instauser-%1.lib --force

rem Remove junk that got generated
del package.lib > NUL 2> NUL
