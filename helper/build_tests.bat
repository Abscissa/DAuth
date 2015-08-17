@echo off

rem Ensure safearg is built
cd /D %3
dub build

rem Compile
echo Compiling/Running instauser-%1 tests...
cd /D %2
dub describe --nodeps --compiler=dmd --config=tests --data-0 --data=options,versions,import-paths,linker-files | %3bin\safearg --post=src\instauser\%1\package.d rdmd -Ires -Jres -ofbin\instauser-%1-unittests -debug -g -unittest -main --force
