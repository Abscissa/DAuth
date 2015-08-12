@echo off

rem Ensure safearg is built
cd /D %3
dub build

rem Compile
echo Compiling/Running instauser-%1 tests...
cd /D %2
dub describe --compiler=dmd --config=tests --data-0 --data=options,versions,import-paths,linker-files | %3bin\safearg --post=src\instauser\%1\package.d rdmd -ofbin\instauser-store-unittests -debug -g -unittest -main --force
