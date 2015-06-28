@echo off

rem Ensure ddox is built
cd /D %2
dub build

rem Build docs
cd /D %1
rdmd -Isrc --build-only --force -c -Dddocs_tmp -X -Xfdocs\docs.json -version=InstaUserBasic_Docs src\instauser\basic\package.d
rmdir /S /Q docs_tmp > NUL 2> NUL
del src\instauser\basic\package.exe
%2\ddox filter docs\docs.json --min-protection=Protected
%2\ddox generate-html docs\docs.json docs\public --navigation-type=ModuleTree
