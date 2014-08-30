@echo off

rem 'ddox' must be installed and on PATH:
rem https://github.com/rejectedsoftware/ddox

rdmd -Isrc --build-only --force -c -Dddocs_tmp -X -Xfdocs\docs.json src\dauth\package.d
rmdir /S /Q docs_tmp > NUL 2> NUL
del src\dauth\package.exe
ddox generate-html docs\docs.json docs\public
