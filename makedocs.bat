@echo off
rdmd -Isrc --build-only --force -c -Dddocs src\instauser\package.d
del docs\index.html > NUL 2> NUL
rename docs\instauser\package.html index.html
del src\instauser\package.exe
