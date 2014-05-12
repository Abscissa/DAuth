@echo off
rdmd -Isrc --build-only --force -c -Dddocs src\instauser.d
del docs\index.html > NUL 2> NUL
rename docs\instauser.html index.html
del src\instauser.exe
