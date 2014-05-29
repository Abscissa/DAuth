@echo off
dmd -Isrc -c -op -Dddocs -version=Have_mysql_native -version=Have_vibe_d %* src\instauser\package.d src\instauser\core.d src\instauser\store\memory.d src\instauser\store\mysqln.d
del docs\src\instauser\index.html > NUL 2> NUL
rename docs\src\instauser\package.html index.html
