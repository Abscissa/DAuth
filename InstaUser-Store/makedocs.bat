@echo off
dmd -Isrc -c -op -Dddocs -version=Have_mysql_native -version=Have_vibe_d %* src\instauser\store\package.d src\instauser\core.d src\instauser\store\memory.d src\instauser\store\mysqln.d
del docs\src\instauser\store\index.html > NUL 2> NUL
rename docs\src\instauser\store\package.html index.html
