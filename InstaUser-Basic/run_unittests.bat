@echo off
rdmd -unittest -debug -g -version=InstaUser_AllowWeakSecurity -version=InstaUserBasic_Unittest -Isrc -main --force %* src\instauser\basic\package.d
