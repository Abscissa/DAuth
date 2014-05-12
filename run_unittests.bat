@echo off
rdmd -unittest -version=InstaUser_Unittest -Isrc -main --force %* src\instauser.d
