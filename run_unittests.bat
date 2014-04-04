@echo off
rdmd -unittest -version=DAuth_AllowWeakSecurity -version=DAuth_Unittest -main --force %* dauth.d
