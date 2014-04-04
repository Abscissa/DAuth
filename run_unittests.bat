@echo off
rdmd -unittest -version=DAuth_AllowWeakSecurity -version=Unittest_DAuth -main --force %* dauth.d
