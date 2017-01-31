@echo off
rdmd -unittest -debug -g -version=DAuth_AllowWeakSecurity -version=DAuth_Unittest -Isrc -main --force -ofbin/dauth-unittest %* src\dauth\package.d
