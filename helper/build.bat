@echo off
cd ..\helper\build-config && dub run -q -- %DUB_CONFIG% %*
