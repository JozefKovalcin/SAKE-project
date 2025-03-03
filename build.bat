@echo off
echo Building server...
gcc -Wall -Wextra -O2 -o server.exe server.c monocypher.c siete.c crypto_utils.c -lws2_32 -lbcrypt
if %ERRORLEVEL% neq 0 goto error

echo Building client...
gcc -Wall -Wextra -O2 -o client.exe client.c monocypher.c siete.c crypto_utils.c -lws2_32 -lbcrypt
if %ERRORLEVEL% neq 0 goto error

echo Build successful!
goto end

:error
echo Build failed!
exit /b 1

:end