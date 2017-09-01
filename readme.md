## What
Swine is an NT executable unpacker. It reads an exe file and outputs a directory of files corresponding to each section of the executable. It can also read in this directory to recreate the original executable.

## How
```
swine.exe \windows\system32\notepad.exe test.d

cd test.d

ls
drwxrwxrwx                  4096        2017-09-01 10:56:40     dos
drwxrwxrwx                  4096        2017-09-01 10:56:40     hdr
drwxrwxrwx                  4096        2017-09-01 10:56:40     opthdr64
drwxrwxrwx                  4096        2017-09-01 10:56:41     section

cat section\.text\data\dis
140002e7a MOVL $0x2, 0x6c(SP)
140002e82 CALL 0x17cf0(IP)
140002e88 TESTL AX, AX
140002e8a JE 0x140002f23
140002e90 TESTQ DI, DI
140002e93 JE 0x140002ea8
140002e95 MOVL $0x104, DX
140002e9a MOVQ DI, CX
140002e9d CALL 0x18055(IP)
140002ea3 MOVQ AX, BX
140002ea6 JMP 0x140002eaa
140002ea8 XORL BX, BX
140002eaa MOVQ SI, DX
140002ead LEAQ -0x30(BP), CX
140002eb1 CALL 0x18041(IP)
140002eb7 MOVL $0x40, CX
140002ebc LEAL 0x1(AX), SI
140002ebf ADDL BX, SI
140002ec1 MOVSXD SI, DX
140002ec4 ADDQ DX, DX
140002ec7 CALL 0x17a3b(IP)
140002ecd MOVQ AX, BX
140002ed0 TESTQ AX, AX
140002ed3 JE 0x140002f23
140002ed5 MOVL SI, R9
140002ed8 LEAQ -0x30(BP), CX
140002edc MOVQ AX, R8
```
## Why
It's fun
