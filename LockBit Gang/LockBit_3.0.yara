rule LockBit_3_0{

meta:

    date = "2023-10-26"
    description = "Detects LockBit 3.0"
    author = "Bilal BAKARTEPE - EchoCTI Malware Team"
    hash = "bbe63d8efc8d8dc7f387b08ee07721ba"
    verdict = "dangerous"
    platform = "windows"

strings:

    $hash1={2D D8 63 77} //ntdll RtlAllocateHeap
    $hash2={54 31 19 c3} //FindFirstFile
    $hash3={23 56 69 4e} //FindNextFile 
    $hash4={8a a5 43 61} //FindClose 
    $hash5={f6 9f 03 19} //MD4Init 
    
    

    $xorkey={f6 9f 03 19} //xor key for hashed API's

    $opc1={55 8B EC 51 52 56 33 C0 8B 55 0C 8B 75 08 AC 33 C9 B9 30 00 00 00 8D 0C 4D 01 00 00 00 02 F1 2A F1 33 C9 B9 06 00 00 00 8D 0C 4D 01 00 00 00 D3 CA 03 D0 90 85 C0 75 D6 8B C2 5E 5A 59 5D} //API name hasher algorithm
    $opc2={55 8B EC 56 57 BE F6 9F FD 66 81 F6 F6 9F 03 19 8D 76 30 8B 7D 08 66 AD 66 85 C0 75 39 66 B8 5C 00  66 AB B8 A5 9F 7A 19 35 F6 9F 03 19 AB B8 85 9F 77 19  35 F6 9F 03 19 AB  B8 93 9F 6E 19  35 F6 9F 03 19  AB B8 C5 9F 31 19  35 F6 9F 03 19 AB 66 33 C0 66 AB EB 04 66 AB EB BC 5F 5E 5D C2 04 00} //deobfuscating "C:\\windows\\system32" string
    $opc3={C7 03 55 60 D6 E6 C7 43 04 27 60 98 E6 C7 43 08 65 60 90 E6 C7 43 0C 09 60 FC E6}//deobfuscating "*.dll" string
    $opc4={55 8B EC 51 52 8B 4D 08 8B 55 0C 90 81 31 F6 9F 03 19 F7 11 90 83 C1 04 4A 75 F1 5A 59 5D} //deobfuscating "*.dll" string together
    $opc5={66 83 F8 41 72 0B 66 83 F8 5A 77 05 66 83 C8 20  90 33 C9 B9 30 00 00 00 8D 0C 4D 01 00 00 00 02 F1 2A F1 33 C9 B9 06 00 00 00 8D 0C 4D 01 00 00 00 D3 CA 03 D0 90 85 C0 75 C3} //Dll name hashing
    $opc6={8B 40 18 F7 40 44 00 00 00 40 74 02 D1 C8}//Heap-based Anti-debug
    $opc7={B9 5D 34 A8 B2 81 F1 F6 9F 03 19 39 48 10 74 01 AB C6 00 B8}//Heap-based Anti-debug

condition:
    any of ($opc*) or (any of ($hash*)and $xorkey)

}



