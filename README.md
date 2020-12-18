# getCodeSection
Get section header and print .text

Calculated with MD5

Command : getCodeSection.exe [pid]

Comparison of code sections in process file(pid) and dlls


# testtt
후킹된 프로세스의 exe파일과 모든 dll파일의 코드섹션을 가져옵니다.
그리고 MD5로 해싱을 한 후, 메모장에 저장합니다.
-> 위 파일과, WriteProcessMemory() 타이밍의 코드섹션 해시값을 비교하려했습니다.

