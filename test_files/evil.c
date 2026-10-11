#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    printf("cmd.exe /c powershell -enc powershell -nop -c",
    "exec ",
    "system(",
    "eval(",
    "shell_exec(",
    "CreateRemoteThread",
    "VirtualAlloc",
    "WriteProcessMemory",
    "RegSetValueEx",
    "/etc/passwd",
    "/root/.ssh/",
    "id_rsa");
}
