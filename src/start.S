#if defined(__x86_64__)
.text
.global _start
.type _start,@function
_start:
    xor %ebp, %ebp
    mov %rsp, %rdi
    and $-16, %rsp
    call pt_start
    ud2
.size _start, .-_start

.global pt_call
.type pt_call,@function
pt_call:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    mov %r9, %r8
    mov 8(%rsp), %r9
    syscall
    ret
.size pt_call, .-pt_call

.global pt_sigreturn
.type pt_sigreturn,@function
pt_sigreturn:
    mov $15, %rax
    syscall
.size pt_sigreturn, .-pt_sigreturn
#elif defined(__i386__)
.text
.global _start
.type _start,@function
_start:
    xor %ebp, %ebp
    mov %esp, %eax
    and $-16, %esp
    sub $12, %esp
    push %eax
    call pt_start
    ud2
.size _start, .-_start

.global pt_call
.type pt_call,@function
pt_call:
    push %ebp
    push %ebx
    push %esi
    push %edi
    mov 20(%esp), %eax
    mov 24(%esp), %ebx
    mov 28(%esp), %ecx
    mov 32(%esp), %edx
    mov 36(%esp), %esi
    mov 40(%esp), %edi
    mov 44(%esp), %ebp
    int $0x80
    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret
.size pt_call, .-pt_call

.global pt_sigreturn
.type pt_sigreturn,@function
pt_sigreturn:
    /* No SA_SIGINFO: i386 delivers the legacy frame even with rt_sigaction. */
    pop %eax /* Discard signo: sys_sigreturn locates the frame at esp - 8. */
    mov $119, %eax
    int $0x80
.size pt_sigreturn, .-pt_sigreturn
#endif
.section .note.GNU-stack,"",@progbits
