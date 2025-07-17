# baby_rev
## presentation
for the L3AK_CTF 2025, I did the baby_rev challenge. 
To solve it, I used IDA free and radare2 (to train myself to use both) and I tried to translate all the assembly code into C code by myself to best understand how it works.

## first block of code in the main

first of all, ida free gives us this first block of code in the main : 

```assembly
endbr64
push    rbp
mov     rbp, rsp
sub     rsp, 10h
mov     edi, 0          ; timer
call    _time
mov     edi, eax        ; seed
call    _srand
mov     eax, 0
call    init_remap
lea     rax, sigint_handler
mov     rsi, rax        ; handler
mov     edi, 2          ; sig
call    _signal
lea     rax, format     ; "Enter flag: "
mov     rdi, rax        ; format
mov     eax, 0
call    _printf
mov     rax, cs:__bss_start
mov     rdi, rax        ; stream
call    _fflush
mov     rax, cs:stdin@GLIBC_2_2_5
mov     rdx, rax        ; stream
mov     esi, 40h ; '@'  ; n
lea     rax, input
mov     rdi, rax        ; s
call    _fgets
mov     [rbp+var_4], 0
jmp     short loc_1502
```

The first lines are easy to translate in c code :
```C
static char input[0x40]; //it's a static char since it's in the .bss section

int main(void){
  srand(time(0));
  // eax = 0 just before our call to init_remap

  init_remap(); // a function made by the user
  signal(2, &sigint_handler);
  printf("Enter flag: ");
  fflush(stdout);
  fgets(input, 0x40, stdin); // 0x40 = 64
  char var_4 = 0; // a stack stored variable
  [...] // we will discover this later ;)
}
```

By looking further into the code, we can discover the flag string : L3AK{ngx_qkt_fgz_ugffq_uxtll_dt}. It seems to be encrypted. The name of the function "init_remap" that is called at the beginning of the main and the structure of the code which seems to loop and then only start to tackle (comparison) operations with above mentioned flag variable can already lead us to emit a hypothesis : maybe our input is encrypted by a substitution function before being compared to the flag. 


## the function init_remap

```assembly
push    rbp
mov     rbp, rsp
mov     [rbp+var_4], 0
jmp     short loc_12B2

loc_129A:
mov     eax, [rbp+var_4]
mov     ecx, eax
mov     eax, [rbp+var_4]
cdqe
lea     rdx, remap
mov     [rax+rdx], cl
add     [rbp+var_4], 1

loc_12B2:
cmp     [rbp+var_4], 7Fh ; 7Fh = 127
jle     short loc_129A
mov     cs:byte_4121, 71h ; 'q'
mov     cs:byte_4122, 77h ; 'w'
mov     cs:byte_4123, 65h ; 'e'
mov     cs:byte_4124, 72h ; 'r'
mov     cs:byte_4125, 74h ; 't'
mov     cs:byte_4126, 79h ; 'y'
mov     cs:byte_4127, 75h ; 'u'
mov     cs:byte_4128, 69h ; 'i'
mov     cs:byte_4129, 6Fh ; 'o'
mov     cs:byte_412A, 70h ; 'p'
mov     cs:byte_412B, 61h ; 'a'
mov     cs:byte_412C, 73h ; 's'
mov     cs:byte_412D, 64h ; 'd'
mov     cs:byte_412E, 66h ; 'f'
mov     cs:byte_412F, 67h ; 'g'
mov     cs:byte_4130, 68h ; 'h'
mov     cs:byte_4131, 6Ah ; 'j'
mov     cs:byte_4132, 6Bh ; 'k'
mov     cs:byte_4133, 6Ch ; 'l'
mov     cs:byte_4134, 7Ah ; 'z'
mov     cs:byte_4135, 78h ; 'x'
mov     cs:byte_4136, 63h ; 'c'
mov     cs:byte_4137, 76h ; 'v'
mov     cs:byte_4138, 62h ; 'b'
mov     cs:byte_4139, 6Eh ; 'n'
mov     cs:byte_413A, 6Dh ; 'm'
nop
pop     rbp
retn
```

first we can see that a variable named var_4 (which has nothing to do with var_4 variable in the main function of course) is initialized to 0.

Then we compare var_4 with 7Fh and we are going to loop in loc_129A until var_4 > 127. That looks like a for loop !
The code in the loop is relatively simple to understand, we get
```C
for (int var_4 = 0; var_4 <= 127; var_4++){
  remap[var_4] = var_4;
}
```

Then, at the index 47 of the remap tab, we place the character q. At index 48, the character w... and so on for all the characters in order on a qwerty keyboard.
Namely and in order : qwertyuiopasdfghjklzxcvbnm

The value of rax should be 128 at the end of this function. It isn't useful. This should be a void function.

So we have now the final code for the function
```C
static char remap[0x61];
void init_remap(){
    for (int var_4 = 0; var_4 <= 127; var_4++){
        remap[var_4] = var_4;
    }
    memncpy(&remap[47], "qwertyuiopasdfghjklzxcvbnm", 26);
// no call to memncpy is made but the code is equivalent
}
```

### starting my python solve script
I tried to recreate the remap variable in python
```python
remap = list(map(chr, range(128)))
keyboard = "qwertyuiopasdfghjklzxcvbnm"
init = 0x4121 - 0x40C0 # the address at which we place the first char minus the beginning of the remap char[]. This gives us the index for the first value of the copy
for i in range(len(keyboard)):
    remap[i+init] = keyboard[i]
print("remap :", remap)
```
I obtained this : 
```
remap : ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\t', '\n', '\x0b', '\x0c', '\r', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'z', 'x', 'c', 'v', 'b', 'n', 'm', '{', '|', '}', '~', '\x7f']
```

That is coherent with what we should find !

## the following code of the main function

Now that we know a bit more about what is happening in the code, we can look at the next part of the main function : the encryption.
Before looking at the code, remember that at the end of the last part of the main, we had a "jmp loc_1502". So the execution starts at loc_1502.
Let's look at this code : 



```assembly
.text:00000000000014C3 loc_14C3:                               ; CODE XREF: main+D6↓j
.text:00000000000014C3                 mov     eax, [rbp+var_4]
.text:00000000000014C6                 cdqe
.text:00000000000014C8                 lea     rdx, input
.text:00000000000014CF                 movzx   eax, byte ptr [rax+rdx]
.text:00000000000014D3                 mov     [rbp+var_5], al
.text:00000000000014D6                 movzx   eax, [rbp+var_5]
.text:00000000000014DA                 test    al, al
.text:00000000000014DC                 js      short loc_14FE
.text:00000000000014DE                 movzx   eax, [rbp+var_5]
.text:00000000000014E2                 cdqe
.text:00000000000014E4                 lea     rdx, remap
.text:00000000000014EB                 movzx   edx, byte ptr [rax+rdx]
.text:00000000000014EF                 mov     eax, [rbp+var_4]
.text:00000000000014F2                 cdqe
.text:00000000000014F4                 lea     rcx, input
.text:00000000000014FB                 mov     [rax+rcx], dl
.text:00000000000014FE
.text:00000000000014FE loc_14FE:                               ; CODE XREF: main+9E↑j
.text:00000000000014FE                 add     [rbp+var_4], 1
.text:0000000000001502
.text:0000000000001502 loc_1502:                               ; CODE XREF: main+83↑j
.text:0000000000001502                 mov     eax, [rbp+var_4]
.text:0000000000001505                 cdqe
.text:0000000000001507                 lea     rdx, input
.text:000000000000150E                 movzx   eax, byte ptr [rax+rdx]
.text:0000000000001512                 test    al, al
.text:0000000000001514                 jnz     short loc_14C3
    ; [...] the end of the code will be tackled in the next and final part :) :)
```


First of all, we can see that input[var_4] (with var_4 initialized at 0 in the first remember) is compared with 0. It's our input (which is a string). This looks like a while which loops on every characters of our input until we reach the '\0' ending char.

Until then , we iterate on loc_14C3.
In loc_14C3, we can see first that we store the in the char var_5 the value input[var_4] 

Then, something interesting happens, we load it in rax and do a test al, al and then look at the SF flag.
The sign flag is set to the value of the MSB of al. What makes this interesting is that in this context, where we manipulate ascii characters, we have every reason to think we are dealing with unsigned char.
As an assembly newbie, I found it interesting to see this use of the sign flag to do comparisons with 127 instead of a simple sign comparison.

If we have indeed a char which ascii representation is above 127, then we will increment our index at loc_14FE and then do another iteration of the loop.

Else, we are going to encrypt this char with this code : input[var_4] = remap[var_5];

Hence, we know the equivalent C code for this part is going to be : 

```C
static char input[0x40]; //it's a static char since it's in the .bss section

int main(void){
  //part 1
  srand(time(0));
  // eax = 0 just before our call to init_remap

  init_remap(); // a function made by the user
  signal(2, &sigint_handler);
  printf("Enter flag: ");
  fflush(stdout);
  fgets(input, 0x40, stdin); // 0x40 = 64
  char var_4 = 0; // a stack stored variable
  // part 2
  char var_5;
  while(input[var4] != '\0') {
    var_5 = input[var_4];
    if (var_5 <= 127) {
        input[var_4] = remap[var_5];
    }
    var_4++;
  }
  // [...] the end of the code will be studied in the last part
}
```

## the end of the main function

We finally arrived to the last part of the code that we are going to study : 

```assembly
.text:0000000000001502 loc_1502:                               ; CODE XREF: main+83↑j
.text:0000000000001502                 mov     eax, [rbp+var_4]
.text:0000000000001505                 cdqe
.text:0000000000001507                 lea     rdx, input
.text:000000000000150E                 movzx   eax, byte ptr [rax+rdx]
.text:0000000000001512                 test    al, al
.text:0000000000001514                 jnz     short loc_14C3
.text:0000000000001516                 lea     rax, flag       ; "L3AK{ngx_qkt_fgz_ugffq_uxtll_dt}"
.text:000000000000151D                 mov     rdi, rax        ; s
.text:0000000000001520                 call    _strlen
.text:0000000000001525                 mov     rdx, rax        ; n
.text:0000000000001528                 lea     rax, flag       ; "L3AK{ngx_qkt_fgz_ugffq_uxtll_dt}"
.text:000000000000152F                 mov     rsi, rax        ; s2
.text:0000000000001532                 lea     rax, input
.text:0000000000001539                 mov     rdi, rax        ; s1
.text:000000000000153C                 call    _strncmp
.text:0000000000001541                 test    eax, eax
.text:0000000000001543                 jnz     short loc_1556
.text:0000000000001545                 lea     rax, s          ; "Correct! Here is your prize."
.text:000000000000154C                 mov     rdi, rax        ; s
.text:000000000000154F                 call    _puts
.text:0000000000001554                 jmp     short loc_1565
.text:0000000000001556 ; ---------------------------------------------------------------------------
.text:0000000000001556
.text:0000000000001556 loc_1556:                               ; CODE XREF: main+105↑j
.text:0000000000001556                 lea     rax, aWrongFlagTryHa ; "Wrong flag. Try harder."
.text:000000000000155D                 mov     rdi, rax        ; s
.text:0000000000001560                 call    _puts
.text:0000000000001565
.text:0000000000001565 loc_1565:                               ; CODE XREF: main+116↑j
.text:0000000000001565                 mov     eax, 0
.text:000000000000156A                 leave
.text:000000000000156B                 retn
.text:000000000000156B ; } // starts at 143E
.text:000000000000156B main            endp
.text:000000000000156B
.text:000000000000156B _text           ends
.text:000000000000156B
```

Actually, we have already study the code until address .text:0000000000001514 (the jnz short loc_14C3 instruction) which is part of the conditionnal part of the while loop.

Then, when the loop is finished, we call a strlen to get the length of the flag.
Then, at the isntruction : text:0000000000001539                 mov     rdi, rax        ; s1
just before we call the function strncmp, we have
  rdi = rax = input (1st argument)
  rsi = flag (2nd argument)
  rdx = the result of the strlen function which we got with rax = strlen("L3AK{ngx_qkt_fgz_ugffq_uxtll_dt}")
  
Hence, this can be translated with strncmp(input, flag, strlen("L3AK{ngx_qkt_fgz_ugffq_uxtll_dt}"))

Then, the test eax, eax instruction enables us to know whether the result of the strncmp was 0 or not. 

If it is different from 0, we jump to loc_1556 (which I rewrote down there) :  

```assembly
.text:0000000000001556 loc_1556:                               ; CODE XREF: main+105↑j
.text:0000000000001556                 lea     rax, aWrongFlagTryHa ; "Wrong flag. Try harder."
.text:000000000000155D                 mov     rdi, rax        ; s
.text:0000000000001560                 call    _puts
```

it is quite easy to understand. We do simply a puts("Wrong flag. Try harder."); Then the flow of execution will lead us to loc_1565 which we will study later (it's very easy).

Else, we continue the normal of execution : 
```assembly
.text:0000000000001545                 lea     rax, s          ; "Correct! Here is your prize."
.text:000000000000154C                 mov     rdi, rax        ; s
.text:000000000000154F                 call    _puts
.text:0000000000001554                 jmp     short loc_1565
```

Once again, this is easy to understand that the equivalent c code is : puts("Correct! Here is your prize.");

Finally, we execute the code at loc_1565 : 
```assembly
.text:0000000000001565 loc_1565:                               ; CODE XREF: main+116↑j
.text:0000000000001565                 mov     eax, 0
.text:000000000000156A                 leave
.text:000000000000156B                 retn
```

This is simply equivalent to a return 0;

We have now finished to study all the code. Here is the final c code equivalent : 

```C

#include <stdio.h>

static char input[0x40]; //it's a static char since it's in the .bss section
static char remap[0x61];

void init_remap(){
    for (int var_4 = 0; var_4 <= 127; var_4++){
        remap[var_4] = var_4;
    }
    memncpy(&remap[47], "qwertyuiopasdfghjklzxcvbnm", 26);
    // no call to memncpy is made but the generated assembly is equivalent
}

int main(void){
  //part 1
  srand(time(0));
  // eax = 0 just before our call to init_remap

  init_remap(); // a function made by the user
  signal(2, &sigint_handler);
  printf("Enter flag: ");
  fflush(stdout);
  fgets(input, 0x40, stdin); // 0x40 = 64
  char var_4 = 0; // a stack stored variable
  // part 2
  char var_5;
  while(input[var4] != '\0') {
    var_5 = input[var_4];
    if (var_5 <= 127) {
        input[var_4] = remap[var_5];
    }
    var_4++;
  }

  // part 3
  if (strncmp(input, flag, strlen("L3AK{ngx_qkt_fgz_ugffq_uxtll_dt}")){
      puts("Wrong flag. Try harder.");
  }else{
      puts("Correct! Here is your prize.");
  }
  return 0;
}
```

sweet ! As you may have understood, this whole thing is probably useless since you can generate decompiled C code with ida free.. However, I like to understand deeply how things work and I thought it would be a good exercise.
## solving the challenge (eventually :') )

As you may have understood, we could have made this a while ago.

```python
# the first part, we already wrote that earlier

remap = list(map(chr, range(128)))
keyboard = "qwertyuiopasdfghjklzxcvbnm"
init = 0x4121 - 0x40C0
for i in range(len(keyboard)):
    remap[i+init] = keyboard[i]

# print("remap :", remap) we don't need this line anymore

# next part:

def decrypt(text):
    result = ""
    for e in text:
        if e not in remap:
            result += e
            continue
        result += chr(remap.index(e))
    return result

print(decrypt("L3AK{ngx_qkt_fgz_ugffq_uxtll_dt}"))
```

We reverse the process to encrypt. Let me explain.
The very part which encrypts one char is this one : 
```C
    // main function line 29, see last part with all the code
    var_5 = input[var_4];
    if (var_5 <= 127) {
        input[var_4] = remap[var_5];
    }
```

Let there be e, the i th char of the text encrypted. remap.index(e) gives us the associated var_5 value in the C code.
As we can see, var_5 = input[var_4]; !
Hence we can just use chr(remap.index(e)) to get back to the original value of input and decrypt the text.

Since throughout all this report, I went into a lot of details, I am also going to explain briefly this part of my python code : 

```python
if e not in remap:
  result += e
  continue
```

That's just because "3", for instance, isn't in remap. So to get the complete key, we need to add it to the final string without any encryption.

Finally, we get the result : L3AK{you_are_not_gonna_guess_me}

