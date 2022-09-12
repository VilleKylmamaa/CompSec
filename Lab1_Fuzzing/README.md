Computer Security Lab 1: Fuzzing
====

## Preliminary tasks

* Create a Github account if you don't already have one
* Create your own fork of the CompSec-2021-AnswerTemplate **as instructed [here](../README.md#instructions)**
* Check the instructions on how to download and use the course's Kali Linux virtual machine
    * If you want to use your own computer, download and install VMWare Player to run the virtual machine. Virtualbox should work also.
* Get familiar with the documentation for the following tools:
    * [Radamsa](https://gitlab.com/akihe/radamsa)
    * [AFL (American Fuzzy Lop)](http://lcamtuf.coredump.cx/afl/)
    * [AddressSanitizer (ASan)](https://github.com/google/sanitizers/wiki/AddressSanitizer)
    * [Valgrind](http://valgrind.org/docs/manual/quick-start.html)


## About the lab

* This document contains task descriptions and theory for the fuzz testing lab. If there are any differences between the return template and this file, consider this to be the up-to-date document.
* **You can use your own computer/virtual machine if you want.** Check the chapter "Prerequisities" for information on what you need to install. This lab has been made to be completed in a Linux environment and tested to work in the provided Kali Linux virtual machine.
* It is estimated that you are able to do Tasks 1-4 during a typical lab session (4 hours).
* __Upper grades for this assignment require that all previous tasks in this assignment have been done as well__, so e.g. in order to get grade 4 you will have to complete tasks 1, 2, 3 & 4.
* Check the deadline from Moodle and __remember that you have to return your name (and possibly people you worked together with) and GitHub repository information to Moodle before the deadline.__


## Background

This week’s theme is fuzzing. Tasks are designed to be done with the provided Kali Linux virtual machine, see the [course mainpage](https://github.com/ouspg/CompSec) for instructions on how to run the virtual machine (VM). The provided Kali VM has all the required tools preinstalled, but if you have your own computer with some other Linux distribution, you are free to use it, just install all the required tools.

In a nutshell, fuzz testing a.k.a. fuzzing is a software testing method that includes feeding malformed and unexpected input data to a program, device, or system. The programs that are used to perform fuzz testing are commonly called fuzzers. The main goal of fuzzing is to make the target system behave *unexpectedly*. From the security perspective, the goal is to find and analyze those unexpected behaviors for possible exploits and figure out how to fix them.

In this exercise you will learn basic usage of 2 common fuzzers; Radamsa and American Fuzzy Lop (AFL). You will also use AddressSanitizer, a memory error detection tool, and Valgrind, a debugging tool (and memory error detector as well), which are often used alongside different fuzzers.

## Prerequisites

A basic understanding of the C programming language is required.

Make yourself familiar with the tools used to complete the exercises:

* **Radamsa** - https://gitlab.com/akihe/radamsa
* **AFL** (American Fuzzy Lop) - http://lcamtuf.coredump.cx/afl/
* **AddressSanitizer** (ASan) - https://github.com/google/sanitizers/wiki/AddressSanitizer
* **Valgrind** - http://valgrind.org/docs/manual/quick-start.html

## Grading

<details><summary>Details</summary>

Task #|Grade/Level|Description|
-----|:---:|-----------|
Task 1 | | Mutated test case generation with Radamsa
Task 2 | 2 | Analyzing a C-program with AddressSanitizer, fuzz testing with AFL
Task 3 | 3 | Creating your own small C-program and fuzz testing it
Task 4 | 4 | Library fuzzing
Task 5 | 5 | Contribute to an existing open-source project. Set up a fuzzer and report findings.

Grade 1 can be acquired by doing mini exam for the corresponding week.
</details>

---

## Task 1

### Generating mutated test cases with Radamsa

**A)** Make yourself familiar with [Radamsa](https://gitlab.com/akihe/radamsa). Try it out in a terminal and print 10 malformed samples of ```Fuzztest 1337``` using *echo*.

**Provide the command line you used to do this.**

Command:

`Fuzztest 1337 | radamsa -n10`

Output:

![image](https://user-images.githubusercontent.com/71127573/188275955-c1689349-c5a1-4fa5-aa37-ba0047424584.png)


Radamsa can also handle various types of files. Next, you have to generate a bunch of *.txt* test samples for later usage. 

**B)** Create a *.txt* file that contains only the text ```12 EF``` and nothing more. Use Radamsa to generate 100 fuzzed samples of the file that are named ```fuzz1.txt```, ```fuzz2.txt```, ```fuzz3.txt```... etc. You should create a separate folder for the samples.

**Provide the content of 2 different samples that radamsa created**

Output:

![image](https://user-images.githubusercontent.com/71127573/188276480-24324e30-e649-41cb-900d-8def117b8733.png)

![image](https://user-images.githubusercontent.com/71127573/188276518-726a2ec4-e57c-4e02-b655-0d5e84d9dcf8.png)

![image](https://user-images.githubusercontent.com/71127573/188276569-72fa2bea-1b8c-4106-80a1-e91dbf194670.png)


**Command line used to create the samples**

Command:

`radamsa fuzz.txt -o fuzz%n.txt -n 100`


---



## Task 2 

### A) Analyzing C program with AddressSanitizer

This repository contains an example C program called [example.c](misc/example.c). Your task is to analyze it using [AddressSanitizer (ASan)](https://github.com/google/sanitizers/wiki/AddressSanitizer). Compile the code with ```clang``` and appropriate [sanitizer flags](https://github.com/google/sanitizers/wiki/AddressSanitizerFlags#compiler-flags). Run the compiled program and analyze what happens.

**Command line used to compile the program**

`clang -fsanitize=address -01 -fno-omit-frame-pointer -g example.c`


**Screenshot of the result after running the program**

![image](https://user-images.githubusercontent.com/71127573/188279289-d1c67770-9087-4176-9a59-e75d839f7ff6.png)


**What is the error and what is causing it in this program?**

`ERROR: LeakSanitizer: detected memory leaks`

The error is that there is a memory leak. Memory is allocated to the buffer: `char * buffer = malloc(1024);` but it is never deallocated.

The error could be fixed by deallocating the memory before finishing the program with: `free(buffer);`. With this addition AddressSanitizer no longer gives the error. 


---
### B) Fuzzing with AFL

In the following task, you will be using [American Fuzzy Lop (AFL)](http://lcamtuf.coredump.cx/afl/) to fuzz test a program called UnRTF. UnRTF is a tool that can be used to convert *.rtf* files to *HTML*, *LaTeX* etc. 

AFL is already installed in the provided Kali Linux virtual machine and the target program's source code is included in this repository ([unrtf0.21.5.tar.xz](misc/unrtf-0.21.5.tar.xz)). When the source code is available, you should instrument the program by using AFL's own wrappers that work as drop-in replacements for **gcc** and **clang** (NOTE: afl-gcc might not work properly in all systems, but it works with the provided Kali Linux vm). 

So, here's what you need to do:

1. **Extract** the source code package ([unrtf0.21.5.tar.xz](misc/unrtf-0.21.5.tar.xz)) and ```cd``` you way to the extracted directory.

2. **Configure** it to use AFL's wrappers:
    ```shell
    ~$ ./configure CC="<add_here>" --prefix=$HOME/unrtf
    ```
    The ```--prefix=$HOME/unrtf``` flag sets the installation location of the binary file to be your home directory. This is recommended, so you don't have to give it access to the root directory.

3. **Compile and build** the program:
    ```shell
    ~$ make
    ~$ make install
    ```

    __Hint__: See AFL [documentation](http://lcamtuf.coredump.cx/afl/README.txt) to learn about instrumenting programs to use AFL compilers.

4. Use AFL's example *.rtf* file located at ```/usr/share/doc/afl++-doc/afl/testcases/others/rtf/small_document.rtf``` to test that your UnRTF works by converting it to HTML:
    ```shell
    ~$ ~/unrtf/bin/unrtf --html /<path>/<to>/<testfile>
    ```

5. Create two folders, one for input files and one for result output. Copy the ```small_document.rtf``` into your input folder.
    ```
    ~$ mkdir <input_folder> <output_folder>
    ~$ cp /<path>/<to>/<testfile> /<path>/<to>/<input_floder>
    ```


6. Start fuzzing UnRTF with AFL using the example ```small_document.rtf``` file as input:
    ```shell
    afl-fuzz -i <input_folder> -o <output_folder> /<path>/<to>/<target_program>
    ```

    __Hint__: See AFL [documentation](http://lcamtuf.coredump.cx/afl/README.txt) on how to start the fuzzer. You are fuzzing the UnRTF binary, which is located at ```~/unrtf/bin/unrtf```.

7. Run the fuzzer until you get at least 50 unique crashes and observe the status window to see what is happening. A good description of the status window can be found [here](http://lcamtuf.coredump.cx/afl/status_screen.txt).

**Command line used to configure unrtf**

`./configure CC=afl-gcc --prefix=$HOME/unrtf`


**Command line used to run AFL**

`afl-fuzz -i ./inputterino -o ./outputteroni ~/unrtf/bin/unrtf`


**Screenshot of the AFL status screen after stopping the fuzzer**

![after-abort](https://user-images.githubusercontent.com/71127573/189041831-41fd99d3-572f-401b-a09d-e0f799c02c69.png)



**What do you think are the most significant pieces of information on the status screen? Why are they important?**

I think saved crashes, i.e. unique crashes, is usually the most important piece of information. There were 51 unique crashes out of 45.5k total in my 9min and 48sec long test. That's 51 interesting cases to study the cause of.

Process timing and cycle progress can be used to figure out how long fuzzing cycles last, i.e. do you need to run the fuzzing for an hour or a whole day for example. Map coverage can inform you if the fuzzing is not very effective: "Be wary of extremes" according to the AFL documentation. Stability in the path geometry section is important if it is showing too low of a percentage. Other than that, it mostly seems extra information for nerds, as the AFL documentation puts it.



---
### C) Reproducing crashes with Valgrind

You should now have found some crashes with the AFL. Next, you need to reproduce one of them to see, what exactly went wrong. You can find the crashes from the output folder you created previously. Make your way into the ```.../<output_folder>/crashes``` and take one of the *.rtf* files that caused a crash under inspection.

Run UnRTF with this file under Valgrind:

```shell
~$ valgrind --leak-check=yes ~/unrtf/bin/unrtf --html /<path>/<to>/<crashfile>
```

__Hint__: Make sure that you are actually running the UnRTF with a crash file! If you get "Error: Cannot open input file" before Valgrind's actual memory analysis output, you are trying to run the program without any input. See the Valgrind [documentation](http://valgrind.org/docs/manual/quick-start.html) for help.



**Take a screenshot of the Valgrind result after running the program**

![image](https://user-images.githubusercontent.com/71127573/189528442-579b7ad4-6d45-4bec-96c1-bf50bd816ad9.png)

The file does not have a `.rtf` suffix but the system identifies it as an `.rtf` file.



**What can you tell about the crash?**

The error points to line 212 in hash.c (`hash_get_string` function):

![image](https://user-images.githubusercontent.com/71127573/189529194-0ed44d2c-2c54-4b3c-8022-f20ccf788b5c.png)

The error also reads "Address 0x11 is not stack'd, malloc'd or (recently) free'd" which would imply a null pointer dereference. It could be fixed by checking for the null pointer.




---

## Task 3

### Fuzz testing your own program

In this task, you will write a small C program and fuzz test it. In task 1, you created a *.txt* file containing ```12 EF``` and 100 malformed samples of it. We will use them in this task. Your program must take a text file as an input and check the file for the following requirements:
- The file contains **two and only two tokens** that are separated with a space
- First token is an **integer**
- Second token is a **string**
- If the content of the text file is as specified above, return 1, otherwise 0

Compile and link your program with AddressSanitizer using appropriate flags.

Run your program with the previously generated 100 test cases. A simple shell script loop, for example, is an easy way to run the test cases. If you don't get enough ASAN outputs with the 100 test cases, try to do the test with 1 000 or 10 000 malformed inputs.



**Provide the C-code of your program**

Specifications asked to check if second token is not a string. I think the specification is unclear because the characters read from a text file will always be a string even if it's all numbers. I added a check that the second token is not all numbers but it's unclear if this is what was meant by the specification.

```C
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char *argv[]) {
    FILE *fp;
    char *filename;
    char ch;

    filename = argv[1];
    fp = fopen(filename, "r");
    char input[99999];

    while ( (ch = fgetc(fp)) != EOF ) {
        strncat(input, &ch, 1);
    }
    printf("Input: %s\n", input);

    char *token;
    token = strtok(input, " ");

    // Allow negative numbers
    if ( token != NULL && token[0] == '-' ) {
        token++; // Skip first char in the following isdigit check
    }
    if ( token != NULL && isdigit(*token) == 0 ) {
        printf("First token is not an integer - return 0\n\n");
        return(0);
    }

    int segmentCount = 0;
    while( token != NULL ) {
        segmentCount++;
        if (segmentCount > 2) {
            printf("Token count is over 2 - return 0\n\n");
            return(0);
        }

        token = strtok(NULL, " ");
        if ( token != NULL && isdigit(*token) != 0 ) {
            printf("Second token is not a string - return 0\n\n");
            return(0);
        }
    }
    if ( segmentCount < 2 ) {
        printf("Token count is less than 2 - return 0\n\n");
        return(0);
    }

    printf("All tests pass - return 1\n\n");
    return(1);
}
```



**Take a screenshot of the AddressSanitizer results after running your program with the test cases. Show at least 3 ASAN outputs.**

These are the only type of errors I get:

ASan error 1:

![image](https://user-images.githubusercontent.com/71127573/189544690-6b5f8617-26a1-4b3c-b459-2abfee382521.png)


ASan error 2:

![image](https://user-images.githubusercontent.com/71127573/189544905-b904c5b8-652a-4f0c-84c6-69f06230f305.png)


ASan error 3:

![image](https://user-images.githubusercontent.com/71127573/189544929-b0b25ac5-ef2e-46e1-b59e-e1a8adb5ebd2.png)



---

## Task 4

### Fuzzing libraries

[OpenSSL](https://www.openssl.org/) is a widely-used open source cryptographic software library for Transport Layer Security and Secure Socket Layer protocols. In 2014, a buffer over-read vulnerability [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) was found in the Heartbeat Extension of OpenSSL (up to version 1.0.1f) two years after the feature was introduced. The vulnerability allowed attackers to obtain memory contents from process memory remotely, and as a result, it compromised the integrity of secure communications.

Since this vulnerability is caused by a memory handling related bug, it is possible to find it using fuzzing tools like AddressSanitizer and AFL. In order to fuzz test the OpenSSL library, we have to have a binary file that uses the library as a fuzzing target. For that, we are going to use the provided [target.c](misc/target.c), which uses OpenSSL to simulate a server-client TLS handshake.

Your task is to do the following:
* **Download and extract the source code** for [OpenSSL 1.0.1f](misc/openssl-1.0.1f.tar.xz).
* **Instrument, compile and build OpenSSL and enable the AddressSanitizer**:
    ```shell
    ~$ AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ ./config -d -g
    ~$ make
    ```
* **Instrument and compile the fuzzing target** and enable AddressSanitizer:
    ```shell
    ~$ AFL_USE_ASAN=1 afl-clang-fast target.c -o target openssl/libssl.a openssl/libcrypto.a -I openssl/include -ldl
    ```
* **Create a dummy certificate**. Use OpenSSL to create for example a 512 bit RSA key. The certificate is only used during fuzzing, so it doesn't matter how secure it is:
    ```
    ~$ openssl req -x509 -newkey rsa:512 -keyout server.key -out server.pem -days 365 -nodes -subj /CN=a/
    ```
* After you have tested that the target program works, **start fuzzing the target program** with AFL:
    ```shell
    ~$ afl-fuzz -i in -o out -m none -t 5000 ./target
    ```
    The bug is rather easy to find, so you should be able to find a crash in less than 10 minutes. Use the ```clienthello``` file as seed for AFL. The file is just a standard SSL hello message that the client sends to the server to initialize a secure session. Create an input folder for AFL and place the file there. TLS/SSL handshake takes longer than just reading input from stdin, so raise the memory limit with ```-m none``` and the timeout limit with ```-t 5000``` just in case.
* **Run the target program with the crash file** you got from the AFL:
    ```shell
    ./target < <crash_file>
    ```
* To see more clearly why the crash occurred, convert the crash file into a *.pcap* file using ```od``` and Wireshark's ```text2pcap```:
    ```shell
    ~$ od -A x -t x1z -v <input_file> | text2pcap -T 443,443 - <output_file>
    ```
    This command can also be used to convert ```clienthello``` to *.pcap*.



**What is the more widely recognized name for this CVE-2014-0160 vulnerability?**

The "Heartbleed" vulnerability.



**What can you tell about the crash based on ASAN results and the pcap file? What is causing the vulnerability?**

The bug is caused by the sent heartbeat request in which the payload length of the request does **not** match the length of the actual data sent. As the length of the payload is longer, the server would then respond with enough data to match the payload's length beyond the intended length of just the message. This would send unintended data from the server's memory to the requester.

ASAN identified this as a heap-buffer-overflow, pointing to `#1 0x4d4b50 in tls1_process_heartbeat /home/kali/Desktop/lab1/task4/openssl/ssl/t1_lib.c:2586:3`. The pcap file has the smarts to red out the payload length:

![image](https://user-images.githubusercontent.com/71127573/189699907-28e0aef8-666f-4dfc-8fde-2cb78357b0df.png)

The bug happens in the file `./openssl/ssl/t1_lib.c` in function `tls1_process_heartbeat`. The length of the payload is read from the request on line 2563: `n2s(p, payload);` and the response to be sent back is copied from the memory using the payload's length on line 2586: `memcpy(bp, pl, payload);`.

![image](https://user-images.githubusercontent.com/71127573/189701406-2e5f9810-944e-4235-bb26-aa8500730c95.png)



**Take a screenshot of the AFL/ASAN results**

![image](https://user-images.githubusercontent.com/71127573/189702223-59d8dc87-9be3-48a0-8523-b074566b23dc.png)

![image](https://user-images.githubusercontent.com/71127573/189672853-0e850398-b802-4cf7-8bf6-a265d0d9ac2f.png)




---

## Task 5

### Contribute to an existing open-source project. Set up a fuzzer and report the whole process and possible findings.

Contribute to some existing open-source software (OSS) project by setting up a fuzzing environment and documenting the total process and results. You can choose the target software by yourself and use one of the 2 fuzzers introduced during the lab exercise, or pick some other that you think serves the purpose better. **You should do all the testing inside a virtual machine in case there are potentially malicious files being handled.**

You should read for example [this guide](https://github.com/ouspg/fuzz-testing-beginners-guide) to get started. Please note that in case a real bug is found in the software, it is very important to document the findings in a way that the issue can be easily reproduced. The guide has some good points about what information you should provide. It is not mandatory for the student to file a "real" bug report, but if you find something new, we highly recommend to do so.

You should grab the most recent version of the source code. Few open-source projects as an example:

- [Chromium](https://www.chromium.org/Home) - An open-source browser project started by Google.
- [VLC media player](https://www.videolan.org/vlc/index.html) - A common open-source media player from VideoLAN. Vast attack surface as the player uses many different libraries to handle audio/video encoding. See [features](https://www.videolan.org/vlc/features.html).
- [ImageMagick](https://www.imagemagick.org/script/index.php) - An open-source suite for displaying, converting, and editing images, supporting over 200 file formats.
- See [American Fuzzy Lop](http://lcamtuf.coredump.cx/afl/) main page for a comprehensive list of tools it has found bugs on. Newer versions of software can spawn new bugs, but the most common tools are usually tested the most so they might not be the best to start with.

You should at minimum to provide the following information in the documentation:
- Which fuzzer was used
- A brief explanation of the target software and why you chose it
 - Are you fuzzing the whole software or some specific part of it? 
 - Is software using some libraries? Are those fuzzed as well?
- Operating system and version information. Version numbers of target software, target software libraries, fuzzer and operating system are very important! Can you explain why?
- Compiler and debugger flags
- Initial test case(s) and the one(s) producing a possible crash
 - Necessary steps to reproduce the crash
- It is not necessary to find any bugs. It is enough, if you can prove that you have fuzzed with good code coverage and they way how input was mutated (=what kind of input fuzzer created overall))
