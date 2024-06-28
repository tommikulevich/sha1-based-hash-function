# 🔑 SHA-1 Based Hash Function

> ☣ **Warning:** This project was created during my studies for educational purposes only. It may contain non-optimal solutions.

### 🪢 Implementation

Basic implementation was made in **Rust 1.78.0**, using **Cargo** project building and management tool (the same version as Rust). No external libraries were used in the project, with the exception of `colored` library, which was for aesthetic purposes only.
Program reads lines from the standard input, and for each of the lines specifies hash and writes it to the standard output. You can also call tests (using `-t` argument) to verify that the execution is correct.

To start the program, you must call the following commands:
- Compilation: `cargo build --release`
- Launch: `cargo run --release`
- [Optional] Tests execution: `cargo run --release -- -t`

### 👊 Attack

To carry out the attack, a **CUDA C** program was written using NVIDIA GeForce RTX 3050 Ti (4Gb) graphics card and **NVCC 12.5.40** compiler. **GNU Make 4.3** was used to manage the compilation. Each block processed 256 threads, and the grid consisted of 256 such blocks. 
To make it easier to start the program, a `Makefile` script has been prepared. The easiest way is to call the program using the commands:
- Compilation: `make`
- Execution: `make run`

Input data should be stored in `data/attack_cases.txt`, which should contain the following format:
- The first line is the search string (it can be an empty line, because it is not used in the current implementation).
- The second line represents the number of characters to find.
- The third line is the value of hash function for the message length given in the previous line.
- Next lines repeat this format: each pair of consecutive lines contains the number of characters and the corresponding value of hash function, respectively.
