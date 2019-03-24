# dynamic-linking-statistics

The goal of this repository is to build statistics on dynamic linking, especially against system libraries across various platforms.

On macOS or Windows, the documented process to call the system is to link against system libraries instead of directly using system call instructions.

It seems that compilers such as MSVC link against system libraries in the order they meet the functions in code, if we want to create a dead program generator that looks as closely as possible to human written code we also need to use system functions in the order they are expected to be used. As it is rather compute intensive to perform in-depth code analysis to determine if some imported symbol is ever used at runtime and tell if a program is human written or generated, we can simply dynamically link to system libraries without ever using the functions in the code. The resulting statistics will help us generate sane symbol or import tables that can't be classified as generated.