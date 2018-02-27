#include <stdio.h>

int main(int argc, char* argv[])
{
    puts("hello");
    if (argc > 1) {
        puts(argv[1]);
    }
    return 0;
}