#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) {
    int total = 0;
    for (int i = 0; i < 5; i++) total = add(total, i);
    printf("total = %d\n", total);
    return 0;
}
