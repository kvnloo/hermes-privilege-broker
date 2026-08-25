#include <unistd.h>
#include <stdlib.h>

int main(void) {
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        sleep(30);
        return 0;
    }
    return 0;
}
