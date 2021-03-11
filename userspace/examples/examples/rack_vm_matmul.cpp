#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096UL

static int *rand_index = NULL;

static void gemm(unsigned long *A, unsigned long *B, unsigned long *C, int N)
{
    int i, j, k, sum;
    int ri, rj, rk;

    for (i = 0; i < N; i++) {
        for (j = 0; j < N; j++) {
            for (k = 0; k < N; k++) {
                ri = rand_index[i];
                rj = rand_index[j];
                rk = rand_index[k];
                sum = 0;
                sum += (*(A + ri*N + rk)) * (*(B + rk*N + rj));
                *(C + ri*N + rj) = sum;
            }
        }
    }
}

static inline unsigned long getns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (((unsigned long) ts.tv_sec) * 1000000000ULL) + ts.tv_nsec;
}

int main(int argc, char *argv[])
{
    unsigned long *A1 = NULL, *A2 = NULL;
    unsigned long *B1 = NULL, *B2 = NULL;
    unsigned long *C1 = NULL, *C2 = NULL;
    unsigned long array_size = 0, t1, t2;
    unsigned long _tmp = 0;
    int i, j, N;
    int fd = -1;

    if (argc < 2) {
        printf("usage: ./rack_vm_matmul ARRAY_SIZE\n");
        exit(1);
    }

    N = atoi(argv[1]);

    rand_index = (int*) malloc(N * sizeof(*rand_index));
    for (i = 0; i < N; i++)
        rand_index[i] = i;
    for (i = 0; i < N; i++) {
        int ii, jj, tmp;
        ii = rand() % N;
        jj = rand() % N;
        tmp = rand_index[ii];
        rand_index[ii] = rand_index[jj];
        rand_index[jj] = tmp;
    }

    array_size = N * N * sizeof(unsigned long);

    A1 = (unsigned long*) malloc(3 * array_size);
    B1 = A1 + (array_size / sizeof(unsigned long));
    C1 = B1 + (array_size / sizeof(unsigned long));

    /* initiailze array */
    for (i = 0; i < N; i++) {
        for (j = 0; j < N; j++) {
            *(A1 + i*N + j) = i+1;
            *(B1 + i*N + j) = j+1;
            *(C1 + i*N + j) = 1;
        }
    }

    t1 = getns();
    gemm(A1, B1, C1, N);
    t2 = getns();

    printf("1.00 local: %lu\n", (t2 - t1) / 1000000);



    if ((fd = open("/dev/rack_vm", O_RDWR)) < 0) {
        perror("Failed to open the device...");
        return errno;
    }

    _tmp = 3 * array_size;
    _tmp += PAGE_SIZE - _tmp % PAGE_SIZE;

    printf("mmap size: %lu -> %lu, fd: %d\n", 3 * array_size, _tmp, fd);

    A2 = (unsigned long*) mmap(NULL, _tmp, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    B2 = A2 + (array_size / sizeof(unsigned long));
    C2 = B2 + (array_size / sizeof(unsigned long));

    printf("Initialize array\n");

    /* initiailze array */
    for (i = 0; i < N; i++) {
        for (j = 0; j < N; j++) {
            *(A2 + i*N + j) = i+1;
            *(B2 + i*N + j) = j+1;
            *(C2 + i*N + j) = 1;
        }
    }

    t1 = getns();
    gemm(A2, B2, C2, N);
    t2 = getns();

    printf("0.50 local: %lu\n", (t2 - t1) / 1000000);

    if (memcmp(A1, A2, 3 * array_size))
        printf("test failed\n");
    else
        printf("test succeed\n");

    munmap(A2, _tmp);

    return 0;
}
