#include <iostream>
#include <libkrdma/krdma.hpp>

int main(void)
{
    libkrdma::libkrdma_test();
    std::cout << "remote_alloc test!" << std::endl;
}
