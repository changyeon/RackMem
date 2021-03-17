#include <exception>
#include <iostream>
#include <cstring>
#include <thread>
#include <chrono>
#include <fmt/core.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options.hpp>

#include <libkrdma/krdma.hpp>

namespace po = boost::program_options;

int main(int argc, char* argv[])
{
    int ret;
    std::string test;

    try {
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("test,t", po::value<std::string>(&test)->required(),
             "test name")
            ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return EXIT_FAILURE;
        }
        po::notify(vm);
    } catch (std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    fmt::print("RackMem test {}\n", test);

    ret = libkrdma::libkrdma_test();
    if (ret) {
        std::cerr << "error on libkrdma_test" << std::endl;
        return EXIT_FAILURE;
    }

    return 0;
}

