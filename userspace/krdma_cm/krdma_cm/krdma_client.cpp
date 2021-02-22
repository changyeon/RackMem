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
    std::string server = "0.0.0.0";
    int port = 7472;

    try {
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("server,s", po::value<std::string>(&server)->required(),
             "server address")
            ("port,p", po::value<int>(&port), "port number")
            ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return 1;
        }
        po::notify(vm);
    } catch (std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    fmt::print("Connect to RackMem remote kernel module ({}, {})\n",
               server, port);

    if (libkrdma::libkrdma_connect(server, port)) {
        fmt::print("failed to process the request\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
