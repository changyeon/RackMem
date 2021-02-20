#include <exception>
#include <iostream>
#include <cstring>
#include <thread>
#include <chrono>
#include <fmt/core.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options.hpp>

#include <libkrdma/krdma.hpp>

namespace po = boost::program_options;

static int connect_to_server(std::string &server, int port)
{
    int ret = 0, fd = 0;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == 0) {
        perror("failed to create a socket");
        ret = -errno;
        goto out_error;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server.c_str(), &addr.sin_addr) <= 0) {
        perror("failed to conver the ip address");
        ret = -errno;
        goto out_close_fd;
    }

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("failed to connect the server");
        ret = -errno;
        goto out_close_fd;
    }

    return fd;

out_close_fd:
    close(fd);
out_error:
    return ret;
}

static int join_cluster(std::string &server, int port)
{
    int fd;

    if ((fd = connect_to_server(server, port)) < 0) {
        perror("error on connect_to_server");
        return fd;
    }

    libkrdma::krdma_message msg;

    memset(&msg, 0, sizeof(msg));
    msg.cmd = KRDMA_CMD_JOIN_CLUSTER;
    write(fd, &msg, sizeof(msg));

    while (true) {
        read(fd, &msg, sizeof(msg));
        if (msg.cmd == KRDMA_CMD_EOF)
            break;
        fmt::print("[node_info] addr: {}, port: {}\n", msg.addr, msg.port);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        libkrdma::libkrdma_connect(server, msg.port);
    }

    close(fd);

    return 0;
}

int main(int argc, char* argv[])
{
    std::string server = "0.0.0.0";
    int port = 7471;

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

    fmt::print("Connect to RackMem cluster manager\n");
    fmt::print("server ip address: {}, port: {}\n", server, port);

    if (join_cluster(server, port)) {
        fmt::print("failed to process the request\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
