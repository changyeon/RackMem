#include <iostream>
#include <fmt/core.h>

#include <netdb.h>
#include <netinet/in.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options.hpp>

#include <libkrdma/krdma.hpp>

namespace po = boost::program_options;

static int handle_join_cluster(int fd, std::string &server)
{
    std::string addr = "10.0.0.15";
    libkrdma::krdma_message msg;

    memset(&msg, 0, sizeof(msg));
    msg.cmd = KRDMA_CMD_NODE_INFO;
    server.copy(msg.addr, server.size(), 0);
    addr.copy(msg.addr, addr.size(), 0);
    msg.port = 7472;

    write(fd, &msg, sizeof(msg));

    //libkrdma::libkrdma_accept(addr, msg.port);

    msg.cmd = KRDMA_CMD_EOF;
    write(fd, &msg, sizeof(msg));

    return 0;
}

int run_server(std::string &server, int port)
{
    int ret = 0, fd = 0, opt = 1, backlog = 128;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == 0) {
        perror("failed to create a socket");
        ret = -errno;
        goto out;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("failed to set socket options");
        ret = -errno;
        goto out_close_fd;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("failed to bind the socket");
        ret = -errno;
        goto out_close_fd;
    }

    if (listen(fd, backlog) < 0) {
        perror("failed to call listen on the socket");
        ret = -errno;
        goto out_close_fd;
    }

    libkrdma::krdma_message msg;

    while (true) {
        int len = sizeof(addr);
        int new_fd = accept(fd, (struct sockaddr *) &addr, (socklen_t *) &len);

        if (new_fd < 0) {
            ret = -errno;
            perror("failed to accept the request");
            break;
        }
        read(new_fd, &msg, sizeof(msg));
        switch (msg.cmd) {
        case KRDMA_CMD_JOIN_CLUSTER:
            handle_join_cluster(new_fd, server);
            break;
        case KRDMA_CMD_LEAVE_CLUSTER:
            break;
        default:
            fmt::print("wrong krdma cmd: %d\n", msg.cmd);
            break;
        }
    }

out_close_fd:
    close(fd);
out:
    return ret;
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

    fmt::print("Start a RackMem cluster manager\n");
    fmt::print("listen on ip: {}, port: {}\n", server, port);
    if (run_server(server, port)) {
        fmt::print("Got an error while running RackMem server\n");
        exit(EXIT_FAILURE);
    }
    fmt::print("Terminate server\n");

    return 0;
}
