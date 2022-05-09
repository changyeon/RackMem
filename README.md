# RackMem
This repository is the implementation of our RackMem paper presented at PACT'20.
* https://dl.acm.org/doi/10.1145/3410463.3414643

RackMem provides transparent remote paging for virtual machines on high-performance networking hardware.
RackMem effectively minimizes paging latency and maximizes paging throughput with unique optimizations for remote paging scenarios.
With RackMem, virtual machines under memory pressure can tolerate performance degradation caused by remote paging.

We implement RackMem as a set of Linux kernel modules.
The three main modules are `krdma`, `rack_dvs`, and `rack_vm`; implements kernel-to-kernel RPC, distributed storage, and virtual memory separately in the kernel space.

## How to build?
RackMem requires header files of a slightly modified Linux kernel to build the kernel modules.
The modified Linux kernel is available [here](https://gitlab.csap.snu.ac.kr/changyeon/linux-rackmem).

In the root of the repository, execute the following commands to build RackMem.

```bash
$ cd modules
$ make
```

Then the following kernel modules are generated.

```bash
$ ls *.ko
dvs_dram.ko  dvs_rdma.ko  krdma.ko  rack_dvs.ko  rack_vm.ko
```

## RackMem Networking (`krdma`)
KRDMA module implements the networking layer of RackMem.
Many components in RackMem rely on KRDMA to communicate remote nodes (e.g., RPC and RDMA).

To load `krdma.ko`, execute the following command.

```bash
$ sudo insmod krdma.ko

Once the module is successfully loaded, you will see the success message in the kernel log as follows.

```bash
$ dmesg

krdma: loading out-of-tree module taints kernel.
krdma: module verification failed: signature and/or required key missing - tainting kernel
krdma: a node name is not given, use the hostname: RDMA-07
krdma: enabling unsafe global rkey
krdma: module loaded: RDMA-07 (0.0.0.0, 7472)
```

### Connecting nodes
After `krdma` module is successfully loaded, we can add remote nodes to the memory pool.
To establish a connection with a remote node, write ("`<ip_addr> <port>`") to the debugfs interface of `krdma`.

```bash
$ echo "10.0.0.18 7472" | sudo tee /sys/kernel/debug/krdma/connect
```

On success, you will see the following messages in the kernel log.

```bash
$ dmesg

krdma: connect addr: 10.0.0.18, port: 7472
krdma: connection established with RDMA-08 (2108593153)
```

## RackMem Distributed Storage (`rack_dvs`)
`rack_dvs` module implements a single storage abstraction of remote and local storages in the cluster.
We have mainly showcased remote memory as the main backend of `rack_dvs`, but you can also add any type of storage as a backend of `rack_dvs`.

The following example shows registering a remote memory backend to `rack_dvs`.

```bash
$ sudo insmod rack_dvs.ko
$ sudo insmod rack_rdma.ko

Similarly, you can add dram backend as follows.

```bash
$ sudo insmod rack_dvs.ko
$ sudo insmod rack_dram.ko
```

On success, you will see the following messages in the kernel log.
```bash
$ dmesg

rack_dvs: rack_dvs: module loaded
dvs_rdma: available nodes: 1
dvs_rdma: node: RDMA-08 (0000000070e53e5b)
dvs_rdma: rack_dvs_rdma: module loaded
```

## RackMem Virtual Memory (`rack_vm`)
Finally, `rack_vm` implements virtual memory on top of `rack_dvs`.
User applications can request a managed space to `rack_vm`, and under memory pressure,
`rack_vm` automatically pages out the local data to remote memory by writing the data with `rack_dvs`.


The following command loads `rack_vm` and limits the number of pages allowed for a user application to 32768.
```bash
$ sudo insmod rack_vm.ko local_pages=32768
```

On success, you will see the following messages in the kernel log.

```bash
$ dmesg
rack_vm: module loaded: (0, 4096, 32768, 67108864)
```

Each number in the parentheses represents `debug_mode`, `page_size`, `local_pages`, and `dvs_slab_size` separately.
All numbers are configurable with `rack_vm` module parameters.

Now we can request a managed space of `rack_vm` by calling `mmap` system call to the device file at `/dev/rack_vm`
```bash
$ ll /dev/rack_vm
crw------- 1 root root 234, 0 Aug 27 02:02 /dev/rack_vm
```

A number of examples using the device file are available in the `example` directory, and we also provide the modified QEMU that allocates VM's memory from RackMem [here](https://gitlab.csap.snu.ac.kr/changyeon/qemu-rackmem).
