# eBPF-Firewall
## Current state
The user-space program ...
* Loads the BPF program into the kernel
* Reads TCP and UDP conntrack entries (incl. NAT information) via <code>libnetfilter_conntrack</code> and offloads them to the BPF program via the BPF map <code>conn_map</code>
* Attaches the BPF program to all specified interfaces
* Polls <code>conn_map</code> and checks if ...
    * The BPF program has received a package for a new (not yet offloaded) connection. If yes, lookup the connection (incl. NAT information) via <code>libnetfilter_conntrack</code>, and if it is found, offload it to the BPF program
    * The BPF program has received a new package for an already offloaded connection. If yes, it updates the conntrack entry timeout via <code>libnetfilter_conntrack</code>
    * An already existing connection has either finished (TCP FIN, RST) or a timeout has occurred. If yes, delete that connection from the BPF map <code>conn_map</code> so that the network stack can take over again
* If a SIGINT or SIGTERM occurs, it detaches and unloads the BPF program afterward

<br>

The kernel/BPF program ...
* Parses the <code>Ethernet</code>, <code>VLAN</code>, <code>IPv4</code>, <code>TCP</code> and <code>UDP</code> header
* Checks if a connection entry inside the BPF map <code>conntrack</code> exists
    * If not, it creates a new entry to signal the user-space program and passes the package to the network stack (for now)
    * If yes ...
        * If the connection isn't marked as offloaded yet, it passes the package to the network stack
        * If the connection is marked as offloaded, it determines via <code>bpf_fib_loopkup</code> if the package is to be redirected and where to. Depending on the result, it then applies NAT and routes the package to the next hop, passes the package to the network stack, or drops it. The next hop is cached as long as the connection is alive, ignoring possible routing table changes for now.
        * If the TCP FIN or RST is set, it marks the connection as finished and passes the package again to the network stack
* Prints debug messages to <code>/sys/kernel/debug/tracing/trace_pipe</code>

<br>

## Usage

Compile the XDP/TC BPF program. This creates four BPF objects (for the XDP and TC hook and little and big-endian machines) which will be located under <code>kernel/obj/</code>.
<pre>
cd kernel
make
</pre>
<br>

Compile the user-space program. It will be located at <code>user/bin/bpfw</code>.<br>
The <code>libbpf</code> and <code>libnetfilter_conntrack</code> libraries are needed for the compilation.
<pre>
cd user
make
</pre>
<br>

Cross-compile the user-space program for OpenWrt. The paths (gcc, toolchain, ...) may need to be adjusted inside <code>user/OpenWrt.mk</code>.
<pre>
cd user
make OPENWRT_DIR=&lt;Path to the OpenWrt root directory&gt; TARGET=&lt;OpenWrt Target&gt;

# For example
make OPENWRT_DIR=~/openwrt TARGET=x86_64
make OPENWRT_DIR=~/openwrt TARGET=aarch64
</pre>
<br>

Execute the program. <code>&lt;hook&gt;</code> can be either <code>xdp</code> or <code>tc</code>.
<pre>
./bpfw &lt;hook&gt; &lt;Path to the XDP/TC program&gt; &lt;Network Interfaces&gt;

# For example
./bpfw xdp xdp_le_bpfw.o lan1 lan2
./bpfw tc tc_be_bpfw.o lan1 lan2
</pre>
<br>

The following symbols should be set inside OpenWrt's <code>make menuconfig</code>:
<pre>
# For bpf_printk (debugging) support
CONFIG_KERNEL_KPROBES=y

# For TC support
CONFIG_PACKAGE_kmod-sched-bpf=y
CONFIG_PACKAGE_kmod-sched-core=y

# Needed libraries for the user-space program
CONFIG_PACKAGE_libbpf=y
CONFIG_PACKAGE_libnetfilter-conntrack=y
</pre>
