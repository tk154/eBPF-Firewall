# eBPF-Firewall
## Current state
The user-space program ...
* Loads the BPF program into the kernel
* Reads TCP, UDP and ICMP conntrack entries via <code>libnetfilter_conntrack</code> and saves them inside the BPF map <code>conn_map</code>
* Attaches the BPF program to all specified interfaces
* Checks every two seconds inside <code>conn_map</code> ...
    * The BPF program has received a package for a new connection. If yes, lookup the conection via <code>libnetfilter_conntrack</code> and if the connection is established (TCP), mark it inside <code>conn_map</code> as such
    * The BPF program has received a package for an already existing connection. If yes, it updates the conntrack entry timeout via <code>libnetfilter_conntrack</code>
    * An already existing connection has either finsished (TCP FIN, RST) or a timeout has occured. If yes, delete that connection from the BPF map <code>conn_map</code>
* If the user enters CTRL+C, it detaches and unloads the BPF program afterwards

<br>

The kernel/BPF program ...
* Parses the <code>Ethernet</code>, <code>VLAN</code>, <code>IPv4</code>, <code>TCP</code>, <code>UDP</code> and <code>ICMP</code> header
* Checks if a connection entry inside the BPF map <code>conntrack</code> exists
    * If not, it creates a new entry to signal it to the user-space program and passes the package to the network stack
    * If yes ...
        * If the TCP FIN or RST is set, it marks the connection as finished and passes the package to the network stack
        * If the connection isn't established yet, it passes the package to the network stack
        * If the connection is established, it determines via <code>bpf_fib_loopkup</code> if the package is to redirected and where to. Depending on the result, it then routes the package to the next hop, passes the package to the network stack or drops it. The result is cached and saved inside <code>conn_map</code> as long as the connection is alive, ignoring possible routing table changes for now.
* Prints debug messages to <code>/sys/kernel/debug/tracing/trace_pipe</code>

<br>

The following picture illustrates how the forwarding of TCP packages is handled by the user-space and BPF program:
<br><br>
![](https://github.com/tk154/eBPF-Firewall/blob/main/pictures/tcp_conntrack.svg)
<br><br>

## Usage

Compile the XDP/TC kernel program. It will be located at <code>kernel/obj/xdp_fw.o</code> and <code>kernel/obj/tc_fw.o</code>.
<pre>
cd kernel
make
</pre>
<br>

Compile the user-space program. It will be located at <code>user/bin/bpfw</code>.<br>
The <code>libbpf</code> and <code>libnetfilter_conntrack</code> library is needed for the compilation.
<pre>
cd user
make
</pre>
<br>

Cross-Compile the user-space program for OpenWrt. The paths (gcc, toolchain, ...) may need to be adjusted inside <code>user/OpenWrt.mk</code>.
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
./fw &lt;hook&gt; &lt;Path to the XDP/TC program&gt; &lt;Network Interface(s)&gt;

# For example
./fw xdp xdp_fw.o lan1 lan2
./fw tc tc_fw.o lan1 lan2
</pre>
<br>

The following symbols should be set inside OpenWrt's <code>make menuconfig</code>:
<pre>
# For bpf_printk support
CONFIG_KERNEL_KPROBES=y

# For TC support
CONFIG_PACKAGE_kmod-sched-bpf=y
CONFIG_PACKAGE_kmod-sched-core=y
</pre>
