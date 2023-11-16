# eBPF-Firewall
## Current state
The user-space program ...
* Loads the BPF program into the kernel
* Reads TCP, UDP and ICMP conntrack entries from <code>/proc/net/nf_conntrack</code> and saves them inside the BPF map <code>conntrack</code>
* Attaches the BPF program to all non-virtual interfaces
* Waits for CTRL+C, detaches and unloads the BPF program afterwards

<br>

The kernel/BPF program ...
* Parses the <code>Ethernet</code>, <code>VLAN</code>, <code>IPv4</code>, <code>TCP</code>, <code>UDP</code> and <code>ICMP</code> header
* Checks if a connection entry inside the BPF map <code>conntrack</code> exists
* Prints debug messages to <code>/sys/kernel/debug/tracing/trace_pipe</code>

<br>

## Usage

Compile the XDP/TC kernel program. It will be located at <code>kernel/obj/xdp_fw.o</code> and <code>kernel/obj/tc_fw.o</code>.
<pre>
cd kernel
make
</pre>
<br>

Compile the user-space program. It will be located at <code>user/output/fw</code>. The <code>libbpf</code> library is needed for the compilation.
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
</pre>
<br>

Execute the program. <code>&lt;hook&gt;</code> can be either <code>xdp</code> or <code>tc</code>.
<pre>
./fw &lt;hook&gt; &lt;Path to the XDP/TC program&gt;

# For example
./fw xdp xdp_fw.o
./fw tc tc_fw.o
</pre>
