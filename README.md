# edcap

Very tiny pcap manipulator. Something like WireEdit, TraceWrangler but not as ugly and waaaaay more dump;)

### Usage
```bash
  -ctn
        change time now (default true)
  -dbg
        debug
  -idi string
        input dst IP
  -ifn string
        input file name
  -isi string
        input src IP
  -ita string
        input text array
  -odi string
        output dst IP
  -ofn string
        output file name
  -osi string
        output src IP
  -ota string
        output text array
```

### Examples
```bash
# Replace src IP 95.136.3.174 to 1.1.1.1 and write to some_output.pcap
./edcap -isi 95.136.3.174 -osi 1.1.1.1 -ifn some_input.pcap -ofn some_output.pcap

# Same as above plus replace string PUBLISH with INVITE and snom821 with Fritzbox
./edcap -isi 95.136.3.174 -osi 1.1.1.1 -ifn some_input.pcap -ofn some_output.pcap -ita PUBLISH,snom821 -ota INVITE,Fritzbox

```

### TODO
Fix various layer length header to avoid bogus warning.