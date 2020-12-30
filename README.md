# rewritecap #

[![Go Report Card](https://goreportcard.com/badge/github.com/jordan2175/rewritecap)](https://goreportcard.com/report/github.com/jordan2175/rewritecap)  [![GoDoc](https://godoc.org/github.com/jordan2175/rewritecap?status.png)](https://godoc.org/github.com/jordan2175/rewritecap)

A tool for rebasing a PCAP file, editing layer2 and layer3 addresses, and updating 
ARP packets. PCAP-ng files are not currently supported. This tool will accommodate 
802.1Q tagged frames and Q-in-Q double tagged frames. The timestamp changes allow 
you to rebase the PCAP file to a new date without changing the actual time of day 
or the inter-frame gaps.  You can also timeshift all of the packets by a value in
+/-00h00m00s format.  Multiple timeshifts can be specified at the same time by 
separating them with a comma, thus --time-shift=2h,-3m

I wrote this using Go (golang) v1.8.3

For command line flags run, ./rewritecap --help  

## Binary Releases

I have produced binaries for Mac OSX 10.10.5 and Ubuntu Linux 14.04 64bit (but should work on any 64bit Linux), please look in the releases section for the zip files 

## Installation From Source##

```
go/src/> go get github.com/jordan2175/rewritecap
go/src/> go install github.com/jordan2175/rewritecap/
go/src/> cd github.com/jordan2175/rewritecap
go/src/github.com/jordan2175/rewritecap/> go build rewritecap.go
```

## Usage ##

[See GoDoc](http://godoc.org/github.com/jordan2175/rewritecap) for
documentation and examples.

## Examples ##

```
./rewritecap --help
./rewritecap -f test.pcap -n test2.pacp -y 2016 -m 3 -d 10
./rewritecap -f test.pcap -n test2.pcap --ip4 10.0.2.32 --ip4-new 2.2.2.2 --mac 68:A8:6D:18:36:92 --mac-new 22:33:44:55:66:77
./rewritecap -f test.pcap -n test2.pcap --time-shift=2h1m3s
./rewritecap -f test.pcap -n test2.pcap --time-shift=2h,-1m
```

## Contributing ##

Contributions welcome! Please fork the repository and open a pull request
with your changes or send me a diff patch file.

## License ##

This is free software, licensed under the Apache License, Version 2.0.

