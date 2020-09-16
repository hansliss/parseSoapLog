# parseSoapLog
A soap log parser for logs produced by https://github.com/hansliss/simpleproxy when run as a SOAP proxy for unencrypted, uncompressed traffic.

This monster will parse the logs, extract some header info, handle "Expect: 100-continue" (including some weird cases), and merge multiple
segments of the same request or response into one body, parse the XML, extract a message id using XPath and write out new files using the
message id for grouping.

If you can't see a use for this, that's perfectly normal.
If you prefer carefully structured, extensively tested and well maintained code, you may want to look elsewhere. This is a hack. It has been
tested for a single situation only, because that's where I need it.

Oh, and it pretty much assumes that there's only a single stream of SOAP calls - it won't try to regroup anything. The log files are already
organized by client {IP,port} anyway, so it's a pretty safe assumption for this particular case.

Here's an example call, so you can see what the XPath and namespace parameters look like:
```bash
parseSoapLog -g "/s:Envelope/s:Body/*/ns0:request/ns3:MessageId" -n "s=http://schemas.xmlsoap.org/soap/envelope/ ns0=http://www.systemhuset.com/iec/v1 ns3=http://www.systemhuset.com/iec/data/v1" trace_20200916_192.168.4.10_12345
```
