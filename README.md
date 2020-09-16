# parseSoapLog
A soap log parser for logs produced by https://github.com/hansliss/simpleproxy when run as a SOAP proxy for unencrypted, uncompressed traffic.

This monster will parse the logs, extract some header info, handle "Expect: 100-continue" (including some weird cases), and merge multiple
segments of the same request or response into one body, parse the XML, extract a message id using XPath and write out new files using the
message id for grouping.

If you can't see a use for this, that's perfectly normal.
If you prefer carefully structured, extensively tested and well maintained code, you may want to look elsewhere. This is a hack. It has been
tested for a single situation only, because that's where I need it.

TODO: There's no reason to parse everything first and store it in memory, and then print it out. This will be fixed when I feel like it.
Probably fairly soon, because this thing is much slower and more resource-hungry that it should be.
