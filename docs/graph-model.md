# Evidence graph

Topology and investigation graphs derive from relational observations on demand.
IP nodes connect through application-labelled edges. Edges aggregate actual
flow IDs, which remain inspectable. DNS question nodes show queried domains.
Investigation mode adds IOC and finding relationships. Node selection opens its
entity; edge selection lists underlying flows. React Flow supplies keyboard
selection, zoom and pan. Filters accept host/port/protocol and time range.

Layout groups internal addresses, external addresses, domains/IOCs and findings.
Internal means RFC1918/ULA, not a geolocation or attribution claim. DNS resolver
roles are supported by DNS-labelled traffic rather than guessed from a port.
The graph caps 500 selected flows, 200 DNS rows, 100 IOC links and 100 findings;
counts and limits are shown. Refine filters for dense captures.
