package eusign

import "time"

const (
	DefaultTSPAddress = "acskidd.gov.ua"
	DefaultTSPPort    = "80"

	DefaultOCSPAddress = "czo.gov.ua"
	DefaultOCSPPort    = "80"
)

// DefaultConnectionsTimeout bounds every network exchange the library makes
// (CMP, OCSP, TSP): connecting and waiting for the response. Without it a
// black-holed server blocks a call until the OS gives up on connect().
const DefaultConnectionsTimeout = 10 * time.Second
