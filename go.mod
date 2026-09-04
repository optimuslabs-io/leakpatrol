module github.com/optimuslabs-io/leakpatrol

go 1.26

// NO REQUIRE BLOCK. This is deliberate and enforced by `make verify-deps`.
//
// leakpatrol is an incident-response tool that gets copied onto provisioner
// hosts and pods an operator already suspects. Its trust story is "stdlib only,
// read the source". A single third-party dependency would add code we cannot
// audit to a binary whose job is to find someone else's unaudited code -- in a
// tool built for a supply-chain compromise, of all things.
