// package platform holds OS-specific process plumbing used by the simulator
// and the foreground phase 1 agent: process identity snapshots, signals, and
// process groups. linux process snapshots read /proc/<pid>/stat and include
// thread counts; macOS currently uses ps for identity/state without thread
// counts. other platforms return explicit not-implemented errors.
package platform
