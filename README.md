# Win32 WLAN

This is a naive, non-official wrapper crate, over the raw win32 WLAN handers,
provided by the [`windows-sys`](https://docs.rs/windows/latest/windows/index.html) crate.

This crate is ought to liberate you from the official ordious FFI.
Tierd of judging `int` represented errors?
Got your rust code poisoned by pre-STL styled CPP vectors?
Try this crate instead.

## TODO

- [ ] 802.11 information frame parsing
- [ ] asynchronous running (current implementation needs to sleep a thread,
      which is not acceptable)
