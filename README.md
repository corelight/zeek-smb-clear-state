smb-clear-state
===============

This package watches the size of the `c$smb_state$pending_cmds` and
`c$smb_state$fid_map` tables.  If the size of those tables grows too large,
they are cleared and a `SMBClearState::BrokenConnection` notice is raised that
marks the connection as broken.

A pcap that raises this notice and is suitable for being added to the public
test suite would be greatly appreciated.

This package may not be needed in future versions of zeek.

## Configuration

### Threshold

`SMBClearState::threshold` - The threshold for `(|c$smb_state$pending_cmds| + |c$smb_state$fid_map|)`.
