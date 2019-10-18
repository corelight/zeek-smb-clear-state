module SMBClearMemory;

export {
    redef enum Notice::Type += {
        BrokenConnection,
    };
}

event check_memory(c: connection)
{
    if(!connection_exists(c$id))
        return;

    if(!c?$smb_state)
        return;

    local next_sleep = 5mins;

    if (|c$smb_state$pending_cmds| + |c$smb_state$fid_map| > 500) {
        NOTICE([
            $note=BrokenConnection,
            $id=c$id,
            $msg=fmt("Broken smb2 connection detected. pending_cmds=%d, fid_map=%d", |c$smb_state$pending_cmds|, |c$smb_state$fid_map|),
            $n=|c$smb_state$pending_cmds| + |c$smb_state$fid_map|,
            $identifier=c$uid,
        ]);
        c$smb_state$fid_map = table();
        c$smb_state$pending_cmds = table();
        next_sleep = 1mins;
    }
    schedule next_sleep { check_memory(c) };
}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=10
{
    if (!c?$smb_state )
        schedule 60secs { check_memory(c) };
}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=10
{
    if (!c?$smb_state )
        schedule 60secs { check_memory(c) };
}
