module SMBClearState;

export {
    redef enum Notice::Type += {
        BrokenConnection,
    };

    ## The threshold for (|c$smb_state$pending_cmds| + |c$smb_state$fid_map|).
    ## If the size of those tables passes the threshold they are cleared and a
    ## connection is logged as broken.
    option threshold = 500;
}

event check_state(c: connection)
{
    if(!connection_exists(c$id))
        return;

    if(!c?$smb_state)
        return;

    local next_sleep = 5mins;

    if (|c$smb_state$pending_cmds| + |c$smb_state$fid_map| > threshold) {
        NOTICE([
            $note=BrokenConnection,
            $id=c$id,
            $msg=fmt("Broken smb2 connection detected. pending_cmds=%d, fid_map=%d", |c$smb_state$pending_cmds|, |c$smb_state$fid_map|),
            $n=|c$smb_state$pending_cmds| + |c$smb_state$fid_map|,
            $identifier=c$uid
        ]);
        c$smb_state$fid_map = table();
        c$smb_state$pending_cmds = table();
        next_sleep = 1mins;
    }
    schedule next_sleep { check_state(c) };
}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=10
{
    if (!c?$smb_state )
        schedule 60secs { check_state(c) };
}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=10
{
    if (!c?$smb_state )
        schedule 60secs { check_state(c) };
}
