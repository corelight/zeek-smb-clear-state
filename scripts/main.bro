module SMBState;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        uid:          string &log;
        ts:           time &log;
        id:           conn_id &log;
        duration:     interval &log;
        ver:          count &log;
        ev:           string &log;
        fids:         count &log;
        tids:         count &log;
        uids:         count &log;
        pipes:        count &log;
        pending:      count &log;
        recent:       count &log;
    };
}

event bro_init()
{
    Log::create_stream(LOG, [$columns=Info]);
}

function log_state(c: connection, version: count, ev: string)
{
    local info: Info;
    info$uid = c$uid;
    info$id = c$id;
    info$ts = network_time();
    info$duration = network_time() - c$start_time;
    info$ver = version;
    info$ev = ev;

    info$fids = |c$smb_state$fid_map|;
    info$tids = |c$smb_state$tid_map|;
    info$uids = |c$smb_state$uid_map|;
    info$pipes = |c$smb_state$pipe_map|;
    info$pending = |c$smb_state$pending_cmds|;
    info$recent  = |c$smb_state$recent_files|;
    Log::write(LOG, info);
}

event track(c: connection, version: count, ev: string)
{
    if(!connection_exists(c$id))
        return;

    if(!c?$smb_state)
        return;

    log_state(c, version, ev);
    schedule 30secs { track(c, version, "poll") };
}

event connection_state_remove(c: connection)
{
    if(!c?$smb_state)
        return;
    log_state(c, 0, "remove");
}


event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=10
{
    if (!c?$smb_state )
        schedule 5secs { track(c, 1, "new") };
}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=-10
{
    if (!c?$smb_state )
        schedule 5secs { track(c, 2, "new") };
}