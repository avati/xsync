#!/bin/bash --noediting

##  Copyright (c) 2012 Red Hat, Inc. <http://www.redhat.com/>
##  This file is part of GlusterFS.
##
##  This file is licensed to you under your choice of the GNU Lesser
##  General Public License, version 3 or any later version (LGPLv3 or
##  later), or the GNU General Public License, version 2 (GPLv2), in all
##  cases as published by the Free Software Foundation.


MASTER=            # example, dp-prod-vol
SLAVESPEC=         # example, ssh://remote-host::dp-prod-vol-backup
MOUNT=/unreachable # will get reset in mount_client()
declare -A LOCAL_EXPORTS  # will get set in gather_local_exports
VOLUMEID=

SLAVEHOST=        # extracted from $SLAVESPEC in parse_slave()
SLAVEVOL=         # extracted from $SLAVESPEC in parse_slave()
SLAVEMOUNT=       # mount via idler's cwd in /proc on slave
SLAVEPID=         # pid of slave idler

SSHKEY="/var/lib/glusterd/geo-replication/secret.pem"
MONITOR=          # pid of the monitor
MOUNT=            # /proc/$MONITOR/cwd

TAR_FROM_FUSE=yes  # tar directly from backend or from FUSE mount?

HEARTBEAT_INTERVAL=30  # between idler on salve and master

PIDFILE=/dev/null  # will get set in parse_cli
LOGFILE=/dev/stderr # will get set in parse_cli
STATEFILE=/dev/null # will get set in parse_cli
BRICKS=            # total number of bricks

SRCDIR=            # set to either MOUNT or SCANDIR based on TAR_FROM_FUSE

REPLICA=1
FIXED_REPLICA=${FIXED_REPLICA:-}

#DEBUG=1    # set to 1 to enable debugging
#STATS=1    # set to 1 to enable statistics
#XFER_XATTR=1 # set to 1 to transfer XATTR
SHARE_SSH=${SHARE_SSH:-1} # set to 1 to share SSH sessions
#MB_PER_TAR= # set to 16 or 32 etc.
PARALLEL_TARS=${PARALLEL_TARS:-3}   # maximum number of parallel transfers
FUSE_TIMEOUT=${FUSE_TIMEOUT:-1}
#XFER_MODE=all|none
#DUMMY_UNTAR=1
FIXED_INDEX=${FIXED_INDEX:-}

shopt -s expand_aliases;


function out()
{
    echo "$@" >>$LOGFILE;
}


function msg()
{
    local datefmt="+%Y-%m-%d_%H:%M:%S";
    local lvl=$1;
    shift;
    local line=$1;
    shift;
    out -n "[$BASHPID `date \"$datefmt\"` `basename $0`:$line] $lvl: ";
    out "$@";
}


function __fatal()
{
    msg FATAL "$@";
    exit 1
}


function __warn()
{
    msg WARNING "$@";
}


function __info()
{
    msg INFO "$@";
}


function __dbg()
{
    [ "$DEBUG" = 0 ] && return;

    msg DEBUG "$@";
}


alias fatal='__fatal $LINENO';
alias warn='__warn $LINENO';
alias info='__info $LINENO';
alias dbg='__dbg $LINENO';


function stderr()
{
    echo "$@" >&2;
}


function usage()
{
    echo "Usage: $0 [options] <VOLNAME> <SLAVESPEC>"
    exit 1;
}


function SSHM()
{
    ssh -qi $SSHKEY \
	-oPasswordAuthentication=no \
	-oStrictHostKeyChecking=no \
	-oControlMaster=yes \
	-S $SLAVESOCK "$@";
}

function SSH()
{
    ssh -qi $SSHKEY \
	-oPasswordAuthentication=no \
	-oStrictHostKeyChecking=no \
	-oControlMaster=auto \
	-S $SLAVESOCK IDLER.IS.DEAD "$@";
}


function parse_master()
{
    local vol="$1";
    local status;
    local type;

    status=$(gluster volume info $vol | grep Status: | cut -f2 -d:);
    [ "x$status" = "x" ] && fatal "unable to contact volume $vol";
    [ $status != "Started" ] && fatal "volume $vol is not start ($status)";

    MASTER=$vol

    VOLUMEID=$(gluster volume info $vol | grep 'Volume ID:' | cut -f3 -d' ');
    [ "x$VOLUMEID" = "x" ] && fatal "no volume ID for volume $MASTER";

    if [ -z "$FIXED_REPLICA" ]; then
	if gluster volume info $vol | grep Type: | grep -iq Replicate; then
	    REPLICA=$(gluster volume info $vol | \
		sed -rn 's#Number of Bricks:.*x ([0-9]+) =.*#\1#p');
	fi
    else
	REPLICA=$FIXED_REPLICA;
    fi

    info "Replicas in $vol = $REPLICA";
}


function parse_slave()
{
    local slavespec="$1";
    local slave;
    local next;
    local host;

    slave=$(echo "$slavespec" | sed -nr 's#[^:]+://(.+:.+)#\1#p');
    SLAVEHOST=${slave/:*/};
    next=${slave/*:/};

    if [[ "$next" =~ .*/.* ]]; then
	SLAVEPATH=$next;
	info "Slave path is $SLAVEPATH";
    else
	SLAVEVOL=$next;
	info "Slave volume is $SLAVEVOL";
    fi

    [ "x$SLAVEHOST" = "x" ] && fatal "Invalid SLAVESPEC $1";
    [ "x$SLAVEVOL" = "x" -a "x$SLAVEPATH" = "x" ] && \
	fatal "Invalid SLAVESPEC $1";
}


function abspath()
{
    local path="$1";

    [[ "$path" =~ /.* ]] && echo $path || echo `pwd`/$path;
}


function parse_cli()
{
    local go;

    go=$(getopt -- hi:p:l:s: "$@");
    [ $? -eq 0 ] || exit 1;

    eval set -- $go;

    while [ $# -gt 0 ]; do
	case "$1" in
	    (-h) usage;;
	    (-i) SSHKEY=$2; shift;;
	    (-p) PIDFILE=$2; shift;;
	    (-s) STATEFILE=$2; shift;;
	    (-l) logfile="`abspath $2`"; shift
	    info "Log file: $logfile";
	    LOGFILE=$logfile;
	    info "===========================================================";
	    ;;
	    (--) shift; break;;
	    (-*) stderr "$0: Unrecognized option $1"; usage;;
	    (*) warn "Passing $1" ; break;;
	esac
	shift;
    done

    [ $# -eq 2 ] || usage;

    MASTER="$1";
    SLAVESPEC="$2";

    parse_master "$MASTER";

    parse_slave "$SLAVESPEC";
}


function mount_client()
{
    local T; # temporary mount
    local i; # inode number

    T=$(mktemp -d);

    [ "x$T" = "x" ] && fatal "could not mktemp directory";

    [ -d "$T" ] || fatal "$T: not a directory";

    glusterfs -s localhost --volfile-id $MASTER --client-pid=-1 $T --attribute-timeout=$FUSE_TIMEOUT --entry-timeout=$FUSE_TIMEOUT;

    i=$(stat -c '%i' $T);

    [ "x$i" = "x1" ] || fatal "could not mount volume $MASTER on $T";

    info "Mounted volume $MASTER";

    cd $T;

    umount -l $T || fatal "could not umount $MASTER from $T";

    i=$(stat -c '%i' $T);

    [ "x$i" = "x1" ] && fatal "umount of $MASTER from $T failed?";

    rmdir $T || warn "rmdir of $T failed";

    MOUNT=/proc/$$/cwd/;
    MONITOR=$$;

    info "Monitor PID is $MONITOR";
}


function resolve_ip()
{
    local host;

    host="$1";

    ping -c 1 -w 1 "$host" 2>/dev/null | \
	head -1 | \
	awk '{print $3}' | \
	sed 's/(\(.*\))/\1/g';
}


function is_host_local()
{
    local host;
    local ip;

    host="$1";
    ip=$(resolve_ip "$host");

    [ "x$ip" = "x" ] && return 1;

    ping -I "$ip" -w 1 -c 1 localhost >/dev/null 2>&1
}


function gather_local_exports()
{
    local bricks;
    local brick;
    local host;
    local dir;
    local index;

    info -n "Gathering local bricks ... "
    index=0
    bricks=$(gluster volume info $MASTER | egrep 'Brick[0-9]+:' | cut -f2- -d:);
    for brick in $bricks; do
	host=${brick/:*/};
	dir=${brick/*:/};

	is_host_local $host && LOCAL_EXPORTS[$dir]=$index;

	index=$(($index + 1));
    done

    BRICKS=$index;

    out "${!LOCAL_EXPORTS[*]}";

    if [ "x${!LOCAL_EXPORTS[*]}" = "x" ]; then
	info "No local exports. Bye.";
	exit 0;
    fi
}


function set_stime()
{
    local path="$1";
    local newstime="$2";

    if [ "$newstime" = 0 ]; then
	return;
    fi

    setfattr -h -n "trusted.glusterfs.$VOLUMEID.stime" -v "$newstime" "$path";
}


function get_sxtimes()
{
    local path="$1";
    local key;
    local out;

    _xtime=0;
    _stime=0;

    out=$(getfattr -h -e hex -d -m "trusted.glusterfs.$VOLUMEID.(s|x)time" "$path" 2>/dev/null);

    for l in $out; do
	if ! [[ $l =~ .*=.* ]] ; then
	    continue;
	fi

	key=${l/=*/};
	val=${l/*=/};

	if [ $key = "trusted.glusterfs.$VOLUMEID.xtime" ]; then
	    _xtime=$val;
	fi

	if [ $key = "trusted.glusterfs.$VOLUMEID.stime" ]; then
	    _stime=$val;
	fi
    done

    if [ $_stime = 0 -o $_stime = 0x0 ]; then
	_stime=0;
	out=$(SSH sh -c "'getfattr -h -e hex -d -m trusted.glusterfs.$VOLUMEID.xtime $SLAVEMOUNT/$PFX 2>/dev/null'");
	for l in $out; do
	    if ! [[ $l =~ .*=.* ]] ; then
		continue;
	    fi

	    key=${l/=*/};
	    val=${l/*=/};

	    # yes, remote xtime will be local stime
	    if [ $key = "trusted.glusterfs.$VOLUMEID.xtime" ]; then
		_stime=$val;
	    fi
	done
    fi
}


function greater_than()
{
    local stime="$1"; # format 0x509026d0000ea0cd
    local ctime="$2"; # format 1351849326.0750226530
    local st_sec;
    local st_usec;
    local ct_sec;
    local ct_usec;
    local ct_usectmp;

    st_sec=${stime%????????};
    ct_sec=${ctime/.*/};

    if [[ $st_sec -ne $ct_sec ]]; then
	[[ $st_sec -gt $ct_sec ]];
	return $?
    fi

    st_usec=0x${stime#??????????};

    ct_usec=${ctime/*./};
    ct_usec=${ct_usec%0}; # strip one trailing 0 always

    ct_usectmp=${ct_usec#0};
    while [ "$ct_usectmp" != "$ct_usec" ]; do
	ct_usec=$ct_usectmp;
	ct_usectmp=${ct_usec#0};
    done

    [[ $st_usec -gt $ct_usec ]];
}


function array_nl()
{
    while [ $# -gt 0 ]; do
	echo "$1";
	shift;
    done
}


#
# @pending:
#
# Associative array with keys being directory paths and values being a triplets
# in the format "PENDING_COUNT XTIME_HEX STATUS"
#
# e.g "2 0x509026d0000ea0cd OK"
#     "1 0x339026d0000ea0cd ERR"
#
# When PENDING_COUNT reaches 0, depending on the STATUS either the xtime
# is written to disk as stime (if it is OK) or not, and also propagates
# "upwards" by decrementing the parent directory's PENDING_COUNT (and setting
# ERR if necessary)
#

declare -A pending;

#
# @BG_PIDS
#
# Array indexed by background PID and value the directory on which the
# background worker is processing
#

declare -A BG_PIDS;


function sync_files()
{
    trap 'info Cleaning up transfer; kill $(jobs -p) 2>/dev/null' EXIT;

    local dir=$1;
    shift;
    local files="$@";
    local srcdir;
    local dstdir;
    local xatt;

    if [ "$TAR_FROM_FUSE" = "yes" ]; then
	xatt="--xattr";
    else
	xatt=;
    fi

    array_nl "$@" | \
	tar $xatt -b 128 -C "$SRCDIR/$PFX" -c --files-from=- | \
	SSH "tar -b 128 -C $SLAVEMOUNT/$PFX -x";
}


function throttled_bg()
{
    while [ `jobs -pr | wc -l` -ge $PARALLEL_TARS ]; do
	dbg "Throttling. Waiting for (`jobs -pr | wc -l` / $PARALLEL_TARS) jobs".
	# This is the point of application of "backpressure" from the WAN
	sleep 0.1;
	inc_throttle;
    done

    "$@" &

    BG_PIDS[$!]="$PFX";
    pending_inc "$PFX";
}


function pending_set()
{
    local pfx;

    pfx="$1";

    pending["$pfx"]="1 $2 OK";
}


function pending_inc()
{
    local val;
    local pfx;

    pfx="$1";

    val=${pending["$pfx"]};
    set $val;
    pending["$pfx"]="$(($1 + 1)) $2 $3";
}


function pending_done()
{
    local val;
    local cnt;
    local xtime;
    local pfx;
    local ppfx;
    local s;
    local status;

    pfx="$1";
    s="$2";

    val=${pending["$pfx"]};

    if [ "x$val" = "x" ]; then
	info "ERROR!! $pfx found NULL value!";
	exit 1;
    fi

    set $val;

    cnt=$1;
    xtime=$2;
    status=${s:-$3};

    cnt=$(($cnt - 1));

    pending["$pfx"]="$cnt $xtime $status";

    if [ $cnt -eq 0 ]; then
	unset pending['$pfx'];

	stats_dump;

	# propagate upwards
	if [ "$status" = "OK" ]; then
            # old xtime now becomes new stime, and will match new xtime if
            # no changes happened while we were crawling
	    dbg "Completed: $pfx ($status)";

	    set_stime "${SCANDIR}/$pfx" "$2";
	else
	    info "Failed: $pfx";
	fi

	ppfx="${pfx%/*}";
	[ "$ppfx" = "$pfx" ] && return;

	pending_done "$ppfx" "$status";
    fi

}


function pending_dec()
{
    pending_done "$1" "";
}


function pending_err()
{
    pending_done "$1" "ERR";
}


function reap_bg()
{
    local jobspr;
    local j;
    local b;
    local s;
    local pfx;

    declare -A jobspr;

    for j in `jobs -pr`; do
	jobspr[$j]="r";
    done

    for b in ${!BG_PIDS[@]}; do
	if [ x${jobspr[$b]} = x ]; then
	    # this BG_PID is not running any more
	    wait $b;
	    s=$?;

	    pfx=${BG_PIDS[$b]};
	    unset BG_PIDS[$b];

	    if [ $s -eq 0 ]; then
		# successful remote untar
		pending_dec "$pfx";
	    else
		# failed remote untar
		pending_err "$pfx";
	    fi
	fi
    done
}


TOT_START=0
INT_START=0

TOT_ENTRIES=0
INT_ENTRIES=0

TOT_DIRS=0
INT_DIRS=0

TOT_DESC=0
INT_DESC=0

TOT_FILES=0
INT_FILES=0

TOT_XFER=0
INT_XFER=0

TOT_SIZE=0
INT_SIZE=0

function inc()
{
    val=$1;
    by=${2:-1};

    bump=1;

    eval "TOT_${val}=\$((\$TOT_${val} + $by))";
    eval "INT_${val}=\$((\$INT_${val} + $by))";
}

function inc_entries()
{
    inc ENTRIES;
}

function inc_dirs()
{
    inc DIRS;
}

function inc_desc()
{
    inc DESC;
}

function inc_files()
{
    inc FILES;
}

function inc_xfer()
{
    inc XFER;
}

function inc_size()
{
    inc SIZE $1;
}

function inc_xfer_size()
{
    inc_xfer;
    inc_size $1;
}

function inc_entry()
{
    inc_entries;
    if [ $1 = d ]; then
	inc_dirs;
    else
	inc_files;
    fi
}

function inc_throttle()
{
    inc THROTTLE;
}

function stats_dump()
{
    [ $bump -eq 0 ] && return;
    bump=0;

    now=`date '+%s'`;

    then=$INT_START;
    INT_START=$now;

    (
    cat <<EOF
Field Interval Total
Time $(($now - $then))s $(($now - $TOT_START))s
Scanned_Entries $INT_ENTRIES $TOT_ENTRIES
Scanned_Dirs $INT_DIRS $TOT_DIRS
Descended_Dirs $INT_DESC $TOT_DESC
Scanned_Files $INT_FILES $TOT_FILES
Xfered_Files $INT_XFER $TOT_XFER
Xfered_Size $INT_SIZE $TOT_SIZE
Throttle_CentiSecs $INT_THROTTLE $TOT_THROTTLE
EOF
    ) | column -tc 3
    echo "==========================================="

    INT_START=$now;
    INT_ENTRIES=0
    INT_DIRS=0
    INT_DESC=0
    INT_FILES=0
    INT_XFER=0
    INT_SIZE=0
    INT_THROTTLE=0
}


function stats_wipe()
{
    now=`date '+%s'`;

    TOT_START=$now
    TOT_ENTRIES=0
    TOT_DIRS=0
    TOT_DESC=0
    TOT_FILES=0
    TOT_XFER=0
    TOT_SIZE=0
    TOT_THROTTLE=0

    INT_START=$now;
    INT_ENTRIES=0
    INT_DIRS=0
    INT_DESC=0
    INT_FILES=0
    INT_XFER=0
    INT_SIZE=0
    INT_THROTTLE=0
}


function do_statify()
{
    while [ $# -gt 0 ]; do
	if [ "$STATS" = 0 ]; then
	    eval "unset -f $1";
	    eval "function $1() { true; }";
	fi
	shift;
    done
}


function statify()
{
    do_statify stats_dump stats_wipe
    do_statify inc_entry inc_xfer_size inc_desc inc_throttle;
}


function crawl()
{
    local xtime; # xtime of master
    local stime; # xtime of slave (maintained on master's copy)
    local type;
    local name;
    local ctime;
    local files; # shortlisted
    local dirs; # shortlisted
    local d;
    local dir;
    local pfx;
    local size;
    local mode;
    local ppfx;

    dir="$1";
    pfx="$PFX";
    ppfx="${pfx%/*}";

    get_sxtimes "$dir";

    xtime=$_xtime;
    stime=$_stime;

    if [ "$xtime" = "0" ]; then
	true
	warn "[$BASHPID] missing xtime on $pfx (returning)";
	return;
    fi
    # missing stime is 0 stime


    if [ "$xtime" = "$stime" ]; then
	if [ "$silent" != 1 ]; then
	    info "Nothing to do: $pfx (x,s=$xtime)";
	fi
	if [ "$PFX" = . ]; then
	    silent=1;
	fi
	return 0;
    fi

    silent=0

    # always happens in pair:
    pending_set "$pfx" "$xtime";
    [ "$pfx" != "." ] && pending_inc "$ppfx";

    dbg "Entering: $pfx (x=$xtime,s=$stime)";

    inc_desc;

    local file=/tmp/xsync.$BASHPID.list;

    (cd "$dir"; find . -maxdepth 1 -mindepth 1 -printf "%y:%s:%#m:%C@:=%f\n") > $file;

    if [ "$PFX" = . ]; then
	sort $file > $file.tmp;
	mv $file.tmp $file;
    fi

    files=();
    dirs=();

    ind=0;
    while read line; do
	oldIFS="$IFS";
	IFS=":";
	set $line;
	IFS="$oldIFS";
	type=$1;
	size=$2;
	mode=$3;
	ctime=$4;
	name=${line#*=};

	inc_entry $type;

	[ "$name" = "." ] && continue;

	if [ "$name" = ".glusterfs" -a "$dir" = "$SCANDIR" ]; then
	    # Skipping internal .glusterfs
	    continue;
	fi

	if [ "$mode" = "01000" -a "$size" = "0" -a "$type" = "f" ]; then
	    # Skipping linkfile
	    continue;
	fi

	if [ "$PFX" = . ]; then
	    ind=$(($ind + 1));
	    top_skip $INDEX "$name" $ind && continue;
	fi

	greater_than $stime $ctime && continue;

	if [ "$type" = "d" ]; then

	    dirs+=("$name");

	else
	    inc_xfer_size $size;

	    files+=("$name");
	fi

    done < $file;
    rm -rf $file;

    if [ ${#dirs[@]} -gt 0 ]; then
	# in case directories are missing
	# use cpio to create just the directories without contents
	# (tar cannot do that)
	array_nl "${dirs[@]}" | (cd "$SRCDIR/$PFX" && cpio --quiet --create) | \
		SSH "cd $SLAVEMOUNT/$PFX && cpio --quiet --extract";
    fi

    if [ ${#files[@]} -gt 0 ]; then
	## TODO check for false positives (xtime != ctime)
	## and add a doublecheck if necessary
	throttled_bg sync_files "$dir" "${files[@]}";
    fi

    for d in "${dirs[@]}"; do
	[ "$d" = "." ] && continue

	PFX="$pfx/$d";
	crawl "$dir/$d";
    done

    pending_dec "$pfx";

    reap_bg;

    return 0;
}


function top_skip()
{
    local index=$1;
    local name="$2";
    local ind=$3;

    ## TODO: disable skipping when the other server is down

    if [ $(($index % $REPLICA)) -ne $(($ind % $REPLICA)) ]; then
	info "Skipping $name ($index, $ind, $REPLICA)";
	return 0;
    fi

    return 1;
}


function do_xfind()
{
    WORKERS=$PARALLEL_TARS;
    XFER_CMD="$(dirname $0)/xsync_files.sh"

    export REPLICA
    export INDEX
    export SSHKEY
    export SLAVESOCK
    export SRCDIR
    export SLAVEMOUNT
    export SLAVEHOST
    export TAR_FROM_FUSE
    export STATS
    export DEBUG
    export WORKERS
    export XFER_CMD
    export XFER_XATTR
    export SHARE_SSH
    export MB_PER_TAR
    export DUMMY_UNTAR

    unset PFX;
    $(dirname $0)/xfind $SCANDIR;

}

function worker()
{
    SCANDIR="$1";
    INDEX="$2";
    PFX="."

    info "Worker $INDEX/$BRICKS (R=$REPLICA) with monitor $MONITOR at $SCANDIR";
    trap 'info Cleaning up worker; kill $(jobs -p) 2>/dev/null' EXIT;

    if [ "$TAR_FROM_FUSE" = "yes" ]; then
	SRCDIR=$MOUNT;
    else
	SRCDIR=$SCANDIR;
    fi

    while true; do
	sleep 1;

	if [ -f $(dirname $0)/xfind ]; then
	    do_xfind;
	    continue;
	fi

        # top level PFX _has_ to be "." for pending_{dec,err}() to work
	# it is assumed that if ${p%/*} = $p then we have reached top
	# of the tree.
	PFX=".";
	unset pending[*]; declare -A pending; # start fresh
	unset BG_PIDS[*]; declare -A BG_PIDS;

	stats_wipe;

	crawl "${SCANDIR}";

	while [ ${#BG_PIDS[*]} -ne 0 ]; do
	    reap_bg;
	    sleep 0.1;
	done

	if [ ${#BG_PIDS[*]} -ne 0 -o ${#pending[*]} -ne 0 ]; then
	    warn "!!!BUG!!! non empty pending/BG_PID at end of walk";
	    warn "Pending: ${!pending[*]}";
	    warn "BG_PIDS: ${!BG_PIDS[*]}";
	fi
    done
}


function idler()
{
    local cmd_line;

    cmd_line=$(cat <<EOF
function do_mount() {
v=\$1;
d=\$(mktemp -d 2>/dev/null);
glusterfs -s localhost --xlator-option="*dht.lookup-unhashed=off" --volfile-id \$v --client-pid=-1 --attribute-timeout=$FUSE_TIMEOUT --entry-timeout=$FUSE_TIMEOUT -l /var/log/glusterfs/geo-replication-slaves/slave.log \$d;
cd \$d;
umount -l \$d;
rmdir \$d;
};
cd /tmp;
[ x$SLAVEVOL != x ] && do_mount $SLAVEVOL;
echo SLAVEPID \$BASHPID;
while true; do
    read -t $HEARTBEAT_INTERVAL pong || break;
    echo ping || break;
done
EOF
)
    SSHM $SLAVEHOST bash -c "'$cmd_line'";
}


function keep_idler_busy()
{
    # there is no do/while loop :(
    local T=0;
    local i=0;
    local ping;
    local pong;

    while true; do
	echo ping >&${COPROC[1]} || break;
	read -t $HEARTBEAT_INTERVAL pong <&${COPROC[0]} || break;
	i=$(($i + 1));
	sleep 15;
	echo -n "`hostname -s`-$SLAVEHOST:OK" > $STATEFILE;
    done
    echo -n "`hostname -s`-$SLAVEHOST:NOK" > $STATEFILE;
}


function set_slave_pid()
{
    local line;
    local pid;

    SLAVEPID=

    read line <&${COPROC[0]};

    SLAVEPID=$(echo $line | sed -n 's/^SLAVEPID //p');
}


function monitor()
{
    trap 'info Cleaning up master; kill $(jobs -p) $BASHPID $COPROC_PID 2>/dev/null; echo -n NOK > $STATEFILE' EXIT;

    if [ ! -z "$PIDFILE" ]; then
	exec 300>>$PIDFILE;

	[ $? -ne 0 ] && fatal "Unable to open PIDFILE $PIDFILE";

	flock -xn 300 || fatal "PIDFILE $PIDFILE is busy";

	echo $MONITOR >$PIDFILE;
    fi

    while true; do
	# re-evaluate $RAND for every generation
	SLAVESOCK=/tmp/xsync-$MONITOR-$RANDOM;

	info "Starting idler via $SLAVESOCK for $SLAVEHOST:${SLAVEVOL:-$SLAVEMOUNT}";

	coproc idler;

	set_slave_pid;

	if [ "x$SLAVEPID" = "x" ]; then
	    info "Could not establish connectivity with client";
	    kill $(jobs -p) 2>/dev/null;
	    wait;
	    info "Cleanup done (sleep 60)";
	    sleep 60;
	    continue;
	fi

	if [ "x$SLAVEPATH" != "x" ]; then
	    SLAVEMOUNT=$SLAVEPATH;
	else
	    SLAVEMOUNT=/proc/$SLAVEPID/cwd;
	fi

	info "Slave PID is $SLAVEPID. Path is $SLAVEMOUNT";

	for dir in ${!LOCAL_EXPORTS[*]}; do
	    if [ "x$FIXED_INDEX" != "x" ]; then
		THIS_INDEX=$FIXED_INDEX;
	    else
		THIS_INDEX=${LOCAL_EXPORTS[$dir]};
	    fi
	    worker $dir $THIS_INDEX &
	    sleep 0.1
	done

	keep_idler_busy;

	info "Idler terimnated. Killing workers"

	kill $(jobs -p);

	wait;

	info "Cleanup done (sleep 10)";
	sleep 10;
    done
}


function main()
{
    statify;

    parse_cli "$@";

    gather_local_exports;

    mount_client;

    monitor;
}

main "$@";
