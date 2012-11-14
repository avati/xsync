#!/bin/bash

function SSH()
{
    ssh -qi $SSHKEY \
        -oPasswordAuthentication=no \
        -oStrictHostKeyChecking=no \
	-oControlMaster=auto \
        -S $SLAVESOCK IDLER.IS.DEAD "$@";
}


function sync_files()
{
    if [ "$TAR_FROM_FUSE" = "yes" ]; then
        xatt="--xattr";
    else
        xatt=;
    fi

    tar $xatt -b 128 -C "$SRCDIR/$PFX" -c --files-from=- | \
	SSH "mkdir -p $SLAVEMOUNT/$PFX && tar -b 128 -C $SLAVEMOUNT/$PFX -x";
}

PFX="$1";

sync_files;
