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

    tar $xatt -b 128 -C "$SRCDIR" -c --files-from=- | \
	SSH "tar -b 128 -C $SLAVEMOUNT -x";
}

sync_files;
