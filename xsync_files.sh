#!/bin/bash

function SSH()
{
    if [ -z "$SHARE_SSH" ]; then
	ssh -qi $SSHKEY \
            -oPasswordAuthentication=no \
            -oStrictHostKeyChecking=no \
	    -oControlMaster=auto \
            -S $SLAVESOCK IDLER.IS.DEAD "$@";
    else
	ssh -qi $SSHKEY
            -oPasswordAuthentication=no \
            -oStrictHostKeyChecking=no \
		"$SLAVEHOST" "$@";
    fi
}


function sync_files()
{
    if [ ! -z "$XFER_XATTR" ]; then
        xatt="--xattr";
    else
        xatt=;
    fi

    tar $xatt -b 128 -C "$SRCDIR" -c --files-from=- | \
	SSH "tar -b 128 -C $SLAVEMOUNT -x";
}

sync_files;
