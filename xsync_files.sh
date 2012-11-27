#!/bin/bash

function SSH()
{
    if [ "x$SHARE_SSH" = "x1" ]; then
	ssh -qi $SSHKEY \
            -oPasswordAuthentication=no \
            -oStrictHostKeyChecking=no \
	    -oControlMaster=auto \
            -S $SLAVESOCK IDLER.IS.DEAD "$@";
    else
	ssh -qi $SSHKEY \
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

    if [ -z "$DUMMY_UNTAR" ]; then
	tar $xatt -C "$SRCDIR" -c --files-from=- | \
	    SSH "tar -C $SLAVEMOUNT -x";
    else
	tar $xatt -C "$SRCDIR" -c --files-from=- | \
	    SSH "cat >/dev/null";
    fi
}

sync_files;
