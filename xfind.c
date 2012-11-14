/*
  Copyright (c) 2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/time.h>
#include <attr/xattr.h>
#include <assert.h>
#include <arpa/inet.h>
#include <linux/limits.h>

#include "list.h"

#define THREAD_MAX 32

#define err(x ...) fprintf(stderr, x);
#define out(x ...) fprintf(stdout, x);
#ifdef DEBUG
#define dbg(x ...) fprintf(stdout, x);
#else
#define dbg(x ...)
#endif
#define tout(x ...) do { out("[%ld] ", pthread_self()); out(x); } while (0)
#define terr(x ...) do { err("[%ld] ", pthread_self()); err(x); } while (0)
#define tdbg(x ...) do { dbg("[%ld] ", pthread_self()); dbg(x); } while (0)

#define NEW(x) x = calloc(1, sizeof(typeof(*x)))


char *xtime_key; // set in parse_arg() based on export dir
char *stime_key; // --ditto--


int
get_xtime (const char *path, const char *key, struct timeval *tv)
{
	return 0;

	unsigned int timebuf[2];
	int          ret;

	ret = lgetxattr (path, key, timebuf, sizeof(timebuf));
	if (ret == -1 && errno != ENODATA)
		terr ("lgetxattr(%s,%s): %s\n", path, key, strerror (errno));

	tv->tv_sec = ntohl (timebuf[0]);
	tv->tv_usec = ntohl (timebuf[1]);

	return (ret == sizeof(timebuf)) ? 0 : -1;
}


int
set_xtime (const char *path, const char *key, struct timeval *tv)
{
	return 0;

	unsigned int timebuf[2];
	int          ret;

	timebuf[0] = htonl (tv->tv_sec);
	timebuf[1] = htonl (tv->tv_usec);

	ret = lsetxattr (path, key, timebuf, sizeof(timebuf), 0);
	if (ret)
		terr ("lsetxattr(%s,%s): %s\n", path, key, strerror (errno));

	return ret;
}


struct dirjob {
	struct list_head    list;

	char               *dirname;

	struct dirjob      *parent;
	struct timeval      xtime;
	int                 ret;    /* final status of this subtree */
	int                 refcnt; /* how many dirjobs have this as parent */
	pthread_spinlock_t  lock;
};


struct xwork {
	pthread_t        threads[THREAD_MAX];
	int              count;
	int              idle;
	int              stop;

	struct dirjob    jobs;

	pthread_mutex_t  mutex;
	pthread_cond_t   cond;
};


struct dirjob *
dirjob_ref (struct dirjob *job)
{
	pthread_spin_lock (&job->lock);
	{
		job->refcnt++;
	}
	pthread_spin_unlock (&job->lock);

	return job;
}


void
dirjob_free (struct dirjob *job)
{
	assert (list_empty (&job->list));

	pthread_spin_destroy (&job->lock);
	free (job->dirname);
	free (job);
}


int
dirjob_update (struct dirjob *job)
{
	int ret = 0;

	ret = set_xtime (job->dirname, stime_key, &job->xtime);
	if (ret)
		terr ("set_xtime(%s): %s\n", job->dirname, strerror (errno));

	return ret;
}


void
dirjob_ret (struct dirjob *job, int err)
{
	int            ret = 0;
	int            refcnt = 0;
	struct dirjob *parent = NULL;

	pthread_spin_lock (&job->lock);
	{
		refcnt = --job->refcnt;
		job->ret = (job->ret || err);
	}
	pthread_spin_unlock (&job->lock);

	if (refcnt == 0) {
		ret = job->ret;

		if (ret == 0)
			ret = dirjob_update (job);

		if (ret)
			tdbg ("Finished: %s (%d)\n", job->dirname, ret);

		parent = job->parent;
		if (parent)
			dirjob_ret (parent, ret);

		dirjob_free (job);
		job = NULL;
	}

	return;
}


struct dirjob *
dirjob_new (const char *dir, struct dirjob *parent)
{
	struct dirjob *job = NULL;

	NEW(job);
	if (!job)
		return NULL;

	job->dirname = strdup (dir);
	if (!job->dirname) {
		free (job);
		return NULL;
	}

	INIT_LIST_HEAD(&job->list);
	pthread_spin_init (&job->lock, PTHREAD_PROCESS_PRIVATE);
	job->ret = 0;

	if (parent)
		job->parent = dirjob_ref (parent);

	job->refcnt = 1;

	return job;
}


void
xwork_addjob (struct xwork *xwork, struct dirjob *job)
{
	pthread_mutex_lock (&xwork->mutex);
	{
		list_add_tail (&job->list, &xwork->jobs.list);
		pthread_cond_signal (&xwork->cond);
	}
	pthread_mutex_unlock (&xwork->mutex);

	return;
}

int
xwork_add (struct xwork *xwork, const char *dir, struct dirjob *parent)
{
	struct dirjob *job = NULL;

	job = dirjob_new (dir, parent);
	if (!job)
		return -1;

	xwork_addjob (xwork, job);

	return 0;
}


struct dirjob *
xwork_pick (struct xwork *xwork)
{
	struct dirjob *job = NULL;

	pthread_mutex_lock (&xwork->mutex);
	{
		for (;;) {
			if (xwork->stop)
				goto unlock;

			if (list_empty (&xwork->jobs.list)) {
				if (xwork->count == xwork->idle) {
					/* no outstanding jobs, and no
					   active workers
					*/
					tdbg ("Jobless. Terminating\n");
					xwork->stop = 1;
					pthread_cond_broadcast (&xwork->cond);
					goto unlock;
				}

				xwork->idle++;
				pthread_cond_wait (&xwork->cond, &xwork->mutex);
				xwork->idle--;
				continue;
			}

			job = list_entry (xwork->jobs.list.next,
					  typeof(*job), list);
			list_del_init (&job->list);

			break;
		}
	}
unlock:
	pthread_mutex_unlock (&xwork->mutex);

	return job;
}


int
skip_name (const char *name)
{
	if (strcmp (name, ".") == 0)
		return 1;

	if (strcmp (name, "..") == 0)
		return 1;

	if (strcmp (name, ".glusterfs") == 0)
		return 1;

	return 0;
}


int
skip_mode (struct stat *stat)
{
	if (S_ISREG (stat->st_mode) &&
	    ((stat->st_mode & 07777) == 01000) &&
	    stat->st_size == 0)
		/* linkfile */
		return 1;
	return 0;
}


struct xdirent {
	int            xd_skip;
	ino_t          xd_ino;
	struct stat    xd_stbuf;
	char           xd_name[NAME_MAX+1];
};


int
xworker_crawl (struct xwork *xwork, struct dirjob *job)
{
	DIR            *dirp = NULL;
	struct timeval  stime = {0, };
	struct timeval  xtime = {0, };
	struct timeval  ctime = {0, };
	int             ret = -1;
	int             boff;
	int             plen;
	struct dirent  *result;
	char            dbuf[512];
	char           *path = NULL;
	FILE           *fp = NULL;
	struct xdirent *entries = NULL;
	struct xdirent *rentries = NULL;
	int             ecount = 0;
	int             esize = 0;
	int             i = 0;
	struct dirjob  *cjob = NULL;


	plen = strlen (job->dirname) + 256 + 2;
	path = alloca (plen);

	ret = get_xtime (job->dirname, xtime_key, &job->xtime);
	if (ret) {
		terr ("xtime missing on %s\n", job->dirname);
		goto out;
	}

	ret = get_xtime (job->dirname, stime_key, &stime);
	if (ret) {
		tdbg ("stime missing on %s\n", job->dirname);

		stime.tv_sec = 0;
		stime.tv_usec = 0;
	}

	dirp = opendir (job->dirname);
	if (!dirp) {
		terr ("opendir failed on %s (%s)\n", job->dirname,
		     strerror (errno));
		goto out;
	}

	for (;;) {
		ret = readdir_r (dirp, (struct dirent *)dbuf, &result);
		if (ret) {
			err ("readdir_r(%s): %s\n", job->dirname,
			     strerror (errno));
			goto out;
		}

		if (!result) /* EOF */
			break;

		if (skip_name (result->d_name))
			continue;

		if (!esize) {
			esize = 1024;
			entries = calloc (esize, sizeof (*entries));
			if (!entries) {
				err ("calloc failed\n");
				goto out;
			}
		} else if (esize == ecount) {
			esize += 1024;
			rentries = realloc (entries, esize * sizeof (*entries));
			if (!rentries) {
				err ("realloc failed\n");
				goto out;
			}
			entries = rentries;
		}

		entries[ecount].xd_ino = result->d_ino;
		strncpy (entries[ecount].xd_name, result->d_name, NAME_MAX);
		/* only selectively pick entries. skip by default */
		entries[ecount].xd_skip = 1;
		ecount++;
	}

	int xd_cmp (const void *a, const void *b)
	{
		const struct xdirent *xda = a;
		const struct xdirent *xdb = b;

		return (xda->xd_ino - xdb->xd_ino);
	}

	qsort (entries, ecount, sizeof (*entries), xd_cmp);

	for (i = 0; i < ecount; i++) {
		if (entries[i].xd_ino == 0)
			continue;

		ret = fstatat (dirfd (dirp), entries[i].xd_name,
			       &entries[i].xd_stbuf,
			       AT_SYMLINK_NOFOLLOW);
		if (ret) {
			terr ("lstat(%s): %s\n", path, strerror (errno));
			closedir (dirp);
			return -1;
		}

	}

	boff = sprintf (path, "%s/", job->dirname);

	for (i = 0; i < ecount; i++) {
		if (entries[i].xd_ino == 0)
			continue;

		if (skip_mode (&entries[i].xd_stbuf))
			continue;

		ctime.tv_sec = entries[i].xd_stbuf.st_ctime;
		ctime.tv_usec = entries[i].xd_stbuf.st_ctim.tv_nsec / 1000;

		if (timercmp (&ctime, &stime, <))
			/* if ctime itself is lower than the stime,
			   don't bother with the get_xtime */
			continue;

		strncpy (path + boff, entries[i].xd_name, (plen-boff));

		ret = get_xtime (path, xtime_key, &xtime);
		if (ret == 0) {
			if (timercmp (&xtime, &stime, <))
				continue;
		}

		entries[i].xd_skip = 0;
	}

	for (i = 0; i < ecount; i++) {
		if (entries[i].xd_skip)
			continue;

		strncpy (path + boff, entries[i].xd_name, (plen-boff));

		if (S_ISDIR (entries[i].xd_stbuf.st_mode)) {
			cjob = dirjob_new (path, job);
			if (!cjob) {
				err ("dirjob_new(%s): %s\n",
				     path, strerror (errno));
				ret = -1;
				goto out;
			}

			if (entries[i].xd_stbuf.st_nlink == 2) {
				/* leaf node */
				xwork_addjob (xwork, cjob);
			} else {
				ret = xworker_crawl (xwork, cjob);
				dirjob_ret (cjob, ret);
				if (ret)
					goto out;
			}
			continue;
		}
	}

	ret = 0;
out:
	if (dirp)
		closedir (dirp);
	if (entries)
		free (entries);

	return ret;
}


void *
xworker (void *data)
{
	struct xwork *xwork = data;
	struct dirjob *job = NULL;
	int            ret = -1;

	while ((job = xwork_pick (xwork))) {
		tdbg ("Picked: %s\n", job->dirname);
		ret = xworker_crawl (xwork, job);
		dirjob_ret (job, ret);
	}

	return NULL;
}


int
xwork_fini (struct xwork *xwork, int stop)
{
	int i = 0;
	int ret = 0;
	void *tret = 0;

	pthread_mutex_lock (&xwork->mutex);
	{
		xwork->stop = (xwork->stop || stop);
		pthread_cond_broadcast (&xwork->cond);
	}
	pthread_mutex_unlock (&xwork->mutex);

	for (i = 0; i < xwork->count; i++) {
		pthread_join (xwork->threads[i], &tret);
		out ("Thread id %ld returned %p\n", xwork->threads[i], tret);
	}

	return ret;
}


int
xwork_init (struct xwork *xwork, int count)
{
	int  i = 0;
	int  ret = 0;

	pthread_mutex_init (&xwork->mutex, NULL);
	pthread_cond_init (&xwork->cond, NULL);

	INIT_LIST_HEAD (&xwork->jobs.list);

	xwork_add (xwork, ".", NULL);

	xwork->count = count;
	for (i = 0; i < count; i++) {
		ret = pthread_create (&xwork->threads[i], NULL,
				      xworker, xwork);
		if (ret)
			break;
		out ("Spawned worker %d thread %ld\n", i,
		     xwork->threads[i]);
	}

	return ret;
}


int
xfind (const char *basedir)
{
	struct xwork xwork;
	int          ret = 0;
	char         *cwd = NULL;

	ret = chdir (basedir);
	if (ret) {
		err ("%s: %s\n", basedir, strerror (errno));
		return ret;
	}

	cwd = getcwd (0, 0);
	if (!cwd) {
		err ("getcwd(): %s\n", strerror (errno));
		return -1;
	}

	out ("Working directory: %s\n", cwd);
	free (cwd);

	memset (&xwork, 0, sizeof (xwork));
	ret = xwork_init (&xwork, 0);
	if (ret == 0)
		xworker (&xwork);

	ret = xwork_fini (&xwork, ret);

	return ret;
}


static char *
parse_arg (int argc, char *argv[])
{
	char        *basedir = NULL;
	struct stat  d = {0, };
	int          ret = -1;
	unsigned char volume_id[16];

	if (argc != 2) {
		err ("Usage: %s <DIR>\n", argv[0]);
		return NULL;
	}

	basedir = argv[1];
	ret = lstat (basedir, &d);
	if (ret) {
		err ("%s: %s\n", basedir, strerror (errno));
		return NULL;
	}

	ret = lgetxattr (basedir, "trusted.glusterfs.volume-id",
			 volume_id, 16);
	if (ret != 16) {
		err ("%s: %s\n", basedir, strerror (errno));
		return NULL;
	}

	asprintf (&xtime_key, "trusted.glusterfs."
		  "%02x%02x%02x%02x" "-"
		  "%02x%02x" "-" "%02x%02x" "-" "%02x%02x" "-"
		  "%02x%02x%02x%02x%02x%02x" ".xtime",
		  volume_id[0], volume_id[1], volume_id[2], volume_id[3],
		  volume_id[4], volume_id[5], volume_id[6], volume_id[7],
		  volume_id[8], volume_id[9], volume_id[10], volume_id[11],
		  volume_id[12], volume_id[13], volume_id[14], volume_id[15]);

	out ("Xtime key = '%s'\n", xtime_key);
	asprintf (&stime_key, "trusted.glusterfs."
		  "%02x%02x%02x%02x" "-"
		  "%02x%02x" "-" "%02x%02x" "-" "%02x%02x" "-"
		  "%02x%02x%02x%02x%02x%02x" ".stime",
		  volume_id[0], volume_id[1], volume_id[2], volume_id[3],
		  volume_id[4], volume_id[5], volume_id[6], volume_id[7],
		  volume_id[8], volume_id[9], volume_id[10], volume_id[11],
		  volume_id[12], volume_id[13], volume_id[14], volume_id[15]);

	return basedir;
}


int
main (int argc, char *argv[])
{
	char *basedir = NULL;

	basedir = parse_arg (argc, argv);
	if (!basedir)
		return 1;

	xfind (basedir);

	return 0;
}
