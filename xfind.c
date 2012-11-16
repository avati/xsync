/*
  Copyright (c) 2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/


/*
  - stats
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
#include <sys/wait.h>

#include "list.h"

#define THREAD_MAX 32

#define err(x ...) fprintf(stderr, x);
#define out(x ...) fprintf(stdout, x);
#define dbg(x ...) do { if (DEBUG) fprintf(stdout, x); } while (0)
#define tout(x ...) do { out("[%ld] ", pthread_self()); out(x); } while (0)
#define terr(x ...) do { err("[%ld] ", pthread_self()); err(x); } while (0)
#define tdbg(x ...) do { dbg("[%ld] ", pthread_self()); dbg(x); } while (0)


struct stats {
	struct timeval start;
	int  cnt_encountered_files;
	int  cnt_encountered_dirs;
	int  cnt_encountered_leafs;
	int  cnt_shortlist_files;
	int  cnt_shortlist_dirs;

	int  cnt_scanned_dirs;

	int  cnt_xfered_files;
	long long int cnt_xfered_bytes;
	int  cnt_xfer_execs;
};
int stats_bumped;

pthread_spinlock_t stats_lock;
struct stats stats_interval;
struct stats stats_total;
int STATS;

#define INC(name, val) do {				\
	if (!STATS)				        \
		break;					\
	pthread_spin_lock(&stats_lock);			\
	{						\
		stats_interval.cnt_##name += val;	\
		stats_total.cnt_##name += val;		\
		stats_bumped = 1;			\
	}						\
	pthread_spin_unlock(&stats_lock);		\
	} while (0)

void
stats_dump(int force)
{
	struct timeval now;
	struct timeval idiff;
	struct timeval tdiff;
	struct stats interval;
	struct stats total;
	int          dump = 0;

	if (!STATS)
		return;

	if (!stats_bumped)
		return;

	gettimeofday (&now, 0);

	pthread_spin_lock(&stats_lock);
	{
		if (!stats_bumped)
			goto unlock;

		timersub(&now, &stats_interval.start, &idiff);

		if (idiff.tv_sec < 5 && !force)
			goto unlock;

		dump = 1;

		interval = stats_interval;
		total = stats_total;
		memset (&stats_interval, 0, sizeof(struct stats));
		stats_interval.start = now;
	}
unlock:
	pthread_spin_unlock(&stats_lock);

	if (!dump)
		return;
/*
	struct timeval start;
	int  cnt_encountered_files;
	int  cnt_encountered_dirs;
	int  cnt_encountered_leafs;
	int  cnt_shortlist_files;
	int  cnt_shortlist_dirs;

	int  cnt_scanned_dirs;

	int  cnt_xfered_files;
	long long int cnt_xfered_bytes;
	int  cnt_xfer_execs;
*/
	timersub (&now, &total.start, &tdiff);

	tout("-------------------------------------------\n");
	tout("Field                 Interval      Total\n");
	tout("Time_Sec          : %10ld %10ld\n",
	     idiff.tv_sec, tdiff.tv_sec);
	tout("Encountered_Files : %10d %10d\n",
	     interval.cnt_encountered_files, total.cnt_encountered_files);
	tout("Encountered_Dirs  : %10d %10d\n",
	     interval.cnt_encountered_dirs, total.cnt_encountered_dirs);
	tout("Encountered_Leafs : %10d %10d\n",
	     interval.cnt_encountered_leafs, total.cnt_encountered_leafs);
	tout("Shortlist_Files   : %10d %10d\n",
	     interval.cnt_shortlist_files, total.cnt_shortlist_files);
	tout("Shortlist_Dirs    : %10d %10d\n",
	     interval.cnt_shortlist_dirs, total.cnt_shortlist_dirs);
	tout("Scanned_Dirs      : %10d %10d\n",
	     interval.cnt_scanned_dirs, total.cnt_scanned_dirs);
	tout("Transferred_Files : %10d %10d\n",
	     interval.cnt_xfered_files, total.cnt_xfered_files);
	tout("Transferred_Bytes : %10lld %10lld\n",
	     interval.cnt_xfered_bytes, total.cnt_xfered_bytes);
	tout("Transfer_Count    : %10d %10d\n",
	     interval.cnt_xfer_execs, total.cnt_xfer_execs);
	tout("Throughput MB/s   : %10lld %10lld\n",
	     (interval.cnt_xfered_bytes / (1048586 * (idiff.tv_sec?idiff.tv_sec:1))),
	     (total.cnt_xfered_bytes / (1048586 * (tdiff.tv_sec?tdiff.tv_sec:1))));
	tout("-------------------------------------------\n");
}

#define BUMP(name) INC(name, 1)

#define DEFAULT_WORKERS 2

int XFER_MODE; /* 0=default -1=none 1=all */

/* ENV variables */
int DEBUG;

int REPLICA;
int INDEX;
int WORKERS;
int MB_PER_TAR;

#define DEFAULT_XFER_CMD "false"

char *XFER_CMD;

char *BASEDIR;

int
setenvint(const char *str, int *intp)
{
	char *val = NULL;
	int  i = 0;

	val = getenv (str);
	if (!val)
		return -1;

	i = atoi(val);

	if (intp)
		*intp = i;
	return 0;
}


char *
setenvstr(const char *str, char **strp)
{
	char *val = NULL;

	val = getenv (str);
	if (!val)
		return NULL;

	if (strp)
		*strp = val;

	return val;
}


#define NEW(x) x = calloc(1, sizeof(typeof(*x)))


char *xtime_key; // set in parse_arg() based on export dir
char *stime_key; // --ditto--


int
get_xtime (const char *path, const char *key, struct timeval *tv)
{
	unsigned int timebuf[2];
	int          ret;

	ret = lgetxattr (path, key, timebuf, sizeof(timebuf));
	if (ret == -1) {
		if (errno != ENODATA)
			terr ("lgetxattr(%s,%s): %s\n", path, key,
			      strerror (errno));
		return ret;
	}

	tv->tv_sec = ntohl (timebuf[0]);
	tv->tv_usec = ntohl (timebuf[1]);

	return (ret == sizeof(timebuf)) ? 0 : -1;
}


int
set_xtime (const char *path, const char *key, struct timeval *tv)
{
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
	struct timeval      stime;
	int                 ret;    /* final status of this subtree */
	int                 refcnt; /* how many dirjobs have this as parent */

	int                 filecnt;
	int                 dircnt;
	long long int       filesize;

	struct xdirent     *entries;
	struct list_head    files;  /* xdirents of shortlisted files */
	struct list_head    dirs;   /* xdirents of shortlisted dirs */

	pthread_spinlock_t  lock;
};


struct xwork {
	pthread_t        cthreads[THREAD_MAX]; /* crawler threads */
	pthread_t        xthreads[THREAD_MAX]; /* xfer threads */
	int              count;
	int              idle;
	int              stop;

	struct dirjob    crawl;
	struct dirjob    xfer;

	struct dirjob   *rootjob; /* to verify completion in xwork_fini() */

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
	if (job->entries)
		free (job->entries);
	free (job);
}


int
dirjob_update (struct dirjob *job)
{
	int ret = 0;

	ret = set_xtime (job->dirname, stime_key, &job->xtime);
	if (ret)
		terr ("set_xtime(%s): %s\n", job->dirname, strerror (errno));

	stats_dump (0);
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
			terr ("Failed: %s (%d)\n", job->dirname, ret);
		else
			tdbg ("Finished: %s\n", job->dirname);

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
	INIT_LIST_HEAD(&job->files);
	INIT_LIST_HEAD(&job->dirs);
	pthread_spin_init (&job->lock, PTHREAD_PROCESS_PRIVATE);
	job->ret = 0;

	if (parent)
		job->parent = dirjob_ref (parent);

	job->refcnt = 1;

	return job;
}


void
xwork_addcrawl (struct xwork *xwork, struct dirjob *job)
{
	pthread_mutex_lock (&xwork->mutex);
	{
		list_add_tail (&job->list, &xwork->crawl.list);
		pthread_cond_broadcast (&xwork->cond);
	}
	pthread_mutex_unlock (&xwork->mutex);

	return;
}


void
xwork_addxfer (struct xwork *xwork, struct dirjob *job)
{
	pthread_mutex_lock (&xwork->mutex);
	{
		list_add_tail (&job->list, &xwork->xfer.list);
		pthread_cond_broadcast (&xwork->cond);
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

	xwork_addcrawl (xwork, job);

	return 0;
}


struct dirjob *
xwork_pick (struct xwork *xwork, int crawljob, int block)
{
	struct dirjob *job = NULL;
	struct list_head *head = NULL;

	if (crawljob)
		head = &xwork->crawl.list;
	else
		head = &xwork->xfer.list;

	pthread_mutex_lock (&xwork->mutex);
	{
		for (;;) {
			if (xwork->stop)
				break;

			if (!list_empty (head)) {
				job = list_entry (head->next, typeof(*job),
						  list);
				list_del_init (&job->list);
				break;
			}

			if (((xwork->count * 2) == xwork->idle) &&
			    list_empty (&xwork->crawl.list) &&
			    list_empty (&xwork->xfer.list)) {
				/* no outstanding jobs, and no
				   active workers
				*/
				tdbg ("Jobless. Terminating\n");
				xwork->stop = 1;
				pthread_cond_broadcast (&xwork->cond);
				break;
			}

			if (!block)
				break;

			xwork->idle++;
			pthread_cond_wait (&xwork->cond, &xwork->mutex);
			xwork->idle--;
		}
	}
	pthread_mutex_unlock (&xwork->mutex);

	return job;
}


int
dumbhash (const char *name)
{
	int h = 0;
	const char *p = NULL;

	for (p = name; *p; p++)
		h += *p;

	return h;
}

int
skip_name (const char *dirname, const char *name)
{
	if (strcmp (name, ".") == 0)
		return 1;

	if (strcmp (name, "..") == 0)
		return 1;

	if (strcmp (name, ".glusterfs") == 0)
		return 1;

	if (strcmp (dirname, ".") == 0)
		/* skip even/odd entries from replicas */
		if ((dumbhash (name) % REPLICA) != (INDEX % REPLICA)) {
			tdbg ("Skipping ./%s\n", name);
			return 1;
		}

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
	struct list_head list;
	ino_t            xd_ino;
	struct stat      xd_stbuf;
	char             xd_name[NAME_MAX+1];
};


int
xworker_do_xfer (struct xwork *xwork, struct list_head *jobs)
{
	FILE           *fp = NULL;
	char           *xfer_cmd = NULL;
	int             ret = -1;
	struct dirjob  *job = NULL;
	struct xdirent *entry = NULL;
	int             filecnt = 0;
	long long int   bytes = 0;

	asprintf (&xfer_cmd, "/bin/bash -c '%s'", XFER_CMD);
	if (!xfer_cmd) {
		terr ("%s: asprintf failed\n", job->dirname);
		return -1;
	}

	fp = popen (xfer_cmd, "w");
	free (xfer_cmd);

	if (!fp) {
		terr ("%s: popen failed: %s\n", job->dirname,
		      strerror (errno));
		return -1;
	}

	list_for_each_entry (job, jobs, list) {
		list_for_each_entry (entry, &job->files, list) {
			fprintf (fp, "%s/%s\n", job->dirname,
				 entry->xd_name);
			filecnt++;
			bytes += entry->xd_stbuf.st_size;
		}
	}

	ret = pclose (fp);
	ret = WEXITSTATUS(ret);

	if (ret) {
		list_for_each_entry (job, jobs, list)
			break;
		terr ("%s: xfer failed (%d)\n", job->dirname, ret);
	} else {
		BUMP(xfer_execs);
		INC(xfered_files, filecnt);
		INC(xfered_bytes, bytes);
	}

	return ret;
}


int
xworker_do_crawl (struct xwork *xwork, struct dirjob *job)
{
	DIR            *dirp = NULL;
	struct timeval  xtime = {0, };
	struct timeval  ctime = {0, };
	int             ret = -1;
	int             boff;
	int             plen;
	struct dirent  *result;
	char            dbuf[512];
	char           *path = NULL;
	struct xdirent *entries = NULL;
	struct xdirent *entry = NULL;
	struct xdirent *rentries = NULL;
	int             ecount = 0;
	int             esize = 0;
	int             i = 0;
	struct dirjob  *cjob = NULL;
	int             filecnt = 0;
	int             dircnt = 0;
	long long int   filesize = 0;


	plen = strlen (job->dirname) + 256 + 2;
	path = alloca (plen);

	tdbg ("Entering: %s\n", job->dirname);

	ret = get_xtime (job->dirname, xtime_key, &job->xtime);
	if (ret) {
		terr ("xtime missing on %s\n", job->dirname);
		goto out;
	}

	ret = get_xtime (job->dirname, stime_key, &job->stime);
	if (ret) {
		tdbg ("stime missing on %s\n", job->dirname);
	}

	if (!XFER_MODE && timercmp (&job->xtime, &job->stime, ==)) {
		tdbg ("Nothing to do: %s\n", job->dirname);
		return 0;
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

		if (result->d_ino == 0)
			continue;

		if (skip_name (job->dirname, result->d_name))
			continue;

		if (!esize) {
			esize = 1024;
			entries = calloc (esize, sizeof (*entries));
			if (!entries) {
				err ("calloc failed\n");
				goto out;
			}
			job->entries = entries;
		} else if (esize == ecount) {
			esize += 1024;
			rentries = realloc (entries, esize * sizeof (*entries));
			if (!rentries) {
				err ("realloc failed\n");
				goto out;
			}
			entries = rentries;
			job->entries = entries;
		}

		entry = &entries[ecount];
		entry->xd_ino = result->d_ino;
		strncpy (entry->xd_name, result->d_name, NAME_MAX);
		INIT_LIST_HEAD (&entry->list);

		ecount++;
	}

	int xd_cmp (const void *a, const void *b)
	{
		const struct xdirent *xda = a;
		const struct xdirent *xdb = b;

		return (xda->xd_ino - xdb->xd_ino);
	}

	qsort (entries, ecount, sizeof (*entries), xd_cmp);

	boff = sprintf (path, "%s/", job->dirname);

	for (i = 0; i < ecount; i++) {
		entry = &entries[i];
		ret = fstatat (dirfd (dirp), entry->xd_name,
			       &entry->xd_stbuf,
			       AT_SYMLINK_NOFOLLOW);
		if (ret) {
			terr ("fstatat(%s): %s\n", path, strerror (errno));
			closedir (dirp);
			return -1;
		}

		if (S_ISDIR (entry->xd_stbuf.st_mode)) {
			dircnt++;
		} else {
			filecnt++;
			filesize += entry->xd_stbuf.st_size;
		}

		if (skip_mode (&entry->xd_stbuf))
			continue;

		ctime.tv_sec = entry->xd_stbuf.st_ctime;
		ctime.tv_usec = entry->xd_stbuf.st_ctim.tv_nsec / 1000;

		if (!XFER_MODE && timercmp (&ctime, &job->stime, <))
			/* if ctime itself is lower than the stime,
			   don't bother with the get_xtime */
			continue;

		strncpy (path + boff, entry->xd_name, (plen-boff));

		ret = get_xtime (path, xtime_key, &xtime);
		if (ret == 0) {
			if (!XFER_MODE && timercmp (&xtime, &job->stime, <))
				continue;
		}

		if (S_ISDIR (entry->xd_stbuf.st_mode)) {
			list_add_tail (&entry->list, &job->dirs);
			BUMP(shortlist_dirs);
		} else {
			if (XFER_MODE == -1)
				continue;

			list_add_tail (&entry->list, &job->files);
			BUMP(shortlist_files);
		}
	}

	job->filecnt = filecnt;
	job->filesize = filesize;
	job->dircnt = dircnt;

	INC(encountered_dirs, dircnt);
	INC(encountered_files, filecnt);

	if (XFER_MODE == -1)
		/* reset the old stime back in dirjob_update() */
		job->xtime = job->stime;

	if (!list_empty (&job->files)) {
		dirjob_ref (job);
		xwork_addxfer (xwork, job);
	}

	list_for_each_entry (entry, &job->dirs, list) {
		strncpy (path + boff, entry->xd_name, (plen-boff));

		cjob = dirjob_new (path, job);
		if (!cjob) {
			err ("dirjob_new(%s): %s\n",
			     path, strerror (errno));
			ret = -1;
			goto out;
		}

		if (entry->xd_stbuf.st_nlink == 2) {
			/* leaf node */
			xwork_addcrawl (xwork, cjob);
			BUMP(encountered_leafs);
		} else {
			ret = xworker_do_crawl (xwork, cjob);
			dirjob_ret (cjob, ret);
			if (ret)
				goto out;
		}
	}

	ret = 0;
out:
	if (dirp)
		closedir (dirp);

	BUMP(scanned_dirs);

	return ret;
}


void *
xworker_crawl (void *data)
{
	struct xwork *xwork = data;
	struct dirjob *job = NULL;
	int            ret = -1;

	while ((job = xwork_pick (xwork, 1, 1))) {
		ret = xworker_do_crawl (xwork, job);
		dirjob_ret (job, ret);
	}

	return NULL;
}


void *
xworker_xfer (void *data)
{
	struct xwork     *xwork = data;
	struct dirjob    *job = NULL;
	struct dirjob    *tmp = NULL;
	int               ret = -1;
	struct list_head  jobs;
	long long int     filesize = 0;

	while ((job = xwork_pick (xwork, 0, 1))) {
		INIT_LIST_HEAD (&jobs);
		list_add_tail (&job->list, &jobs);
		filesize += job->filesize;

		while ((job = xwork_pick (xwork, 0, 0))) {
			list_add_tail (&job->list, &jobs);
			filesize += job->filesize;

			if (MB_PER_TAR < (filesize / 1048576))
				break;
		}

		ret = xworker_do_xfer (xwork, &jobs);

		list_for_each_entry_safe (job, tmp, &jobs, list) {
			list_del_init (&job->list);
			dirjob_ret (job, ret);
		}
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
		pthread_join (xwork->cthreads[i], &tret);
		tdbg ("CThread id %ld returned %p\n",
		      xwork->cthreads[i], tret);
		pthread_join (xwork->xthreads[i], &tret);
		tdbg ("XThread id %ld returned %p\n",
		      xwork->xthreads[i], tret);
	}

	if (DEBUG) {
		assert (xwork->rootjob->refcnt == 1);

		dirjob_ret (xwork->rootjob, 0);
	}

	return ret;
}


int
xwork_init (struct xwork *xwork, int count)
{
	int  i = 0;
	int  ret = 0;
	struct dirjob *rootjob = NULL;

	pthread_mutex_init (&xwork->mutex, NULL);
	pthread_cond_init (&xwork->cond, NULL);

	INIT_LIST_HEAD (&xwork->crawl.list);
	INIT_LIST_HEAD (&xwork->xfer.list);

	rootjob = dirjob_new (".", NULL);
	if (DEBUG)
		xwork->rootjob = dirjob_ref (rootjob);

	xwork_addcrawl (xwork, rootjob);

	xwork->count = count;
	for (i = 0; i < count; i++) {
		ret = pthread_create (&xwork->cthreads[i], NULL,
				      xworker_crawl, xwork);
		if (ret)
			break;
		tdbg ("Spawned crawler %d thread %ld\n", i,
		      xwork->cthreads[i]);

		ret = pthread_create (&xwork->xthreads[i], NULL,
				      xworker_xfer, xwork);
		if (ret)
			break;
		tdbg ("Spawned xfer %d thread %ld\n", i,
		      xwork->xthreads[i]);
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

	tdbg ("Working directory: %s\n", cwd);
	free (cwd);

	memset (&xwork, 0, sizeof (xwork));
	ret = xwork_init (&xwork, WORKERS);
	if (ret == 0)
		xworker_crawl (&xwork);

	ret = xwork_fini (&xwork, ret);
	stats_dump (1);

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

	// Ugly, no time
	asprintf (&xtime_key, "trusted.glusterfs."
		  "%02x%02x%02x%02x" "-"
		  "%02x%02x" "-" "%02x%02x" "-" "%02x%02x" "-"
		  "%02x%02x%02x%02x%02x%02x" ".xtime",
		  volume_id[0], volume_id[1], volume_id[2], volume_id[3],
		  volume_id[4], volume_id[5], volume_id[6], volume_id[7],
		  volume_id[8], volume_id[9], volume_id[10], volume_id[11],
		  volume_id[12], volume_id[13], volume_id[14], volume_id[15]);

	tdbg ("Xtime key = '%s'\n", xtime_key);
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
parse_env (void)
{
	char *xfer_mode_str = NULL;

	if (setenvint ("REPLICA", &REPLICA) == -1) {
		tout ("Defaulting REPLICA to 1\n");
		REPLICA = 1;
	}

	if (setenvint ("INDEX", &INDEX) == -1) {
		tout ("Defaulting INDEX to 1\n");
		INDEX = 1;
	}

	if (setenvint ("WORKERS", &WORKERS) == -1) {
		tout ("Defaulting WORKERS to %d\n", DEFAULT_WORKERS);
		WORKERS = DEFAULT_WORKERS;
	}

	if (setenvstr ("XFER_CMD", &XFER_CMD) == NULL) {
		tout ("Defaulting XFER_CMD to " DEFAULT_XFER_CMD "\n");
		XFER_CMD = DEFAULT_XFER_CMD;
	}

	if (getenv ("DEBUG"))
		DEBUG = 1;

	if (getenv ("STATS")) {
		STATS = 1;
		pthread_spin_init (&stats_lock, PTHREAD_PROCESS_PRIVATE);
		memset (&stats_interval, 0, sizeof (stats_interval));
		memset (&stats_total, 0, sizeof (stats_total));
		gettimeofday (&stats_interval.start, NULL);
		gettimeofday (&stats_total.start, NULL);
	}

	XFER_MODE = 0;

	xfer_mode_str = getenv ("XFER_MODE");
	if (xfer_mode_str) {
		if (strcasecmp (xfer_mode_str, "ALL") == 0)
			XFER_MODE = 1;

		if (strcasecmp (xfer_mode_str, "NONE") == 0)
			XFER_MODE = -1;
	}

	if (setenvint ("MB_PER_TAR", &MB_PER_TAR) == -1) {
		tout ("Defaulting MB_PER_TAR to 32\n");
		MB_PER_TAR = 32;
	}

	return 0;
}


int
main (int argc, char *argv[])
{
	char *basedir = NULL;

	basedir = parse_arg (argc, argv);
	if (!basedir)
		return 1;

	BASEDIR = basedir;

	parse_env ();

	xfind (basedir);

	return 0;
}
