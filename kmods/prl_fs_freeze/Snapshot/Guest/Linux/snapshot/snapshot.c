///////////////////////////////////////////////////////////////////////////////
///
/// @file snapshot.c
/// @author evg
///
/// main programm - suspend or resume writers
///
/// Copyright (c) 1999-2016 Parallels International GmbH.
/// All rights reserved.
/// http://www.parallels.com
///
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <mntent.h>
#include <sys/mman.h>
#include <linux/version.h>
#include <sys/utsname.h>

//timeout to wait that FS state changed from "running" to "freezed"
#define SUSPEND_TIMEOUT		10

//maximum time, that FS can be in "freezed" state.
//if during this time there is no command to resume FS,
//FS will be resumed automatically
#define RESUME_TIMEOUT		60

#define UNUSED(expr) do { (void)(expr); } while (0)

struct mount_entry
{
	struct mntent mnt;
	struct mount_entry *next;
};

char* xstring2(char sep, char* str1, char* str2)
{
	char* full = malloc(strlen(str1)+strlen(str2)+2);
	if (NULL == full) {
		fprintf(stderr, "failed to malloc\n");
		return NULL;
	}
	sprintf(full, "%s%c%s", str1, sep, str2);
	return full;
}


char* xstrdup(const char* str)
{
	char * dup = strdup(str);
	if (NULL == dup)
		fprintf(stderr, "failed to strdup string\n");
	return dup;
}

struct mount_entry *get_list()
{
	struct mount_entry *mount_list;
	struct mount_entry *me;
	struct mount_entry **mtail = &mount_list;

	struct mntent *mnt;

	FILE *fp;

	fp = setmntent ("/etc/mtab", "r");
	if (fp == NULL)
	{
		fprintf(stderr, "failed to open /etc/mtab\n");
		return NULL;
	}

	while ((mnt = getmntent (fp)))
	{
		me =  (struct mount_entry * ) malloc (sizeof(*me));
		if (NULL == me)
		{
			fprintf(stderr, "failed to calloc %d bytes\n", (int)sizeof(*me));
			return NULL;
		}
		me->mnt.mnt_fsname = xstrdup(mnt->mnt_fsname);
		me->mnt.mnt_dir = xstrdup(mnt->mnt_dir);
		me->mnt.mnt_opts = xstrdup(mnt->mnt_opts);
		me->mnt.mnt_type = xstrdup(mnt->mnt_type);

		if (me->mnt.mnt_fsname == NULL || me->mnt.mnt_dir == NULL ||
			me->mnt.mnt_opts == NULL || me->mnt.mnt_type == NULL)
			return NULL;

		*mtail = me;
		mtail = &me->next;
	}

	endmntent (fp);

	*mtail = NULL;
	return mount_list;
}

int wait_suspend()
{
        sleep(SUSPEND_TIMEOUT);
        return 0;
}

int wait_resume()
{
	sleep(RESUME_TIMEOUT);
	return 0;
}

int send_command(const char *command)
{
	int ret = 0;
	int fd;
	struct utsname uts;
	unsigned int major, minor;

	//Workaround, #PSBM-16537
	if (uname(&uts) ||
		sscanf(uts.release, "%u.%u.%*s", &major, &minor) != 2 ||
		major < 3  || (major == 3 && minor < 7)) {
		fprintf(stderr, "not supported for this kernel\n");
		return 0;
	}

	printf("command '%s'\n", command);

	fd  = open( "/proc/driver/prl_freeze" , O_WRONLY );
	if (fd < 0)
	{
		fprintf(stderr, "failed to open /proc/driver/prl_freeze\n");
		return -1;
	}

	if ( write(fd, command, strlen(command)) < 0 )
	{
		fprintf(stderr, "failed to write to /proc/driver/prl_freeze\n");
		ret = 1;
	}

	close(fd);

	return ret;
}

int resume()
{
	return send_command("#");
}

void resume_action(int act)
{ //running in child context
        (void) act;

        printf("catch resume action from parent\n");
        resume();
        exit(0);
}

void suspend_done(int act)
{ //running in parent context
        printf("catch result from child: %s\n", act == SIGUSR1 ? "ok" : "false");

        if (act == SIGUSR1) //ok
                exit(0);
        else
                exit(1);
}

int suspend()
{
	struct mount_entry * list = get_list();
	struct mount_entry *me;
	struct stat dev_stat, disk_stat;
	char buf_timeout[64];

	char *str = NULL;

	if (list == NULL)
	{
		fprintf(stderr, "failed to get list of mount point\n");
		return -1;
	}

	me = list;
	do
	{
		if (NULL == me)
			break;

		if ( me->mnt.mnt_fsname[0] != '/' || me->mnt.mnt_dir[0] != '/' )
			continue;

		if (stat( me->mnt.mnt_fsname, &dev_stat ))
			continue;

		if (stat( me->mnt.mnt_dir, &disk_stat ))
			continue;

		//skip not block devices
		if ( !S_ISBLK( dev_stat.st_mode ) )
			continue;

		printf("mount point %s -> %s opts %s type %s\n",
				me->mnt.mnt_fsname, me->mnt.mnt_dir,
				me->mnt.mnt_opts, me->mnt.mnt_type
			);

		if (str == NULL)
		{
			str = xstrdup( me->mnt.mnt_dir );
			if (NULL == str)
				return -1;
		}
		else
		{
			char *tmp = xstring2('\n', me->mnt.mnt_dir, str);
			if (NULL == tmp)
				return -1;
			free(str);
			str = tmp;
		}

	}while((me = me->next));

	if (str == NULL) //nothing todo
		return 0;

	if (snprintf( buf_timeout, sizeof(buf_timeout), "t%d", RESUME_TIMEOUT) <= 0)
	{
		fprintf(stderr, "failed to create timeout string\n");
		return -1;
	}

	char *command = xstring2('\n', buf_timeout, str);
	if (NULL == command)
		return -1;

	if ( send_command(command) )
	{
		resume();
		return 1;
	}
	return 0;
}

int do_suspend()
{
	signal(SIGUSR1, suspend_done);
	signal(SIGUSR2, suspend_done);

	int pid = fork();
	if (pid < 0)
	{
		printf("failed to fork\n");
		return -1;
	}
	else if (pid > 0)
	{
		//say toolscenter PID of freeze process
		printf( "PID=%d\n", pid );

		//parent: wait for signal from child and exit
		wait_suspend();
		printf("timeout to wait signal from child\n");
		//too long!!!
		return 1;
	}
	else
	{
		//child
		int ppid = getppid();
		if (setsid() < 0)
		{
			printf("ERROR: failed to create new SID");
			kill(ppid, SIGUSR2);
			return -1;
		}

		close(0);
		close(1);
		close(2);

		//for child redefine signal SIGTERM
		signal(SIGTERM, resume_action);

		int rc = suspend();

		//send signal to parent
		if (rc)
		{
			//if false - send SIGUSR2 and exit
			kill(ppid, SIGUSR2);
			return rc;
		}

		//if Ok - send SIGUSR1 and wait for kill
		//printf("send signal OK to parent\n");
		kill(ppid, SIGUSR1);


		wait_resume();
		//printf("timeout to wait signal from parent\n");
		resume();
		exit(0);
	}
	return 0;
}



void usage(void)
{
	char *prog = "prl_snapshot";
	printf("Resume/Suspend hard disks via prl_fs_freeze module\n") ;
	printf("Usage:\n") ;

	printf("%s       - suspend\n", prog);
	printf("%s stop  - resume\n", prog);
	printf("%s help  - print this usage\n", prog);
}


int main (int argc, char **argv)
{
	int rc = 0;

	if (argc > 1 && !strcmp(argv[1], "help"))
	{
		usage();
		rc = 0;
	}
	else if (argc > 1 && !strcmp(argv[1], "stop"))
	{
		printf("resume disks\n") ;

		rc = resume();
	}
	else if (argc > 1)
	{
		usage();
		rc = 100;
	}
	else
	{
		int locked;

		printf("suspend disks\n") ;

		if ( (locked =  mlockall(MCL_CURRENT | MCL_FUTURE)) != 0)
			fprintf(stderr, "failed to mlockall\n");

		rc = do_suspend();

		if (locked == 0)
			munlockall();
	}

	return rc;
}

