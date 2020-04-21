#include<stdio.h>
#include<sys/types.h>
#include<pwd.h>
#include<shadow.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>
#include<errno.h>
#include<grp.h>
#include<crypt.h>
#include<syslog.h>

/* The default PATH for simulated logins to non-superuser accounts.  */
#ifdef _PATH_DEFPATH
#define DEFAULT_LOGIN_PATH _PATH_DEFPATH
#else
# define DEFAULT_LOGIN_PATH ":/usr/ucb:/bin:/usr/bin"
#endif

/* The default PATH for simulated logins to superuser accounts.  */
#ifdef _PATH_DEFPATH_ROOT
#define DEFAULT_ROOT_LOGIN_PATH _PATH_DEFPATH_ROOT
#else
# define DEFAULT_ROOT_LOGIN_PATH "/usr/ucb:/bin:/usr/bin:/etc"
#endif

const struct spwd *shadowstruct; 
const struct passwd *pw ;
char *unen_passwd;
char *shell=NULL;
extern char **environ;
const char *program_name;

static void system_logs(bool successful){
	char *new_user,*old_user,*tty;
	new_user = pw->pw_name;
	old_user = getlogin();
	tty = ttyname(STDERR_FILENO);
	openlog (program_name,0,LOG_AUTH);
	syslog(LOG_NOTICE,"%s(to %s) %s on %s",successful ? "Login In" : "Login Failed",new_user,old_user,tty);
	closelog();
}


static void set_environment(){
	
	char *term = getenv("TERM");
	shell = pw->pw_shell;
	term = strdup(term);
	environ = malloc ((6 + !!term) * sizeof (char *));
	environ[0]= NULL;
	setenv ("TERM",term,1);
      	setenv ("HOME",pw->pw_dir,1);
      	setenv ("SHELL",pw->pw_shell,1);
      	setenv ("USER",pw->pw_name,1);
      	setenv ("LOGNAME",pw->pw_name,1);
      	setenv ("PATH",(pw->pw_uid
                        ? DEFAULT_LOGIN_PATH
                        : DEFAULT_ROOT_LOGIN_PATH),1);
	
}

static void run_shell(){
	char *args[]={shell,NULL}; 
        execvp(args[0],args); 
}

static void new_identity(){
	initgroups(pw->pw_name, pw->pw_gid);
  	setgid(pw->pw_gid);
 	setuid(pw->pw_uid);
}

static bool password_mapping(){

	shadowstruct = getspnam(pw->pw_name);
	endspent();
	char *correct_pass,*en_passwd,info[50];
	if(shadowstruct ==NULL){
		printf("Program doesnot have permission \n");
		exit(1);
	}	
	correct_pass = shadowstruct->sp_pwdp;
	if(!strcmp(pw->pw_name,getlogin())||(correct_pass[0] == '\0')||!strcmp(getlogin(),"root")){
		return false;
	}
	sprintf(info, "Enter %s password :",pw->pw_name);
	unen_passwd = getpass(info);
	en_passwd = crypt(unen_passwd ,correct_pass);
	if(!en_passwd){
		return true;
	}
	memset (unen_passwd, 0, strlen (unen_passwd));
	return strcmp(correct_pass,en_passwd);
}

int main(int argc,char **argv){

	if( argc < 2 ) {
		pw = getpwnam("root");
   	}else if( argc > 2 ) {
      		printf("argument limit exceeds\n");
		exit(1);
	}else{
		pw = getpwnam(argv[1]);
	}
	program_name = argv[0];	
	if(pw == NULL){
		printf("User Not Exsist\n");
		exit(1);
	}if(password_mapping()){
		system_logs(false);
		printf("incorrect password\n");
		exit(1);	
	}	
	system_logs(true);
	set_environment();
	new_identity();
	run_shell();
	return 0;

}

