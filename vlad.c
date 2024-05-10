#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <sys/wait.h>

#define MAX_PATH_LEN 1024

typedef struct SnapshotInfo {
    char entry[256]; // Calea
    long timestamp; // Timestamp
    long size; // Dimensiunea
    long last_modified; // Ultima modificare
    char permissions[10]; // Permisiunile
    long inode_no; // Numarul de inode
}SnapshotInfo;

void err(const char *e){
    perror(e);
    exit(1);
}

void isolateMaliciousFile(const char *filePath, const char *isolatedDirectory)
{
    execl("./verif.sh", "d", filePath, isolatedDirectory,(char *)NULL);
}

char *readLineFromFile(int snapshotFile)
{
    char *line = malloc(MAX_PATH_LEN * sizeof(char));
    char c;
    int lineIndex = 0;
    while (read(snapshotFile, &c, 1) == 1)
    {
        if (c == '\n')
        {
            line[lineIndex] = '\0';
            return line;
        }
        else
        {
            line[lineIndex++] = c;
            if (lineIndex >= MAX_PATH_LEN - 1)
            {
                err("Line too long in snapshot file.");
            }
        }
    }

    if (lineIndex == 0)
    {
        free(line);
        return NULL;
    }

    line[lineIndex] = '\0';
    return line;
}

char *getPermissions(mode_t mode){
    static char ans[10] = {0};
    ans[0] = (mode & S_IRUSR) ? 'r' : '-';
    ans[1] = (mode & S_IWUSR) ? 'w' : '-';
    ans[2] = (mode & S_IXUSR) ? 'x' : '-';
    ans[3] = (mode & S_IRGRP) ? 'r' : '-';
    ans[4] = (mode & S_IWGRP) ? 'w' : '-';
    ans[5] = (mode & S_IXGRP) ? 'x' : '-';
    ans[6] = (mode & S_IROTH) ? 'r' : '-';
    ans[7] = (mode & S_IWOTH) ? 'w' : '-';
    ans[8] = (mode & S_IXOTH) ? 'x' : '-';
    return ans;
}

void printSnapshot(const char *path,struct stat *info,int fd){
    char buffer[1024];
    sprintf(buffer, " %s", path);
    write(fd, buffer, strlen(buffer));

    sprintf(buffer, " %ld", time(0));
    write(fd, buffer, strlen(buffer));

    sprintf(buffer, " %ld", info->st_size);
    write(fd, buffer, strlen(buffer));

    sprintf(buffer, " %ld", info->st_mtime);
    write(fd, buffer, strlen(buffer));

    sprintf(buffer, " %s", getPermissions(info->st_mode));
    write(fd, buffer, strlen(buffer));

    sprintf(buffer, " %ld\n", info->st_ino);
    write(fd, buffer, strlen(buffer));
}

static bool zeroPermissions(struct stat *info){
    mode_t m = info->st_mode;
    return !((m & S_IRUSR) || (m & S_IWUSR) || (m & S_IXUSR) ||
       (m & S_IRGRP) || (m & S_IWGRP) || (m & S_IXGRP) ||
       (m & S_IROTH) || (m & S_IWOTH) || (m & S_IXOTH));
}

void searchDir(const char *argc,int snapshot,const char *safe){
    DIR *dir = opendir(argc);

    if(dir == NULL){
        perror("opendir()");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    
    char path[1000];

    struct stat info;

    while((entry = readdir(dir)) != NULL){
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        sprintf(path,"%s/%s",argc,entry->d_name);
        
        int st = stat(path,&info);
        if(st < 0){
            perror("stat()");
            exit(EXIT_FAILURE);
        }

        if(zeroPermissions(&info))
        {
            int pfd[2];
            if(pipe(pfd)<0)
            {
            perror("Eroare la crearea pipe-ului\n");
            exit(1);
            }
            pid_t pid = fork();
            if(pid == 0)//sunt in copil
            {
                close(pfd[0]);/* inchide capatul de citire; */
                dup2(pfd[1],1);
                execl("./sus.sh", "d", path, safe,(char *)NULL);
                close(pfd[1]);
                perror("Exec didn t overwrite\n");
                exit(EXIT_FAILURE);
            }
            else //sunt in parinte
            {
                int status;
                waitpid(pid, &status, 0);
                close(pfd[1]);
                char *line = NULL;

                if (WIFEXITED(status))
                {
                    
                    
                    int exitStatus = WEXITSTATUS(status);
                    if (exitStatus != 0)
                    {
                       
                        if ((line = readLineFromFile(pfd[0])) != NULL)
                        {
                            close(pfd[0]);
                           
                            if (strcmp(line, "SAFE") != 0)
                            {   
                                int pij=fork();
                                if(pij==0)
                                {
                                isolateMaliciousFile(path,safe);
                                exit(EXIT_FAILURE);
                                }
                            }
                        }
                    }
                }
                else
                {
                    close(pfd[0]);
                    err("Couldn't scan the file.");
                }
            }
        }
        else
        {
            printSnapshot(path,&info,snapshot);
            if(S_ISDIR(info.st_mode)){
                searchDir(path,snapshot,safe);
            }
        }
    }
    closedir(dir);
}

SnapshotInfo extractMetadataFromLine(char *line)
{
    char *p = NULL;
    p = strtok(line, " ");
    SnapshotInfo SnapshotInfo;
    strcpy(SnapshotInfo.entry, p);
    p = strtok(NULL, " ");
    SnapshotInfo.timestamp = atol(p);
    p = strtok(NULL, " ");
    SnapshotInfo.size = atol(p);
    p = strtok(NULL, " ");
    SnapshotInfo.last_modified = atol(p);
    p = strtok(NULL, " ");
    strcpy(SnapshotInfo.permissions, p);
    p = strtok(NULL, " ");
    SnapshotInfo.inode_no= atol(p);
    p = strtok(NULL, " ");
    return SnapshotInfo;
}

SnapshotInfo *readSnapshot(const char *snapshotPath, int *numFiles)
{
    int snapshotFile = open(snapshotPath, O_RDONLY, S_IRUSR);
    if (snapshotFile == -1)
    {
        err("Fisierul nu a putut fi deschis.\n");
    }
    SnapshotInfo *metadata = NULL;
    *numFiles = 0;

    char *line = NULL;

    while ((line = readLineFromFile(snapshotFile)) != NULL)
    {
        SnapshotInfo SnapshotInfo = extractMetadataFromLine(line);
        metadata = realloc(metadata, (++*numFiles) * sizeof(SnapshotInfo));
        metadata[*numFiles - 1] = SnapshotInfo;
        free(line);
    }

    close(snapshotFile);

    return metadata;
}

void comparaSnapshots(SnapshotInfo *snapshot1, SnapshotInfo *snapshot2, int numFiles1, int numFiles2, const char *outputPath)
{

    int outputFile = open(outputPath, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);

    char buffer[MAX_PATH_LEN];

    for (int i = 0; i < numFiles1; i++)
    {
        int found = 0;
        for (int j = 0; j < numFiles2; j++)
        {
            if (strcmp(snapshot1[i].entry ,snapshot2[j].entry)==0)
            {
                found = 1;
            }
        }

        if (!found)
        {

            int len = snprintf(buffer, sizeof(buffer), "Fisier sters: %s\n", snapshot1[i].entry);
            if (write(outputFile, buffer, len) == -1)
            {
                err("Eroare la scrierea în fișierul de ieșire.");
            }
        }
    }

    for (int i = 0; i < numFiles2; i++)
    {
        int found = 0;
        for (int j = 0; j < numFiles1; j++)
        {
            if (strcmp(snapshot2[i].entry,snapshot1[j].entry)==0)
            {
                
                found = 1;
                break;
            }
        }
        if (!found)
        {

            int len = snprintf(buffer, sizeof(buffer), "Fisier adaugat: %s\n", snapshot2[i].entry);
            if (write(outputFile, buffer, len) == -1)
            {
                err("Eroare la scrierea in fiierrul de iesire.");
            }
        }
    }

    close(outputFile);
}

void child(const char *argc,const char *out,const char *safe){
	char *snapPath = malloc(strlen(out) + strlen(argc) + 5);
    struct stat fileInfo;
    if(snapPath == NULL){
        perror("malloc()");
        exit(EXIT_FAILURE);
    }

    sprintf(snapPath,"%s/%s.snp",out,argc);
    if (stat(snapPath, &fileInfo) == 0) {
        
       int numberOfFilesNew = 0;
        int numberOfFilesOriginal = 0;
        
        SnapshotInfo *original = readSnapshot(snapPath,&numberOfFilesOriginal);

        int snapshot = open(snapPath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(snapshot < 0){
            perror("open()");
            exit(EXIT_FAILURE);
        }

        searchDir(argc,snapshot,safe);
        
        SnapshotInfo *new = readSnapshot(snapPath,&numberOfFilesNew);//readSnapshot;
        
        close(snapshot);

        char*modificariTotale=malloc(strlen(out)+strlen(argc)+5);

        sprintf(modificariTotale,"%s/mod%s.snp",out,argc);

        comparaSnapshots(original ,new ,numberOfFilesOriginal, numberOfFilesNew, modificariTotale);

        free(original);
        free(new);
        
    }
    else
    {
        int snapshot = open(snapPath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(snapshot < 0){
            perror("open()");
            exit(EXIT_FAILURE);
        }

        searchDir(argc,snapshot,safe);
        
        close(snapshot);
    }
    printf("Snapshot for dir %s created successfully.\n",argc);
	exit(getpid());
}

void makedir(const char *d){
	struct stat st;

	if(stat(d,&st) == -1){
		if(mkdir(d,0777) < 0){
			err("mkdir():");
		}
	}
}

char *specialdir(int argc,char**argv,const char *flag){
	int outdir = -1;

	for(int i = 1;i < argc;++i){
		if(!strcmp(argv[i],flag)){
			outdir = i + 1;
			if(outdir >= argc) {
				err("Expected directory after \"-c\"");
			}
			break;
		}
	}

	return (outdir < 0) ? "." : argv[outdir];
}

int snapshot(int argc,char**argv,const char *out,const char *safe){
	int n = 0;
	for(int i = 1;i < argc;++i,++n){
		if(strlen(argv[i]) == 2 && argv[i][0] == '-'){
			++i;
            --n;
			continue;
		}

		if(!fork()){
			child(argv[i],out,safe);
		}
	}

	return n;
}

void waitproc(int n){
	for(int i = 0;i < n;++i){
		int status;
		pid_t p = wait(&status);
		if(p < 0){
            printf("HEH\n");
			err("wait():");
		}

		if(WIFEXITED(status)){
			printf("Child Process %d terminated with exit code %d\n",p,WEXITSTATUS(status));
		}
		else{
			err("Child process exited abnormally!\n");
		}
	}
}
int main(int argc,char **argv){
	if(argc < 2){
		printf("Usage: %s <dir1> ...\n",argv[0]);
		return 1;
	}
	
	char *out = specialdir(argc,argv,"-o");
	char *safe = specialdir(argc,argv,"-s");

	if(out != NULL) makedir(out);
	if(safe != NULL) makedir(safe);

	int n = snapshot(argc,argv,out,safe);
	waitproc(n);

	return 0;
}
