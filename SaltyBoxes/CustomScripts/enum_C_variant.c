/*
* C380 - C-based Enumeration
* This is a C version of this script: https://github.com/SOC-SE/RnDSweats/blob/80322919e5ed97c04e5a701d5b90c3d415aaa6b9/LinuxDev/masterEnum.sh
*
* Sudo perms are required to run this program. To compile (gcc is required):
* gcc -o enum.sh enum_C_variant.c
* 
* Research sources:
*
* Gemini was used for much of the research needed for how to perform these tasks
* 
* https://www.tutorialspoint.com/c_standard_library/stdarg_h.htm
* https://man7.org/tlpi/code/online/dist/sockets/list_host_addresses.c.html
* https://www.linux.com/news/discover-possibilities-proc-directory/
* https://en.wikibooks.org/wiki/C_Programming/POSIX_Reference/dirent.h
* https://stackoverflow.com/questions/15952283/get-real-free-usable-space
* 
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>      // Required for va_list, va_start, va_end
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h> // For RAM info
#include <sys/statvfs.h> // For Disk Space info
#include <pwd.h>         // For user info
#include <grp.h>         // For group info
#include <dirent.h>      // For directory traversal
#include <time.h>
#include <sys/utsname.h> // For kernel info
#include <ifaddrs.h>     // For network interfaces
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <mntent.h>      // For parsing filesystem mounts
#include <ctype.h>       // For character handling

// Global Log File Pointer
FILE *log_fp = NULL;

// Helper function to log to both stdout and file
void log_msg(const char *format, ...) {
    va_list args;
    
    // Print to Console
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    // Print to File
    if (log_fp) {
        va_start(args, format);
        vfprintf(log_fp, format, args);
        va_end(args);
    }
}

// ==========================================
// 1. GENERAL INVENTORY
// ==========================================

void get_hostname_os() {
    log_msg("\n--- SYSTEM IDENTITY ---\n");
    
    char hostname[1024];
    if (gethostname(hostname, 1024) == 0) {
        log_msg("Hostname: %s\n", hostname);
    }

    struct utsname buffer;
    if (uname(&buffer) == 0) {
        log_msg("OS Kernel: %s %s %s\n", buffer.sysname, buffer.release, buffer.machine);
    }

    // Attempt to read distro name from /etc/os-release
    FILE *f = fopen("/etc/os-release", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                // Remove quotes and newline
                char *name = line + 13; // Skip PRETTY_NAME="
                name[strlen(name)-2] = '\0'; // Remove last quote and newline
                log_msg("Distro: %s\n", name);
                break;
            }
        }
        fclose(f);
    }
}

void get_network_info() {
    log_msg("\n--- NETWORK INTERFACES ---\n");
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // Only look at IPv4 (AF_INET) for simplicity
        if (ifa->ifa_addr->sa_family == AF_INET) {
            int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s == 0 && strcmp(host, "127.0.0.1") != 0) {
                log_msg("Interface: %s\tIP: %s\n", ifa->ifa_name, host);
            }
        }
    }
    freeifaddrs(ifaddr);
}

void get_hardware_info() {
    log_msg("\n--- HARDWARE RESOURCES ---\n");
    
    // CPU Info via /proc/cpuinfo
    FILE *cpu = fopen("/proc/cpuinfo", "r");
    if (cpu) {
        char line[256];
        int cores = 0;
        char model[256] = "Unknown";
        
        while (fgets(line, sizeof(line), cpu)) {
            if (strncmp(line, "model name", 10) == 0) {
                char *p = strchr(line, ':');
                if (p) strncpy(model, p + 2, sizeof(model));
                model[strcspn(model, "\n")] = 0; // strip newline
            }
            if (strncmp(line, "processor", 9) == 0) {
                cores++;
            }
        }
        log_msg("CPU Model: %s\n", model);
        log_msg("CPU Cores: %d\n", cores);
        fclose(cpu);
    }

    // RAM Info via sysinfo syscall
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        // Convert bytes to MB
        long total_ram = info.totalram * info.mem_unit / 1024 / 1024;
        long free_ram = info.freeram * info.mem_unit / 1024 / 1024;
        log_msg("Total RAM: %ld MB\n", total_ram);
        log_msg("Free RAM:  %ld MB\n", free_ram);
    }

    // Disk Space via statvfs (Root Partition)
    struct statvfs disk_info;
    if (statvfs("/", &disk_info) == 0) {
        // Blocks * Fragment Size = Total Bytes
        unsigned long long total_bytes = disk_info.f_blocks * disk_info.f_frsize;
        unsigned long long free_bytes = disk_info.f_bfree * disk_info.f_frsize;
        
        // Convert to GB for display
        double total_gb = (double)total_bytes / (1024 * 1024 * 1024);
        double free_gb = (double)free_bytes / (1024 * 1024 * 1024);

        log_msg("Root Disk: %.2f GB Total (%.2f GB Free)\n", total_gb, free_gb);
    }
}

// ==========================================
// 2. PROCESS & SERVICE AUDITING
// ==========================================

void scan_processes() {
    log_msg("\n--- ALL RUNNING PROCESSES (Scanning /proc) ---\n");
    // Print a clean header
    log_msg("%-8s %-s\n", "PID", "COMMAND");
    log_msg("--------------------------------------------------------------------------------\n");
    
    DIR *procdir = opendir("/proc");
    struct dirent *entry;

    if (procdir == NULL) {
        log_msg("Error reading /proc\n");
        return;
    }

    while ((entry = readdir(procdir)) != NULL) {
        // Skip if not a directory or not a PID (non-numeric)
        if (entry->d_type != DT_DIR || !isdigit(*entry->d_name))
            continue;

        char path[256];
        snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);

        FILE *f = fopen(path, "r");
        if (f) {
            char cmdline[1024] = {0};
            // cmdline entries are separated by null bytes. We read the whole thing
            // and replace nulls with spaces for display.
            size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, f);
            fclose(f);

            if (len > 0) {
                // Replace null bytes with spaces for cleaner printing
                for (size_t i = 0; i < len; i++) {
                    if (cmdline[i] == '\0') cmdline[i] = ' ';
                }

                // Truncate overly long commands (e.g. browsers with huge args)
                // so they fit on the screen nicely.
                if (strlen(cmdline) > 100) {
                    cmdline[97] = '\0';
                    strcat(cmdline, "...");
                }

                // Log using fixed width for PID
                log_msg("%-8s %s\n", entry->d_name, cmdline);
            }
        }
    }
    closedir(procdir);
}

// ==========================================
// 3. STORAGE & MOUNTS
// ==========================================

void get_mounts() {
    log_msg("\n--- MOUNTED FILESYSTEMS ---\n");
    struct mntent *ent;
    FILE *f = setmntent("/proc/mounts", "r");
    
    if (f == NULL) {
        log_msg("Error opening /proc/mounts\n");
        return;
    }

    log_msg("%-20s %-30s %-10s\n", "DEVICE", "MOUNT POINT", "TYPE");
    log_msg("--------------------------------------------------------------\n");

    while ((ent = getmntent(f)) != NULL) {
        // Filter out pseudo-filesystems for clarity, similar to lsblk/df
        if (strncmp(ent->mnt_fsname, "/dev", 4) == 0 || 
            strstr(ent->mnt_type, "ext") || 
            strstr(ent->mnt_type, "xfs") || 
            strstr(ent->mnt_type, "nfs")) {
            log_msg("%-20s %-30s %-10s\n", ent->mnt_fsname, ent->mnt_dir, ent->mnt_type);
        }
    }
    endmntent(f);
}

// ==========================================
// 4. CRON CONFIGURATION
// ==========================================

void parse_cron_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;
        
        // Basic heuristic: lines starting with numbers or * are likely jobs
        if (isdigit(line[0]) || line[0] == '*') {
            // Remove newline
            line[strcspn(line, "\n")] = 0;
            log_msg("[JOB] (%s) %s\n", filename, line);
        }
    }
    fclose(f);
}

void check_crons() {
    log_msg("\n--- SYSTEM CRON CHECK (/etc/crontab & /etc/cron.d) ---\n");
    
    // Check main crontab
    parse_cron_file("/etc/crontab");

    // Check cron.d directory
    DIR *dir = opendir("/etc/cron.d");
    struct dirent *entry;

    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            // Skip . and ..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char path[256];
            snprintf(path, sizeof(path), "/etc/cron.d/%s", entry->d_name);
            parse_cron_file(path);
        }
        closedir(dir);
    } else {
        log_msg("Could not open /etc/cron.d\n");
    }
}

// ==========================================
// 5. USER ENUMERATION
// ==========================================

void scan_users() {
    log_msg("\n--- USER SECURITY ANALYSIS ---\n");
    log_msg("%-20s %-10s %-30s %-20s\n", "USERNAME", "UID", "SHELL", "NOTES");
    log_msg("--------------------------------------------------------------------------------\n");

    struct passwd *pw;
    setpwent(); // Rewind stream

    while ((pw = getpwent()) != NULL) {
        char notes[256] = "";

        // Check for Root
        if (pw->pw_uid == 0) {
            strcat(notes, "[ROOT-PRIVS] ");
        }

        // Check for suspicious non-root UID 0
        if (pw->pw_uid == 0 && strcmp(pw->pw_name, "root") != 0) {
            strcat(notes, "[SUSPICIOUS-UID0] ");
        }

        // Check for Login Shells on service accounts
        int is_service = (pw->pw_uid < 1000 && pw->pw_uid != 0);
        int has_shell = (strstr(pw->pw_shell, "sh") != NULL && strstr(pw->pw_shell, "nologin") == NULL && strstr(pw->pw_shell, "false") == NULL);
        
        if (is_service && has_shell) {
            strcat(notes, "[SERVICE-WITH-SHELL] ");
        }

        // Only print if it's a real user or has a flag
        if (pw->pw_uid >= 1000 || strlen(notes) > 0 || pw->pw_uid == 0) {
             log_msg("%-20s %-10d %-30s %-20s\n", pw->pw_name, pw->pw_uid, pw->pw_shell, notes);
        }
    }
    endpwent();
}

// ==========================================
// 6. FILE SYSTEM AUDIT (SUID)
// ==========================================

// Recursive directory scanner
void scan_suid_files(const char *base_path, int depth) {
    if (depth > 5) return; // Prevent deep recursion loops

    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;

    if (!(dir = opendir(base_path))) return;

    while ((entry = readdir(dir)) != NULL) {
        char path[1024];
        
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);

        // Use lstat to detect symlinks and ignore them to avoid loops
        if (lstat(path, &statbuf) == -1) continue;

        if (S_ISDIR(statbuf.st_mode)) {
            // Avoid scanning virtual filesystems to prevent hangs
            if (strcmp(entry->d_name, "proc") == 0 || 
                strcmp(entry->d_name, "sys") == 0 || 
                strcmp(entry->d_name, "dev") == 0 || 
                strcmp(entry->d_name, "run") == 0) continue;
            
            scan_suid_files(path, depth + 1);
        } 
        else if (S_ISREG(statbuf.st_mode)) {
            // Check for SUID bit (S_ISUID)
            if (statbuf.st_mode & S_ISUID) {
                log_msg("[SUID DETECTED] %s (Owner UID: %d)\n", path, statbuf.st_uid);
            }
        }
    }
    closedir(dir);
}

// ==========================================
// 7. MAIN EXECUTION
// ==========================================

int main() {
    // 1. Root Check
    if (geteuid() != 0) {
        printf("CRITICAL: This tool must be run as root.\n");
        return 1;
    }

    // 2. Setup Logging
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char log_filename[256];
    
    // Ensure log directory exists
    struct stat st = {0};
    if (stat("/var/log/syst", &st) == -1) {
        mkdir("/var/log/syst", 0700);
    }

    snprintf(log_filename, sizeof(log_filename), "/var/log/syst/audit_c_%d%02d%02d.log", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    log_fp = fopen(log_filename, "w");
    
    if (!log_fp) {
        printf("Error opening log file. Printing to stdout only.\n");
    }

    log_msg("==========================================\n");
    log_msg("   C-BASED SYSTEM AUDIT (CS380 PROJECT)   \n");
    log_msg("   Date: %d-%02d-%02d %02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min);
    log_msg("==========================================\n");

    // Execute Modules
    get_hostname_os();
    get_network_info();
    get_hardware_info();
    get_mounts();      
    scan_processes();    
    check_crons();       
    scan_users();
    
    log_msg("\n--- SCANNING FOR SUID BINARIES (May take a moment) ---\n");
    // Start scan at typical binary locations to save time, rather than root "/"
    scan_suid_files("/usr/bin", 0);
    scan_suid_files("/usr/sbin", 0);
    scan_suid_files("/bin", 0);
    scan_suid_files("/sbin", 0);

    log_msg("\n==========================================\n");
    log_msg("   AUDIT COMPLETE   \n");
    log_msg("==========================================\n");

    if (log_fp) {
        printf("Log saved to: %s\n", log_filename);
        fclose(log_fp);
    }

    return 0;
}