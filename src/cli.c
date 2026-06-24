/* cli.c - Command-line interface for Axis
 *
 * A GUI-free front end exposing the same volume operations as the GTK
 * version, and able to open the exact same encrypted containers.
 *
 * It works in two ways:
 *
 *   1. Interactive menu (run with no arguments) - a guided, menu-driven
 *      front end that walks through create / open / mount / unmount / close.
 *
 *   2. Non-interactive command line (run with a subcommand) - one-shot
 *      operations suitable for scripting:
 *
 *         axis-cli create <path> --size <MB> [--password <pw>]
 *         axis-cli mount  <path> <mountpoint> [--password <pw>]
 *         axis-cli info   <path> [--password <pw>]
 *         axis-cli help
 *         axis-cli version
 *
 *      The interactive menu is just there to help; everything it does can
 *      also be driven directly from the command line.
 */

#include "config.h"
#include "volume.h"
#include "fuse_mount.h"
#include "utils.h"

#include <sodium.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>

/* The currently open volume, if any. */
static volume_context_t *g_volume = NULL;

/* Set by the signal handler when a foreground mount should shut down. */
static volatile sig_atomic_t g_stop_requested = 0;

/* ----- input helpers ------------------------------------------------- */

/* Read a line from stdin into buf (NUL-terminated, newline stripped).
 * Returns 0 on success, -1 on EOF/error. */
static int read_line(char *buf, size_t size) {
    if (!fgets(buf, (int)size, stdin)) {
        return -1;
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    return 0;
}

/* Read a single line. If show is non-zero the characters are echoed normally;
 * otherwise terminal echo is disabled so the password stays hidden.
 * Returns 0 on success, -1 on error. */
static int read_password(const char *prompt, char *buf, size_t size, int show) {
    if (show) {
        fputs(prompt, stdout);
        fflush(stdout);
        return read_line(buf, size);
    }

    struct termios old_term, new_term;
    int have_term = 0;

    fputs(prompt, stdout);
    fflush(stdout);

    if (tcgetattr(STDIN_FILENO, &old_term) == 0) {
        have_term = 1;
        new_term = old_term;
        new_term.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term);
    }

    int rc = read_line(buf, size);

    if (have_term) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
    }
    fputc('\n', stdout);
    return rc;
}

/* Ask the user whether they want the password revealed while typing.
 * Returns non-zero for "yes". */
static int ask_show_password(void) {
    char ans[16];
    printf("Show password while typing? [y/N]: ");
    fflush(stdout);
    if (read_line(ans, sizeof(ans)) != 0) {
        return 0;
    }
    return (ans[0] == 'y' || ans[0] == 'Y');
}

/* ----- progress callback --------------------------------------------- */

static void cli_progress(const char *label, size_t cur, size_t total, void *user_data) {
    (void)user_data;
    if (total == 0) {
        return;
    }
    int pct = (int)((cur * 100) / total);
    int filled = pct / 5; /* 20-char bar */
    char bar[21];
    for (int i = 0; i < 20; i++) {
        bar[i] = (i < filled) ? '#' : '-';
    }
    bar[20] = '\0';
    printf("\r[%s] %3d%% %-28s", bar, pct, label ? label : "");
    fflush(stdout);
    if (cur >= total) {
        fputc('\n', stdout);
    }
}

/* ----- shared volume helpers ----------------------------------------- */

static void close_current_volume(void) {
    if (!g_volume) {
        return;
    }
    if (g_volume->is_open) {
        if (g_volume->vfs.is_mounted) {
            stop_fuse_mount(g_volume);
            volume_unmount(g_volume);
        }
        volume_close(g_volume, NULL, NULL);
    }
    free(g_volume);
    g_volume = NULL;
}

/* Allocate g_volume and trial-decrypt the container at path.
 * Returns 0 on success (g_volume left open), -1 on failure (g_volume NULL).
 * The password buffer is left untouched; the caller still owns/wipes it. */
static int open_volume(const char *path, const char *password) {
    close_current_volume();

    g_volume = malloc(sizeof(volume_context_t));
    if (!g_volume) {
        printf("Out of memory.\n");
        return -1;
    }
    memset(g_volume, 0, sizeof(volume_context_t));

    if (lock_sensitive(g_volume, sizeof(volume_context_t)) != 0) {
        printf("Warning: memory locking failed; the master key may be swapped to disk.\n");
        printf("         Run as root or raise memlock limits for maximum security.\n");
    }

    printf("Opening volume (Argon2 needs ~1 GB RAM)...\n");
    if (volume_open(path, password, g_volume, cli_progress, NULL) != 0) {
        printf("Failed to open volume. Possible causes:\n");
        printf("  - Wrong password\n");
        printf("  - Corrupted volume file\n");
        printf("  - Insufficient RAM for Argon2 (needs ~1 GB free)\n");
        free(g_volume);
        g_volume = NULL;
        return -1;
    }
    return 0;
}

/* Print storage statistics for the currently open/mounted volume,
 * mirroring the GUI "Storage Status" panel. */
static void print_storage_status(void) {
    uint64_t total = (uint64_t)g_volume->vfs.header.total_sectors * VFS_SECTOR_SIZE;
    uint64_t used  = (uint64_t)g_volume->vfs.header.used_sectors  * VFS_SECTOR_SIZE;
    uint64_t free_bytes = total > used ? total - used : 0;

    printf("Volume:      %s\n", g_volume->path);
    printf("Files:       %u\n", g_volume->vfs.header.file_count);
    printf("Total space: %.2f MB\n", (double)total / (1024 * 1024));
    printf("Used space:  %.2f MB\n", (double)used / (1024 * 1024));
    printf("Free space:  %.2f MB\n", (double)free_bytes / (1024 * 1024));
}

/* ----- interactive menu actions -------------------------------------- */

static void action_create(void) {
    char path[512];
    char size_str[64];
    char password[256];
    char confirm[256];

    printf("\n--- Create a new volume ---\n");

    printf("Volume file path: ");
    fflush(stdout);
    if (read_line(path, sizeof(path)) != 0 || path[0] == '\0') {
        printf("Cancelled (no path given).\n");
        return;
    }

    printf("Volume size in MB (min 10): ");
    fflush(stdout);
    if (read_line(size_str, sizeof(size_str)) != 0) {
        printf("Cancelled.\n");
        return;
    }

    char *end = NULL;
    long size_mb_l = strtol(size_str, &end, 10);
    if (!end || *end != '\0' || size_mb_l < 10) {
        printf("Invalid size. Must be a number >= 10.\n");
        return;
    }
    if (size_mb_l > 1024L * 1024L) {
        printf("Size must not exceed 1048576 MB (1 TiB).\n");
        return;
    }

    int show = ask_show_password();
    if (read_password("Password: ", password, sizeof(password), show) != 0 || password[0] == '\0') {
        printf("Cancelled (no password).\n");
        secure_zero(password, sizeof(password));
        return;
    }
    if (read_password("Confirm password: ", confirm, sizeof(confirm), show) != 0) {
        secure_zero(password, sizeof(password));
        secure_zero(confirm, sizeof(confirm));
        return;
    }
    if (strcmp(password, confirm) != 0) {
        printf("Passwords do not match.\n");
        secure_zero(password, sizeof(password));
        secure_zero(confirm, sizeof(confirm));
        return;
    }
    secure_zero(confirm, sizeof(confirm));

    printf("Creating volume (this may take a while)...\n");
    int result = volume_create(path, (size_t)size_mb_l, password, cli_progress, NULL);
    secure_zero(password, sizeof(password));

    if (result == 0) {
        printf("Volume created successfully: %s\n", path);
    } else {
        printf("Failed to create volume. Check permissions and free space.\n");
    }
}

static void action_open(void) {
    char path[512];
    char password[256];

    printf("\n--- Open a volume ---\n");

    printf("Volume file path: ");
    fflush(stdout);
    if (read_line(path, sizeof(path)) != 0 || path[0] == '\0') {
        printf("Cancelled (no path given).\n");
        return;
    }

    if (read_password("Password: ", password, sizeof(password), ask_show_password()) != 0 ||
        password[0] == '\0') {
        printf("Cancelled (no password).\n");
        secure_zero(password, sizeof(password));
        return;
    }

    if (open_volume(path, password) == 0) {
        printf("Volume opened successfully. Use 'Mount a volume' to access files.\n");
    }
    secure_zero(password, sizeof(password));
}

static void action_mount(void) {
    char mount_dir[512];

    printf("\n--- Mount a volume ---\n");

    if (!g_volume || !g_volume->is_open) {
        printf("No volume is currently open. Use 'Open a volume' first.\n");
        return;
    }

    if (g_volume->vfs.is_mounted) {
        printf("Volume is already mounted. Remounting...\n");
        stop_fuse_mount(g_volume);
        volume_unmount(g_volume);
    }

    printf("Mount directory: ");
    fflush(stdout);
    if (read_line(mount_dir, sizeof(mount_dir)) != 0 || mount_dir[0] == '\0') {
        printf("Cancelled (no mount directory).\n");
        return;
    }

    printf("Mounting volume...\n");
    if (volume_mount(g_volume) != 0) {
        printf("Failed to mount volume. The filesystem may be corrupted.\n");
        return;
    }

    if (start_fuse_mount(g_volume, mount_dir) != 0) {
        volume_unmount(g_volume);
        printf("Failed to start FUSE daemon. Check that FUSE is available and the\n");
        printf("mount directory exists and is empty.\n");
        return;
    }

    printf("Volume mounted successfully via FUSE at: %s\n", mount_dir);
    printf("Files are accessible there until you unmount or exit.\n");
}

static void action_unmount(void) {
    printf("\n--- Unmount volume ---\n");

    if (!g_volume || !g_volume->vfs.is_mounted) {
        printf("No volume is currently mounted.\n");
        return;
    }

    printf("Unmounting volume...\n");
    stop_fuse_mount(g_volume);
    if (volume_unmount(g_volume) == 0) {
        printf("Volume unmounted successfully.\n");
    } else {
        printf("Failed to unmount volume.\n");
    }
}

static void action_status(void) {
    printf("\n--- Storage status ---\n");
    if (!g_volume || !g_volume->is_open) {
        printf("No volume is currently open.\n");
        return;
    }
    print_storage_status();
}

static void action_close(void) {
    printf("\n--- Close volume ---\n");

    if (!g_volume || !g_volume->is_open) {
        printf("No volume is currently open.\n");
        return;
    }

    if (g_volume->vfs.is_mounted) {
        printf("Unmounting before close...\n");
        stop_fuse_mount(g_volume);
        volume_unmount(g_volume);
    }

    printf("Closing volume (flushing to disk and wiping keys)...\n");
    int result = volume_close(g_volume, cli_progress, NULL);
    free(g_volume);
    g_volume = NULL;

    if (result == 0) {
        printf("Volume closed successfully.\n");
    } else {
        printf("Volume closed (with errors during flush).\n");
    }
}

/* ----- interactive main loop ----------------------------------------- */

static void print_menu(void) {
    printf("\n========================================\n");
    printf(" %s v%s\n", APP_NAME, APP_VERSION);
    printf("========================================\n");
    printf(" 1. Create a new volume\n");
    printf(" 2. Open a volume\n");
    printf(" 3. Mount a volume\n");
    printf(" 4. Unmount volume\n");
    printf(" 5. Storage status\n");
    printf(" 6. Close volume\n");
    printf(" 7. Exit\n");
    printf("----------------------------------------\n");
    if (g_volume && g_volume->is_open) {
        printf(" [open: %s%s]\n", g_volume->path,
               g_volume->vfs.is_mounted ? " | mounted" : "");
    }
    printf("Select an option [1-7]: ");
    fflush(stdout);
}

static int run_interactive(void) {
    char choice[16];
    for (;;) {
        print_menu();
        if (read_line(choice, sizeof(choice)) != 0) {
            printf("\n");
            break; /* EOF */
        }

        if (strcmp(choice, "1") == 0) {
            action_create();
        } else if (strcmp(choice, "2") == 0) {
            action_open();
        } else if (strcmp(choice, "3") == 0) {
            action_mount();
        } else if (strcmp(choice, "4") == 0) {
            action_unmount();
        } else if (strcmp(choice, "5") == 0) {
            action_status();
        } else if (strcmp(choice, "6") == 0) {
            action_close();
        } else if (strcmp(choice, "7") == 0 ||
                   strcmp(choice, "q") == 0 || strcmp(choice, "Q") == 0) {
            break;
        } else if (choice[0] == '\0') {
            continue;
        } else {
            printf("Invalid option: %s\n", choice);
        }
    }

    printf("Cleaning up...\n");
    close_current_volume();
    printf("Goodbye.\n");
    return 0;
}

/* ----- non-interactive command line ---------------------------------- */

static void usage(const char *prog) {
    printf("%s v%s - %s\n", APP_NAME, APP_VERSION, APP_TITLE);
    printf("\nUsage:\n");
    printf("  %s                                       Launch the interactive menu\n", prog);
    printf("  %s create <path> --size <MB> [--password <pw>]\n", prog);
    printf("  %s mount  <path> <mountpoint> [--password <pw>]\n", prog);
    printf("  %s info   <path> [--password <pw>]\n", prog);
    printf("  %s help | --help | -h\n", prog);
    printf("  %s version | --version | -v\n", prog);
    printf("\nNotes:\n");
    printf("  * If --password is omitted it is prompted for securely (no echo).\n");
    printf("  * Passing --password on the command line may expose it to other\n");
    printf("    users via the process list; prefer the interactive prompt.\n");
    printf("  * 'mount' runs in the foreground and stays mounted until you press\n");
    printf("    Ctrl-C, after which the volume is unmounted, flushed and closed.\n");
    printf("  * The mount directory must already exist and be empty.\n");
}

/* Find the value for a named option (e.g. "--size") in argv[start..argc).
 * Returns the value string, or NULL if not present. */
static const char *find_opt(int argc, char **argv, int start, const char *name) {
    for (int i = start; i < argc - 1; i++) {
        if (strcmp(argv[i], name) == 0) {
            return argv[i + 1];
        }
    }
    return NULL;
}

/* Resolve a password: use the supplied one if non-NULL, otherwise prompt.
 * Writes into buf. Returns 0 on success, -1 on failure/cancel. */
static int resolve_password(const char *supplied, char *buf, size_t size, int confirm) {
    if (supplied) {
        if (strlen(supplied) >= size) {
            printf("Password too long.\n");
            return -1;
        }
        strncpy(buf, supplied, size - 1);
        buf[size - 1] = '\0';
        return 0;
    }

    if (read_password("Password: ", buf, size, 0) != 0 || buf[0] == '\0') {
        printf("Cancelled (no password).\n");
        return -1;
    }
    if (confirm) {
        char again[256];
        if (read_password("Confirm password: ", again, sizeof(again), 0) != 0) {
            secure_zero(again, sizeof(again));
            return -1;
        }
        if (strcmp(buf, again) != 0) {
            printf("Passwords do not match.\n");
            secure_zero(again, sizeof(again));
            return -1;
        }
        secure_zero(again, sizeof(again));
    }
    return 0;
}

static int cmd_create(int argc, char **argv) {
    if (argc < 3) {
        printf("Error: 'create' needs a volume path.\n");
        printf("Usage: %s create <path> --size <MB> [--password <pw>]\n", argv[0]);
        return 1;
    }
    const char *path = argv[2];

    const char *size_str = find_opt(argc, argv, 3, "--size");
    if (!size_str) {
        printf("Error: 'create' needs --size <MB>.\n");
        return 1;
    }
    char *end = NULL;
    long size_mb = strtol(size_str, &end, 10);
    if (!end || *end != '\0' || size_mb < 10) {
        printf("Error: invalid --size. Must be a number >= 10.\n");
        return 1;
    }
    if (size_mb > 1024L * 1024L) {
        printf("Error: --size must not exceed 1048576 MB (1 TiB).\n");
        return 1;
    }

    char password[256];
    if (resolve_password(find_opt(argc, argv, 3, "--password"),
                         password, sizeof(password), 1) != 0) {
        secure_zero(password, sizeof(password));
        return 1;
    }

    printf("Creating volume (this may take a while)...\n");
    int rc = volume_create(path, (size_t)size_mb, password, cli_progress, NULL);
    secure_zero(password, sizeof(password));

    if (rc == 0) {
        printf("Volume created successfully: %s\n", path);
        return 0;
    }
    printf("Failed to create volume. Check permissions and free space.\n");
    return 1;
}

static void on_signal(int sig) {
    (void)sig;
    g_stop_requested = 1;
}

static int cmd_mount(int argc, char **argv) {
    if (argc < 4) {
        printf("Error: 'mount' needs a volume path and a mount directory.\n");
        printf("Usage: %s mount <path> <mountpoint> [--password <pw>]\n", argv[0]);
        return 1;
    }
    const char *path = argv[2];
    const char *mount_dir = argv[3];

    char password[256];
    if (resolve_password(find_opt(argc, argv, 4, "--password"),
                         password, sizeof(password), 0) != 0) {
        secure_zero(password, sizeof(password));
        return 1;
    }

    int rc = open_volume(path, password);
    secure_zero(password, sizeof(password));
    if (rc != 0) {
        return 1;
    }

    printf("Mounting volume...\n");
    if (volume_mount(g_volume) != 0) {
        printf("Failed to mount volume. The filesystem may be corrupted.\n");
        close_current_volume();
        return 1;
    }

    if (start_fuse_mount(g_volume, mount_dir) != 0) {
        volume_unmount(g_volume);
        printf("Failed to start FUSE daemon. Check that FUSE is available and the\n");
        printf("mount directory exists and is empty.\n");
        close_current_volume();
        return 1;
    }

    printf("Volume mounted via FUSE at: %s\n", mount_dir);
    printf("Press Ctrl-C to unmount and close.\n");

    /* Block in the foreground until interrupted, then tear everything down. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while (!g_stop_requested && g_volume->vfs.is_mounted) {
        pause();
    }

    printf("\nUnmounting and closing volume...\n");
    close_current_volume();
    printf("Done.\n");
    return 0;
}

static int cmd_info(int argc, char **argv) {
    if (argc < 3) {
        printf("Error: 'info' needs a volume path.\n");
        printf("Usage: %s info <path> [--password <pw>]\n", argv[0]);
        return 1;
    }
    const char *path = argv[2];

    char password[256];
    if (resolve_password(find_opt(argc, argv, 3, "--password"),
                         password, sizeof(password), 0) != 0) {
        secure_zero(password, sizeof(password));
        return 1;
    }

    int rc = open_volume(path, password);
    secure_zero(password, sizeof(password));
    if (rc != 0) {
        return 1;
    }

    printf("\n");
    print_storage_status();

    close_current_volume();
    return 0;
}

/* ----- startup ------------------------------------------------------- */

static void startup_banner(void) {
    printf("%s v%s - %s\n", APP_NAME, APP_VERSION, APP_TITLE);

    if (check_swap_security()) {
        printf("\nWARNING: Unencrypted swap detected! This may compromise security.\n");
        printf("Consider encrypting swap with LUKS or disabling swap entirely.\n");
    }
}

int main(int argc, char **argv) {
    /* Disable core dumps for security. */
    prctl(PR_SET_DUMPABLE, 0);
    struct rlimit limit = { .rlim_cur = 0, .rlim_max = 0 };
    setrlimit(RLIMIT_CORE, &limit);

    if (sodium_init() < 0) {
        fprintf(stderr, "Error: Failed to initialize libsodium\n");
        return 1;
    }

    /* No subcommand -> interactive menu. */
    if (argc < 2) {
        startup_banner();
        printf("Command-line interface (run '%s help' for non-interactive usage)\n", argv[0]);
        return run_interactive();
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage(argv[0]);
        return 0;
    }
    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0 || strcmp(cmd, "-v") == 0) {
        printf("%s v%s\n", APP_NAME, APP_VERSION);
        return 0;
    }

    startup_banner();

    int rc;
    if (strcmp(cmd, "create") == 0) {
        rc = cmd_create(argc, argv);
    } else if (strcmp(cmd, "mount") == 0) {
        rc = cmd_mount(argc, argv);
    } else if (strcmp(cmd, "info") == 0) {
        rc = cmd_info(argc, argv);
    } else {
        printf("Unknown command: %s\n\n", cmd);
        usage(argv[0]);
        rc = 1;
    }

    /* Safety net: make sure nothing is left open on exit. */
    close_current_volume();
    return rc;
}
