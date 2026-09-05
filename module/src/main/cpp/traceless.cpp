/*
 * Traceless - Zygisk Module
 * Copyright 2025
 *
 * This module aims to hide Magisk/root related mounts from processes
 * specified in the Magisk DenyList by leveraging Zygisk and its
 * companion process feature.
 */
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <android/log.h>
#include "mountsinfo.cpp"
#include "utils.cpp"
#include <sys/mount.h>
#include <sys/syscall.h>
#include <set>
#include <string>
#include <vector>
#include <errno.h>
#include <cstring>
#include <sstream>
#include "zygisk.hpp"

// Single source of truth for the runtime version string. CI can override this
// via a -DTRACELESS_VERSION="..." compile definition; the default is kept in
// sync with the Gradle verName so logcat and module.prop never disagree.
#ifndef TRACELESS_VERSION
#define TRACELESS_VERSION "v0.0.2"
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#define LOG_TAG "Traceless"
#define TL_LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define TL_LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define TL_LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define TL_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// --- Configuration ---
static const std::set<std::string> suspicious_mount_sources = {
        "magisk",
        "KSU",
        "APatch",
        "worker"
};

enum State {
    SUCCESS = 0,
    FAILURE = 1
};

static const std::string magisk_data_path_prefix = "/data/adb";
static const std::string magisk_modules_path_prefix = "/data/adb/modules/";
// The mount "root" field in /proc/<pid>/mountinfo is relative to the source
// filesystem's own root, so a bind mount of /data/adb/modules/<mod>/... shows
// up as ".../adb/modules/..." rather than "/data/adb/...".
static const char *const module_root_marker = "/adb/modules/";
static const char *const maps_filter_target = "jit-cache-zygisk_traceless";
static const char *const self_maps_path = "/proc/self/maps";
static const char *const pid_maps_prefix = "/proc/";
static const char *const maps_suffix = "/maps";

// --- Zygisk Module Implementation ---
// We hook the framework's unshare (in libandroid_runtime, the actual caller of
// the specialization-time unshare) plus the file-open primitives in libc so a
// denylisted process reads a sanitized /proc/<pid>/maps.
int (*original_unshare)(int) = nullptr;

static FILE *(*original_fopen)(const char *, const char *) = nullptr;

static int (*original_open)(const char *, int, ...) = nullptr;

static int (*original_openat)(int, const char *, int, ...) = nullptr;

// Create an in-memory file. memfd-backed descriptors behave like regular files
// (seekable, pread-able, fstat reports a regular file, mmap works), unlike a
// pipe, so a substituted /proc/<pid>/maps does not break legitimate readers and
// is far less tamper-evident. Uses the raw syscall because the memfd_create libc
// wrapper is only available from API 30 while this module targets API 26+.
static int create_memfd(const char *name) {
    return static_cast<int>(syscall(SYS_memfd_create, name, MFD_CLOEXEC));
}

// Helper function to check if a path is a proc maps file
static bool isProcMapsFile(const char *path) {
    if (!path) return false;
    if (strcmp(path, self_maps_path) == 0) return true;
    if (strncmp(path, pid_maps_prefix, strlen(pid_maps_prefix)) == 0) {
        const char *suffix_ptr = strstr(path + strlen(pid_maps_prefix), maps_suffix);
        // Ensure it ends exactly with "/maps"
        return suffix_ptr != nullptr && suffix_ptr[strlen(maps_suffix)] == '\0';
    }
    return false;
}

// Helper function to read entire FD content into a string
static std::string readFdToString(int fd) {
    std::stringstream ss;
    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = TEMP_FAILURE_RETRY(::read(fd, buffer, sizeof(buffer)))) > 0) {
        ss.write(buffer, bytes_read);
    }
    // Check for read error
    if (bytes_read < 0) {
        TL_LOGE("readFdToString: Error reading fd %d: %s", fd, strerror(errno));
        return ""; // Return empty on error
    }
    return ss.str();
}

// Helper function to filter maps content (string version)
static std::string filterMapsContent(const std::string &content) {
    std::stringstream input_ss(content);
    std::stringstream output_ss;
    std::string line;
    while (std::getline(input_ss, line)) {
        if (line.find(maps_filter_target) == std::string::npos) {
            output_ss << line << "\n";
        }
    }
    return output_ss.str();
}

// Build a read-only memfd holding the filtered maps content. On success the
// returned fd contains the sanitized text rewound to offset 0. Returns -1 and
// sets errno on hard failure.
static int makeFilteredMemfd(const std::string &content) {
    std::string filtered = filterMapsContent(content);
    int mfd = create_memfd("jit-cache");
    if (mfd < 0) {
        return -1;
    }
    size_t total_written = 0;
    const char *data = filtered.data();
    size_t data_len = filtered.size();
    while (total_written < data_len) {
        ssize_t written = TEMP_FAILURE_RETRY(::write(mfd, data + total_written,
                                                     data_len - total_written));
        if (written <= 0) {
            ::close(mfd);
            errno = EIO;
            return -1;
        }
        total_written += static_cast<size_t>(written);
    }
    ::lseek(mfd, 0, SEEK_SET);
    return mfd;
}

static int reshare(int flags) {
    errno = 0;
    return flags == CLONE_NEWNS ? 0 : original_unshare(flags & ~CLONE_NEWNS);
}

// Hook for fopen. For a maps path we read the real file, then hand back a FILE*
// wrapping a filtered memfd, so every stdio consumer (fgets/fread/getline/...)
// transparently sees sanitized content. Non-maps paths pass straight through.
static FILE *my_fopen(const char *path, const char *mode) {
    if (!original_fopen) {
        TL_LOGE("my_fopen: original_fopen is null!");
        errno = EFAULT;
        return nullptr;
    }
    if (!isProcMapsFile(path)) {
        return original_fopen(path, mode);
    }

    FILE *real = original_fopen(path, "re");
    if (!real) {
        return original_fopen(path, mode); // preserve original error semantics
    }
    std::string content = readFdToString(fileno(real));
    fclose(real);
    if (content.empty()) {
        // Nothing to hide (or a transient read hiccup): give back the real file
        // rather than fabricating an impossible error.
        return original_fopen(path, mode);
    }

    int mfd = makeFilteredMemfd(content);
    if (mfd < 0) {
        TL_LOGW("my_fopen: memfd fallback failed for %s: %s", path, strerror(errno));
        return original_fopen(path, mode);
    }
    FILE *fp = fdopen(mfd, "r");
    if (!fp) {
        ::close(mfd);
        return original_fopen(path, mode);
    }
    TL_LOGD("my_fopen: served filtered maps for %s", path);
    return fp;
}

// Common logic for open/openat hooks: return a filtered memfd in place of the
// real maps file.
static int handle_open_maps(const char *path, int real_fd) {
    std::string content = readFdToString(real_fd);
    if (content.empty()) {
        // Hand back a valid, rewound real fd instead of an EIO tell.
        ::lseek(real_fd, 0, SEEK_SET);
        return real_fd;
    }
    ::close(real_fd);

    int mfd = makeFilteredMemfd(content);
    if (mfd < 0) {
        TL_LOGE("handle_open_maps: memfd fallback failed for %s: %s", path, strerror(errno));
        return -1;
    }
    TL_LOGD("handle_open_maps: served filtered maps for %s (fd %d)", path, mfd);
    return mfd;
}

// Hook for open
static int my_open(const char *path, int flags, ...) {
    if (!original_open) {
        TL_LOGE("my_open: original_open is null!");
        errno = EFAULT;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (isProcMapsFile(path)) {
        TL_LOGD("my_open: Intercepted open for maps file: %s", path);
        // Force a read-only open of the real file, then substitute a filtered fd.
        int real_fd = original_open(path, O_RDONLY | O_CLOEXEC);
        if (real_fd < 0) {
            TL_LOGE("my_open: Original open failed for %s: %s", path, strerror(errno));
            return -1;
        }
        return handle_open_maps(path, real_fd);
    } else {
        return original_open(path, flags, mode);
    }
}

// Hook for openat
static int my_openat(int dirfd, const char *path, int flags, ...) {
    if (!original_openat) {
        TL_LOGE("my_openat: original_openat is null!");
        errno = EFAULT;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (isProcMapsFile(path)) {
        TL_LOGD("my_openat: Intercepted openat for maps file: %s (dirfd: %d)", path, dirfd);
        int real_fd = original_openat(dirfd, path, O_RDONLY | O_CLOEXEC);
        if (real_fd < 0) {
            TL_LOGE("my_openat: Original openat failed for %s: %s", path, strerror(errno));
            return -1;
        }
        return handle_open_maps(path, real_fd);
    } else {
        return original_openat(dirfd, path, flags, mode);
    }
}

class TracelessModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *pApi, JNIEnv *pEnv) override {
        this->api = pApi;
        this->env = pEnv;
        TL_LOGI("Traceless %s loaded! (Zygisk API v%d)", TRACELESS_VERSION, ZYGISK_API_VERSION);
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        preSpecialize(args);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        TL_LOGD("preServerSpecialize: system_server");
        stored_process_name = "system_server";
        on_denylist = (api->getFlags() & zygisk::StateFlag::PROCESS_ON_DENYLIST);
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        handlePostSpecialization();
        env->ReleaseStringUTFChars(args->nice_name, process);
    }

    void postServerSpecialize(const ServerSpecializeArgs *args) override {
        handlePostSpecialization();
    }

    // --- Core Logic: Mount Hiding Decision ---
    static bool shouldUnmount(const MountInfo &mount) {
        const std::string &mount_point = mount.getMountPoint();
        const std::string &mount_source = mount.getMountSource();
        const std::string &fs_type = mount.getFsType();
        const std::string &root = mount.getRoot();
        const MountOptions &options = mount.getMountOptions();

        if (mount_point.rfind(magisk_data_path_prefix, 0) == 0) {
            TL_LOGD("shouldUnmount: YES - Mount point [%s] is in %s",
                    mount_point.c_str(), magisk_data_path_prefix.c_str());
            return true;
        }

        if (fs_type == "tmpfs" || fs_type == "overlay") {
            if (suspicious_mount_sources.count(mount_source)) {
                TL_LOGD("shouldUnmount: YES - FS type [%s] for [%s] has suspicious source [%s]",
                        fs_type.c_str(), mount_point.c_str(), mount_source.c_str());
                return true;
            }

            if (fs_type == "overlay") {
                const auto &flagmap = options.flagmap;
                for (const auto &key: {"lowerdir", "upperdir", "workdir"}) {
                    auto it = flagmap.find(key);
                    if (it != flagmap.end() && it->second.rfind(magisk_data_path_prefix, 0) == 0) {
                        TL_LOGD("shouldUnmount: YES - Overlay [%s] option \"%s\" (%s) points to %s",
                                mount_point.c_str(), key, it->second.c_str(),
                                magisk_data_path_prefix.c_str());
                        return true;
                    }
                }
            }
        }

        // Magic-mount / bind of module files. /proc/<pid>/mountinfo never carries
        // a literal "bind" option (bind is a mount(2) call-time flag), so detect
        // it by the source path or by the mount root pointing into a module tree.
        if (mount_source.rfind(magisk_modules_path_prefix, 0) == 0 ||
            root.find(module_root_marker) != std::string::npos) {
            TL_LOGD("shouldUnmount: YES - Bind mount [%s] originates from a module tree (source=%s root=%s)",
                    mount_point.c_str(), mount_source.c_str(), root.c_str());
            return true;
        }

        return false;
    }

    // Unmount every root-related mount visible in the CURRENT mount namespace.
    // Shared by the companion (after setns into the app's namespace) and by the
    // in-process fallback. Returns SUCCESS if the mount table could be read.
    static int unmountMatchingInCurrentNs(pid_t target_pid) {
        auto mounts = getMountInfo();
        if (mounts.empty()) {
            TL_LOGW("unmount: No mounts found for PID %d", target_pid);
            return FAILURE;
        }

        int unmounted_count = 0;
        int failed_count = 0;
        // Reverse order so children detach before their parents.
        for (auto it = mounts.rbegin(); it != mounts.rend(); ++it) {
            if (shouldUnmount(*it)) {
                const std::string &mount_point = it->getMountPoint();
                if (umount2(mount_point.c_str(), MNT_DETACH) == 0) {
                    TL_LOGI("unmount: Detached [%s] for PID %d", mount_point.c_str(), target_pid);
                    unmounted_count++;
                } else {
                    TL_LOGW("unmount: Failed to detach [%s] for PID %d: %s",
                            mount_point.c_str(), target_pid, strerror(errno));
                    failed_count++;
                }
            }
        }

        TL_LOGI("[+] unmount pass complete for PID %d. Detached: %d, Failed: %d",
                target_pid, unmounted_count, failed_count);
        return SUCCESS;
    }

private:
    int cfd{};
    Api *api = nullptr;
    JNIEnv *env = nullptr;
    dev_t cdev = 0;
    ino_t cinode = 0;
    dev_t target_dev = 0;
    ino_t target_inode = 0;
    bool on_denylist = false;
    std::string stored_process_name;

    void preSpecialize(AppSpecializeArgs *args) {
        unsigned int flags = api->getFlags();
        if (flags & zygisk::StateFlag::PROCESS_GRANTED_ROOT) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        auto fn = [](const std::string &lib) {
            auto di = devinoby(lib.c_str());
            if (di) {
                return *di;
            } else {
                LOGW("#[zygisk::?] devino[dl_iterate_phdr]: Failed to get device & inode for %s",
                     lib.c_str());
                LOGI("#[zygisk::?] Fallback to use `/proc/self/maps`");
                return devinobymap(lib);
            }
        };

        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process_name_chars) {
            TL_LOGE("preAppSpecialize: Failed to get process nice_name.");
            on_denylist = false;
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        stored_process_name = process_name_chars;
        env->ReleaseStringUTFChars(args->nice_name, process_name_chars);
        on_denylist = (api->getFlags() & zygisk::StateFlag::PROCESS_ON_DENYLIST);
        TL_LOGD("preAppSpecialize: Process \"%s\" on denylist? %d",
                stored_process_name.c_str(), on_denylist);

        // Only denylisted processes get the hook + unmount treatment.
        if (!on_denylist) {
            return;
        }

        pid_t pid = getpid();
        cfd = api->connectCompanion(); // Companion FD
        api->exemptFd(cfd);

        // Check if we can find libc.so and libandroid_runtime.so
        std::tie(cdev, cinode) = fn("libc.so");
        if (!cdev && !cinode) {
            TL_LOGE("Could not find dev/inode for libc.so");
            close(cfd);
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        TL_LOGI("[!] Found libc.so: dev=%u, inode=%lu", cdev, cinode);

        std::tie(target_dev, target_inode) = fn("libandroid_runtime.so");
        if (!target_dev && !target_inode) {
            TL_LOGE("Could not find dev/inode for libandroid_runtime.so");
            close(cfd);
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        TL_LOGI("[!] Found libandroid_runtime.so: dev=%u, inode=%lu", target_dev, target_inode);

        // Neutralize the framework's specialization-time unshare so it cannot
        // escape the sanitized namespace we are about to build.
        api->pltHookRegister(target_dev, target_inode, "unshare",
                             reinterpret_cast<void *>(reshare),
                             reinterpret_cast<void **>(&original_unshare));
        // Sanitize /proc/<pid>/maps reads.
        api->pltHookRegister(cdev, cinode, "fopen",
                             reinterpret_cast<void *>(my_fopen),
                             reinterpret_cast<void **>(&original_fopen));
        api->pltHookRegister(cdev, cinode, "open",
                             reinterpret_cast<void *>(my_open),
                             reinterpret_cast<void **>(&original_open));
        api->pltHookRegister(cdev, cinode, "openat",
                             reinterpret_cast<void *>(my_openat),
                             reinterpret_cast<void **>(&original_openat));

        if (!api->pltHookCommit()) {
            TL_LOGE("Failed to commit PLT hooks for PID %d! Hooks inactive.", pid);
            original_unshare = nullptr;
            original_fopen = nullptr;
            original_open = nullptr;
            original_openat = nullptr;
            close(cfd);
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        TL_LOGI("Successfully committed PLT hooks for PID %d.", pid);

        // Build our own private, de-propagated mount namespace.
        int res = unshare(CLONE_NEWNS);
        if (res != 0) {
            LOGE("#[zygisk::preSpecialize] unshare: %s", strerror(errno));
            close(cfd);
            return;
        }
        res = mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr);
        if (res != 0) {
            LOGE("#[zygisk::preSpecialize] mount(rootfs, \"/\", MS_SLAVE | MS_REC): %d (%s)",
                 errno, strerror(errno));
            close(cfd);
            return;
        }

        // Hand our OWN pid to the companion and wait for it to finish unmounting
        // inside this freshly-unshared namespace. The blocking read below is the
        // synchronization barrier that guarantees the cleanup completed before we
        // continue into specialization.
        int status = FAILURE;
        if (write(cfd, &pid, sizeof(pid)) != sizeof(pid)) {
            LOGE("#[zygisk::preSpecialize] write: [-> pid]: %s", strerror(errno));
            status = FAILURE;
        } else if (read(cfd, &status, sizeof(status)) != sizeof(status)) {
            LOGE("#[zygisk::preSpecialize] read: [<- status]: %s", strerror(errno));
            status = FAILURE;
        }
        close(cfd);

        if (status != SUCCESS) {
            LOGW("#[zygisk::preSpecialize]: Companion failed; falling back to in-process unmount");
            // We already own a private namespace, so a best-effort local unmount
            // still only affects this process.
            unmountMatchingInCurrentNs(pid);
        }
    }

    void handlePostSpecialization() {
        // Restore the PLT hooks we installed.
        if (original_unshare) {
            api->pltHookRegister(target_dev, target_inode, "unshare", (void *) original_unshare,
                                 nullptr);
            original_unshare = nullptr;
        }
        if (original_fopen) {
            api->pltHookRegister(cdev, cinode, "fopen", (void *) original_fopen, nullptr);
            original_fopen = nullptr;
        }
        if (original_open) {
            api->pltHookRegister(cdev, cinode, "open", (void *) original_open, nullptr);
            original_open = nullptr;
        }
        if (original_openat) {
            api->pltHookRegister(cdev, cinode, "openat", (void *) original_openat, nullptr);
            original_openat = nullptr;
        }

        if (!api->pltHookCommit()) {
            TL_LOGE("[!] Failed to commit PLT hooks on post specialization");
        } else {
            TL_LOGI("{+} Successfully committed PLT hooks on post specialization");
        }
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }
};

// --- Companion Process Implementation ---
static void companionHandler(int client_fd) {
    TL_LOGI("Companion: Handling connection on fd %d", client_fd);

    pid_t target_pid = -1;
    ssize_t bytes_read = read(client_fd, &target_pid, sizeof(target_pid));
    if (bytes_read != sizeof(target_pid)) {
        TL_LOGE("Companion: Failed to read PID (read %zd bytes: %s)",
                bytes_read, strerror(errno));
        int status = FAILURE;
        (void) write(client_fd, &status, sizeof(status));
        close(client_fd);
        return;
    }

    TL_LOGI("Companion: Received target PID %d. Processing.", target_pid);

    // Do the namespace switch + unmount inside a forked child so the setns does
    // not disturb the long-lived companion daemon.
    int fork_status = forkcall([target_pid]() -> int {
        TL_LOGD("Companion: Switching to mount namespace of PID %d", target_pid);
        if (!switchnsto(target_pid)) {
            TL_LOGE("Companion: Failed to switch to namespace of PID %d", target_pid);
            return FAILURE;
        }
        TL_LOGI("Companion: Successfully in namespace of PID %d", target_pid);
        return TracelessModule::unmountMatchingInCurrentNs(target_pid);
    });

    int status = (fork_status == SUCCESS) ? SUCCESS : FAILURE;
    if (status != SUCCESS) {
        TL_LOGE("Companion: Unmount task failed for PID %d (status: %d)", target_pid, fork_status);
    }
    // Report the outcome back so the app can run its in-process fallback if needed.
    if (write(client_fd, &status, sizeof(status)) != static_cast<ssize_t>(sizeof(status))) {
        TL_LOGW("Companion: Failed to send status for PID %d: %s", target_pid, strerror(errno));
    }
    if (close(client_fd)) {
        TL_LOGW("Companion: Failed to close client fd: %s", strerror(errno));
    }
}

// --- Zygisk Registration ---
REGISTER_ZYGISK_MODULE(TracelessModule)

REGISTER_ZYGISK_COMPANION(companionHandler)
