#include <ctime>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sched.h>
#include <pty.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <net/if.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <cstring>
#include <cstdlib>
#include <filesystem>

using namespace std;

string base;

void fail(const string &s) {
    perror(s.c_str());
    exit(125);
}

void check(int n, const string &s) {
    if (n < 0) fail(s);
}

void put(const string &p, const string &s) {
    ofstream f(p);
    f << s;
    f.close();
    if (!f) fail(p);
}

bool sendall(int f, const string &s) {
    size_t i = 0;
    while (i < s.size()) {
        ssize_t n = write(f, s.data() + i, s.size() - i);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        i += n;
    }
    return true;
}

string line(int f) {
    string s;
    char c;
    while (s.size() < 65536 && read(f, &c, 1) == 1) {
        if (c == '\n') break;
        s += c;
    }
    return s;
}

struct Job {
    pid_t pid;
    int master;
    int status = -1;
    bool eof = false;
    vector<int> clients;
    time_t deadline = 0;
    int child = 0;
};

map<int, Job> jobs;

void isolated(vector<string> a, bool overlay, int userns, int netns, int ready) {
    uid_t u = getuid();
    gid_t g = getgid();
    if (userns >= 0) {
        // Joining the owning user namespace grants the capabilities needed for setns(net).
        check(setns(userns, CLONE_NEWUSER), "join user namespace");
        check(setns(netns, CLONE_NEWNET), "join network namespace");
        close(userns);
        close(netns);
    }
    else {
        check(unshare(CLONE_NEWUSER), "user namespace");
        put("/proc/self/setgroups", "deny");
        put("/proc/self/uid_map", "0 " + to_string(u) + " 1");
        put("/proc/self/gid_map", "0 " + to_string(g) + " 1");
    }
    check(unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC |
                  (netns < 0 ? CLONE_NEWNET : 0)),
          "namespaces");
    check(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr), "private mounts");

    check(sethostname("minibox", 7), "hostname");
    int ns = socket(AF_INET, SOCK_DGRAM, 0);
    ifreq r{};
    strcpy(r.ifr_name, "lo");
    check(ioctl(ns, SIOCGIFFLAGS, &r), "loopback get");
    r.ifr_flags |= IFF_UP;
    check(ioctl(ns, SIOCSIFFLAGS, &r), "loopback up");
    close(ns);

    int hostproc = open("/proc", O_PATH | O_DIRECTORY);
    check(hostproc, "host proc");
    vector<int> devices;
    for (const char* name : {"null", "zero", "random", "urandom", "tty"}) {
        int fd = open((string("/dev/") + name).c_str(), O_RDWR);
        check(fd, "open device");
        devices.push_back(fd);
    }

    string root = a[0];
    if (overlay) {
        string pattern = base + "/layers-XXXXXX";
        vector<char> name(pattern.begin(), pattern.end());
        name.push_back(0);
        char* dir = mkdtemp(name.data());
        if (!dir) fail("overlay directory");
        string layer = dir;
        for (const char* part : {"upper", "work", "merged"})
            check(mkdir((layer + "/" + part).c_str(), 0700), "overlay mkdir");
        // Legacy mount options use comma/colon/backslash as delimiters.
        if (root.find_first_of(",:\\") != string::npos ||
            layer.find_first_of(",:\\") != string::npos) {
            errno = EINVAL;
            fail("unsupported character in overlay path");
        }
        string options = "lowerdir=" + root + ",upperdir=" + layer + "/upper,workdir=" + layer +
                         "/work,userxattr";
        root = layer + "/merged";
        check(mount("overlay", root.c_str(), "overlay", MS_NOSUID | MS_NODEV, options.c_str()),
              "overlay mount");
        put(base + "/" + to_string(getpid()) + ".layer", layer + "\n");
    }
    check(chdir(root.c_str()), "rootfs");
    check(mount(".", ".", nullptr, MS_BIND | MS_REC, nullptr), "rootfs bind");
    check(chroot("."), "chroot");
    check(chdir("/"), "chdir");
    mkdir("/proc", 0755);
    mkdir("/dev", 0755);

    check(mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=755"), "dev");
    int di = 0;
    for (const char* name : {"null", "zero", "random", "urandom", "tty"}) {
        string path = string("/dev/") + name;
        int fd = open(path.c_str(), O_CREAT | O_RDWR, 0666);
        close(fd);
        string src = "self/fd/" + to_string(devices[di++]);
        int cwd = open("/", O_PATH);
        check(fchdir(hostproc),
              "host proc cwd"); /* bind through host proc before replacing proc below */
        check(mount(src.c_str(), path.c_str(), nullptr, MS_BIND, nullptr), "device bind");
        check(fchdir(cwd), "restore cwd");
        close(cwd);
    }
    for (int fd : devices) close(fd);
    close(hostproc);
    mkdir("/dev/pts", 0755);
    check(mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
                "newinstance,ptmxmode=0666,mode=0620"),
          "devpts");
    check(symlink("pts/ptmx", "/dev/ptmx"), "device symlink");
    check(symlink("/proc/self/fd", "/dev/fd"), "device symlink");
    check(symlink("/proc/self/fd/0", "/dev/stdin"), "device symlink");
    check(symlink("/proc/self/fd/1", "/dev/stdout"), "device symlink");
    check(symlink("/proc/self/fd/2", "/dev/stderr"), "device symlink");

    pid_t p = fork();
    check(p, "fork PID1");
    if (p) {
        close(ready);
        int st;
        while (waitpid(p, &st, 0) < 0 && errno == EINTR) {
        }
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st));
    }

    check(mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr), "proc");
    sendall(ready, "ready\n");
    close(ready);
    vector<char*> av;
    for (size_t i = 1; i < a.size(); ++i) av.push_back(a[i].data());
    av.push_back(nullptr);
    setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
    execvp(av[0], av.data());
    fail("exec");
}

int connect_server() {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un a{};
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, (base + "/socket").c_str(), sizeof(a.sun_path) - 1);
    if (connect(s, (sockaddr*)&a, sizeof(a)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

void daemon_main() {
    signal(SIGPIPE, SIG_IGN);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un a{};
    a.sun_family = AF_UNIX;
    string path = base + "/socket";
    if (path.size() >= sizeof(a.sun_path)) fail("socket path too long");
    strcpy(a.sun_path, path.c_str());
    check(bind(srv, (sockaddr*)&a, sizeof(a)), "bind");
    check(listen(srv, 32), "listen");
    put(base + "/daemon.pid", to_string(getpid()));

    for (;;) {
        vector<pollfd> f{{srv, POLLIN, 0}};
        vector<pair<int, int>> key{{0, 0}};
        for (auto &[id, j] : jobs) {
            if (!j.eof) {
                f.push_back({j.master, POLLIN, 0});
                key.push_back({id, 0});
            }
            for (int c : j.clients) {
                f.push_back({c, POLLIN, 0});
                key.push_back({id, c});
            }
        }

        poll(f.data(), f.size(), 100);
        for (size_t i = 1; i < f.size(); ++i)
            if (f[i].revents) {
                auto &j = jobs.at(key[i].first);
                char buf[8192];
                int n = read(f[i].fd, buf, sizeof(buf));
                if (!key[i].second) {
                    if (n > 0) {
                        string s(buf, n);
                        ofstream log(base + "/" + to_string(j.pid) + ".log",
                                     ios::app | ios::binary);
                        log << s;
                        for (int c : j.clients) sendall(c, s);
                    }
                    else {
                        j.eof = true;
                        close(j.master);
                        for (int c : j.clients) close(c);
                        j.clients.clear();
                    }
                }
                else {
                    if (n > 0 && !j.eof)
                        sendall(j.master, string(buf, n));
                    else {
                        close(f[i].fd);
                        auto &v = j.clients;
                        v.erase(remove(v.begin(), v.end(), f[i].fd), v.end());
                    }
                }
            }

        for (auto &[id, j] : jobs)
            if (j.status < 0) {
                if (j.deadline && time(nullptr) >= j.deadline) {
                    kill(j.child, SIGKILL);
                    j.deadline = 0;
                }
                int st;
                if (waitpid(id, &st, WNOHANG) == id)
                    j.status = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            }

        if (!(f[0].revents & POLLIN)) continue;
        int c = accept(srv, nullptr, nullptr);
        if (c < 0) continue;
        timeval timeout{2, 0};
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        string cmd = line(c);

        if (cmd == "run" || cmd == "run2") {
            bool overlay = false;
            int target = 0;
            if (cmd == "run2") {
                overlay = line(c) == "overlay";
                string network = line(c);
                if (network != "private") {
                    char* end = nullptr;
                    long value = strtol(network.c_str(), &end, 10);
                    if (!end || *end || value <= 0 || value > 2147483647) {
                        sendall(c, "error: invalid network container PID\n");
                        close(c);
                        continue;
                    }
                    target = value;
                }
            }
            int n = atoi(line(c).c_str());
            vector<string> args;
            for (int i = 0; i < n && i < 1024; i++) args.push_back(line(c));
            if (args.size() < 2) {
                close(c);
                continue;
            }
            int userns = -1, netns = -1;
            if (target) {
                auto it = jobs.find(target);
                if (it == jobs.end() || it->second.status >= 0 || it->second.eof) {
                    sendall(c, "error: network container is not running\n");
                    close(c);
                    continue;
                }
                string proc = "/proc/" + to_string(target) + "/ns/";
                userns = open((proc + "user").c_str(), O_RDONLY | O_CLOEXEC);
                netns = open((proc + "net").c_str(), O_RDONLY | O_CLOEXEC);
                if (userns < 0 || netns < 0) {
                    if (userns >= 0) close(userns);
                    if (netns >= 0) close(netns);
                    sendall(c, "error: cannot open target namespaces\n");
                    close(c);
                    continue;
                }
            }
            int ready[2];
            check(pipe2(ready, O_CLOEXEC), "startup pipe");
            int m;
            pid_t p = forkpty(&m, nullptr, nullptr, nullptr);
            if (p == 0) {
                close(srv);
                close(c);
                for (auto &[id, j] : jobs) {
                    if (!j.eof) close(j.master);
                    for (int x : j.clients) close(x);
                }
                close(ready[0]);
                isolated(args, overlay, userns, netns, ready[1]);
                _exit(125);
            }
            close(ready[1]);
            if (userns >= 0) close(userns);
            if (netns >= 0) close(netns);
            if (p < 0) {
                sendall(c, "-1\n");
            }
            else {
                jobs.emplace(p, Job{p, m, -1, false, {}, 0, 0});
                pollfd startup{ready[0], POLLIN, 0};
                if (poll(&startup, 1, 10000) > 0 && line(ready[0]) == "ready")
                    sendall(c, to_string(p) + "\n");
                else {
                    kill(-p, SIGKILL);
                    sendall(c, "error: container setup failed; see logs " + to_string(p) + "\n");
                }
            }
            close(ready[0]);
            close(c);
            continue;
        }
        if (cmd == "list") {
            for (auto &[id, j] : jobs)
                sendall(c, to_string(id) + " " +
                               (j.status < 0 ? "running" : "exited " + to_string(j.status)) + "\n");
            close(c);
            continue;
        }
        int id = atoi(line(c).c_str());
        auto it = jobs.find(id);
        if (it == jobs.end()) {
            sendall(c, "unknown container\n");
            close(c);
            continue;
        }
        auto &j = it->second;
        if (cmd == "kill") {
            // namespace wrapper owns PID1; kill descendants through proc children
            if (j.status < 0) {
                string children;
                ifstream in("/proc/" + to_string(id) + "/task/" + to_string(id) + "/children");
                getline(in, children);
                int child = atoi(children.c_str());
                if (child > 0) {
                    kill(child, SIGTERM);
                    j.child = child;
                    j.deadline = time(nullptr) + 3;
                }
            }
            sendall(c, "ok\n");
            close(c);
        }
        else if (cmd == "wait") {
            sendall(c, to_string(j.status) + "\n");
            close(c);
        }
        else if (cmd == "attach" || cmd == "follow" || cmd == "logs") {
            if (cmd != "attach") {
                ifstream in(base + "/" + to_string(id) + ".log", ios::binary);
                sendall(c, string(istreambuf_iterator<char>(in), {}));
            }
            if (cmd != "logs" && !j.eof)
                j.clients.push_back(c);
            else
                close(c);
        }
        else
            close(c);
    }
}

int main(int argc, char** argv) {
    umask(0077);
    base = string(getenv("XDG_RUNTIME_DIR") ? getenv("XDG_RUNTIME_DIR") : "/tmp") + "/minibox-" +
           to_string(getuid());
    filesystem::create_directories(base);
    if (argc < 2) {
        cerr << "runtime daemon|run [-d] [--overlay] [--network PID] ROOTFS COMMAND "
                "[ARGS...]|list|logs [-f] PID|attach "
                "PID|kill PID\n";
        return 2;
    }
    string cmd = argv[1];
    if (cmd == "daemon") {
        if (connect_server() >= 0) return 0;
        unlink((base + "/socket").c_str());
        pid_t p = fork();
        check(p, "daemon fork");
        if (p) return 0;
        setsid();
        int nullfd = open("/dev/null", O_RDWR);
        for (int fd = 0; fd < 3; fd++) dup2(nullfd, fd);
        if (nullfd > 2) close(nullfd);
        daemon_main();
        return 0;
    }
    int s = connect_server();
    if (s < 0) {
        cerr << "Start runtime daemon first\n";
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    bool raw = false;
    int id = 0;
    bool foreground = false;
    if (cmd == "run") {
        int off = 2;
        bool detach = false, overlay = false;
        string network = "private";
        while (off < argc) {
            string option = argv[off];
            if (option == "-d")
                detach = true;
            else if (option == "--overlay")
                overlay = true;
            else if (option == "--network" && off + 1 < argc)
                network = argv[++off];
            else if (option == "--") {
                ++off;
                break;
            }
            else if (option.size() && option[0] == '-') {
                cerr << "Unknown or incomplete option: " << option << endl;
                return 2;
            }
            else
                break;
            ++off;
        }
        if (network.find_first_of("\r\n") != string::npos) return 2;
        if (argc - off < 2) return 2;
        string req = "run2\n" + string(overlay ? "overlay" : "direct") + "\n" + network + "\n" +
                     to_string(argc - off) + "\n";
        for (int i = off; i < argc; i++) {
            string v = i == off ? filesystem::canonical(argv[i]).string() : argv[i];
            if (v.find('\n') != string::npos) return 2;
            req += v + "\n";
        }
        sendall(s, req);
        string response = line(s);
        id = atoi(response.c_str());
        close(s);
        if (id <= 0) cerr << response << endl;
        if (id <= 0) return 125;
        if (detach) {
            cout << id << endl;
            return 0;
        }
        foreground = true;
        s = connect_server();
        sendall(s, "follow\n" + to_string(id) + "\n");
        raw = true;
    }
    else {
        bool follow = cmd == "logs" && argc > 2 && string(argv[2]) == "-f";
        int off = follow ? 3 : 2;
        if (cmd != "list" && argc <= off) return 2;
        sendall(s,
                (follow ? "follow" : cmd) + "\n" + (cmd == "list" ? "" : string(argv[off]) + "\n"));
        raw = cmd == "attach";
    }
    termios old{};
    bool tty = raw && isatty(0) && tcgetattr(0, &old) == 0;
    if (tty) {
        termios t = old;
        cfmakeraw(&t);
        tcsetattr(0, TCSANOW, &t);
    }
    bool input = raw;
    for (;;) {
        pollfd f[2] = {{s, POLLIN, 0}, {input ? 0 : -1, POLLIN, 0}};
        if (poll(f, 2, -1) < 0) continue;
        char b[8192];
        if (f[0].revents) {
            int n = read(s, b, sizeof(b));
            if (n <= 0) break;
            sendall(1, string(b, n));
        }
        if (f[1].revents) {
            int n = read(0, b, sizeof(b));
            if (n <= 0)
                input = false;
            else {
                if (memchr(b, 29, n)) break;
                sendall(s, string(b, n));
            }
        }
    }
    if (tty) tcsetattr(0, TCSANOW, &old);
    close(s);
    if (foreground) {
        for (;;) {
            s = connect_server();
            sendall(s, "wait\n" + to_string(id) + "\n");
            int st = atoi(line(s).c_str());
            close(s);
            if (st >= 0) return st;
            usleep(100000);
        }
    }
    return 0;
}
