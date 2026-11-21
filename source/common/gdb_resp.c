/* Copyright (C) 2024 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <sys/wait.h>

#include "gdb_arch.h"
#include "gdb_pkt.h"
#include "gdb_resp.h"
#include "gdb_sig.h"
#include "log.h"

#define STR_START_WITH(str, prefix) (!memcmp(str, prefix, strlen(prefix)))

typedef struct gdb_session {
  pid_t pid;
  int fd;
  int sig;
  int stdio;
  intptr_t baseaddr;
} gdb_session_t;

static char target_xml[] = "<?xml version=\"1.0\"?>\n"
                           "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
                           "<target>\n"
                           "<architecture>i386:x86-64</architecture>\n"
                           "<osabi>none</osabi>\n"
                           "</target>\n";

static int
gdb_bin_unescape(char *data, int len) {
  char *w = data;
  char *r = data;

  while(r - data < len) {
    char v = *r++;
    if(v != '}') {
      *w++ = v;
      continue;
    }
    *w++ = *r++ ^ 0x20;
  }

  return w - data;
}

static int
gdb_hex2bin(const char *str, void *bin, size_t size) {
  int len = strlen(str);
  uint8_t *ptr = bin;
  int ch;

  if(len > size * 2 || len % 2) {
    return -1;
  }

  memset(bin, 0, size);
  for(int i = 0; i < len; i += 2, ptr++) {
    if(sscanf(str + i, "%02x", &ch) != 1) {
      return -1;
    }
    *ptr = ch;
  }

  return 0;
}

/*
 * Flush stdout of the interior to the connecting client, and look for Ctrl-c
 * sequence from the client.
 */
static int
gdb_response_stdio(gdb_session_t *sess) {
  struct pollfd fds[2];
  char buf[0x100];
  ssize_t len;
  int cnt = 1;

  memset(fds, 0, sizeof(fds));

  fds[0].fd = sess->fd;
  fds[0].events = POLLIN;

  fds[1].fd = sess->stdio;
  fds[1].events = POLLIN;

  if(fds[1].fd > 0) {
    cnt++;
  }

  switch(poll(fds, cnt, 1)) {
    case -1:
      if(gdb_pkt_notify_perror(sess->fd, "poll")) {
        LOG_PERROR("gdb_pkt_notify_perror");
      }
      return SIGSTOP;

    case 0:
      return 0;

    default:
      if(fds[0].revents & POLLIN) {
        if((len = read(sess->fd, buf, 1)) < 0) {
          LOG_PERROR("read");
          return SIGSTOP;
        }

        if(buf[0] == 3) {
          return SIGSTOP;
        }
      }

      if(fds[1].revents & POLLIN) {
        if((len = read(sess->stdio, buf, sizeof(buf))) < 0) {
          if(gdb_pkt_notify_perror(sess->fd, "read")) {
            LOG_PERROR("gdb_pkt_notify_perror");
          }
          return SIGSTOP;
        }

        if(gdb_pkt_notify(sess->fd, buf, len) < 0) {
          if(errno == EINTR) {
            return SIGSTOP;
          }

          LOG_PERROR("gdb_pkt_notify");
          return SIGSTOP;
        }
      }
  }

  return 0;
}

static int
gdb_waitpid(gdb_session_t *sess, char *data, size_t size) {
  int status = 0;
  int res;

  while(1) {
    if((res = waitpid(sess->pid, &status, WNOHANG | WUNTRACED)) < 0) {
      return -1;
    }

    if(!res) {
      if((res = gdb_response_stdio(sess))) {
        kill(sess->pid, res);
      }
      continue;
    }

    if(WIFEXITED(status)) {
      snprintf(data, size, "W%02x", WEXITSTATUS(status));
      return 0;

    } else if(WIFSIGNALED(status)) {
      sess->sig = WTERMSIG(status);
      snprintf(data, size, "X%02x", gdb_sig_fromposix(sess->sig));
      return 0;

    } else if(WIFSTOPPED(status)) {
      sess->sig = WSTOPSIG(status);
      snprintf(data, size, "S%02x", gdb_sig_fromposix(sess->sig));
      return 0;
    }
  }

  return 0;
}

static int
gdb_response_extended_mode(gdb_session_t *sess, const char *data,
                           size_t size) {
  return gdb_pkt_puts(sess->fd, "OK");
}

static int
gdb_response_getsig(gdb_session_t *sess, const char *data, size_t size) {
  int exit_code = 0;

  if(sess->pid > 0) {
    return gdb_pkt_printf(sess->fd, "S%02X", gdb_sig_fromposix(sess->sig));
  } else {
    return gdb_pkt_printf(sess->fd, "W%02X", exit_code);
  }
}

static int
gdb_response_continue(gdb_session_t *sess, const char *data, size_t size) {
  intptr_t addr = 0;
  char buf[32];
  int sig = 0;

  if(sscanf(data, "S%x;%lx", &sig, &addr) != 2) {
    if(sscanf(data, "S%x", &sig) != 1) {
      sscanf(data, "s%lx", &addr);
    }
  }

  sig = gdb_sig_toposix(sig);

  if(gdb_continue(sess->pid, addr, sig)) {
    return gdb_pkt_perror(sess->fd, "gdb_continue");
  }

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}

static int
gdb_response_detach(gdb_session_t *sess, const char *data, size_t size) {
  pid_t pid = sess->pid;

  if(sscanf(data, "D;%x", &pid) != 2) {
    if(strcmp(data, "D")) {
      return -1;
    }
  }

  if(gdb_detach(pid, SIGCONT)) {
    return gdb_pkt_perror(sess->fd, "gdb_detach");
  }

  sess->pid = -1;

  return gdb_pkt_puts(sess->fd, "OK");
}

static int
gdb_response_getregs(gdb_session_t *sess, const char *data, size_t size) {
  uint64_t gprmap[GDB_GPR_MAX];
  char buf[(GDB_GPR_MAX * 16) + 1];
  char hex[16 + 1];

  if(gdb_getregs(sess->pid, gprmap)) {
    return gdb_pkt_perror(sess->fd, "gdb_getregs");
  }

  buf[0] = 0;
  for(int i = GDB_GPR_RAX; i <= GDB_GPR_RIP; i++) {
    sprintf(hex, "%016lx", __builtin_bswap64(gprmap[i]));
    strcat(buf, hex);
  }

  for(int i = GDB_GPR_EFLAGS; i <= GDB_GPR_GS; i++) {
    sprintf(hex, "%08x", __builtin_bswap32(gprmap[i]));
    strcat(buf, hex);
  }

  return gdb_pkt_puts(sess->fd, buf);
}

static int
gdb_response_setregs(gdb_session_t *sess, const char *data, size_t size) {
  uint64_t gprmap[GDB_GPR_MAX];

  data++;
  for(int i = GDB_GPR_RAX; i <= GDB_GPR_RIP; i++) {
    long val;
    if(sscanf(data, "%016lx", &val) != 1) {
      return -1;
    }
    data += 16;
    gprmap[i] = __builtin_bswap64(val);
  }

  for(int i = GDB_GPR_EFLAGS; i <= GDB_GPR_GS; i++) {
    int val;
    if(sscanf(data, "%08x", &val) != 1) {
      return -1;
    }
    data += 8;
    gprmap[i] = __builtin_bswap32(val);
  }

  if(gdb_setregs(sess->pid, gprmap)) {
    return gdb_pkt_perror(sess->fd, "gdb_setregs");
  }

  return gdb_pkt_puts(sess->fd, "OK");
}

static int
gdb_response_kill(gdb_session_t *sess, const char *data, size_t size) {
  if(sess->pid < 0) {
    return gdb_pkt_puts(sess->fd, "");
  }

  if(gdb_detach(sess->pid, SIGKILL)) {
    return gdb_pkt_perror(sess->fd, "gdb_detach");
  }

  return 0;
}

static int
gdb_response_getmem(gdb_session_t *sess, const char *data, size_t size) {
  char dbuf[GDB_PKT_MAX_SIZE / 2];
  char sbuf[GDB_PKT_MAX_SIZE];
  intptr_t addr;
  char hex[17];
  size_t len;

  if(sscanf(data, "m%lx,%lx:", &addr, &len) != 2) {
    return -1;
  }

  if(sizeof(dbuf) <= len) {
    return -1;
  }

  if(gdb_copyout(sess->pid, addr, dbuf, len)) {
    return gdb_pkt_printf(sess->fd, "E%02X", errno);
  }

  sbuf[0] = 0;
  for(size_t i = 0; i < len; i += 8) {
    long *word = (long *)&dbuf[i];
    sprintf(hex, "%016lx", __builtin_bswap64(*word));
    strcat(sbuf, hex);
  }
  sbuf[len * 2] = 0;

  return gdb_pkt_puts(sess->fd, sbuf);
}

static int
gdb_response_setmem(gdb_session_t *sess, const char *data, size_t size) {
  intptr_t addr;
  size_t len;
  char *buf;
  int r;

  if(sscanf(data, "M%lx,%lx:", &addr, &len) != 2) {
    return gdb_pkt_printf(sess->fd, "E00");
  }
  if(!(data = strstr(data, ":"))) {
    return -1;
  }

  if(!(buf = malloc(len))) {
    return -1;
  }
  if(gdb_hex2bin(data + 1, buf, len)) {
    free(buf);
    return -1;
  }

  if(gdb_copyin(sess->pid, buf, addr, len)) {
    r = gdb_pkt_printf(sess->fd, "E%02X", errno);
  } else {
    r = gdb_pkt_puts(sess->fd, "OK");
  }

  free(buf);

  return r;
}

static int
gdb_response_getreg(gdb_session_t *sess, const char *data, size_t size) {
  enum gdb_gpr reg;
  uint64_t val;

  if(sscanf(data, "p%x", &reg) != 1) {
    return -1;
  }

  if(gdb_getreg(sess->pid, reg, &val)) {
    return gdb_pkt_perror(sess->fd, "gdb_getreg");
  }

  if(reg <= GDB_GPR_RIP) {
    return gdb_pkt_printf(sess->fd, "%016lx", __builtin_bswap64(val));
  } else {
    return gdb_pkt_printf(sess->fd, "%08lx", __builtin_bswap32(val));
  }
}

static int
gdb_response_setreg(gdb_session_t *sess, const char *data, size_t size) {
  enum gdb_gpr reg;
  uint64_t val;

  if(sscanf(data, "P%x=%lx", &reg, &val) != 2) {
    return -1;
  }

  if(reg <= GDB_GPR_RIP) {
    val = __builtin_bswap64(val);
  } else {
    val = __builtin_bswap32(val);
  }

  if(gdb_setreg(sess->pid, reg, val)) {
    return gdb_pkt_perror(sess->fd, "gdb_getreg");
  }

  return gdb_pkt_puts(sess->fd, "OK");
}

static int
gdb_response_attached(gdb_session_t *sess, const char *data, size_t size) {
  return gdb_pkt_printf(sess->fd, "%d", sess->pid > 0);
}

static int
gdb_response_offsets(gdb_session_t *sess, const char *data, size_t size) {
  return gdb_pkt_printf(sess->fd, "Text=%lx;Data=%lx;Bss=%lx", sess->baseaddr,
                        sess->baseaddr, sess->baseaddr);
}

static int
gdb_response_supported(gdb_session_t *sess, const char *data, size_t size) {
  char s[0x100];

  sprintf(s, "PacketSize=%x", GDB_PKT_MAX_SIZE);
  strcat(s, ";qXfer:features:read+");

  return gdb_pkt_puts(sess->fd, s);
}

static int
gdb_response_transfer(gdb_session_t *sess, const char *data, size_t size) {
  if(STR_START_WITH(data, "qXfer:features:read:target.xml:")) {
    return gdb_pkt_printf(sess->fd, "l%s", target_xml);
  }

  return gdb_pkt_printf(sess->fd, "");
}

static int
gdb_response_step(gdb_session_t *sess, const char *data, size_t size) {
  intptr_t addr = 0;
  char buf[32];
  int sig = 0;

  if(sscanf(data, "S%x;%lx", &sig, &addr) != 2) {
    if(sscanf(data, "S%x", &sig) != 1) {
      sscanf(data, "s%lx", &addr);
    }
  }

  sig = gdb_sig_toposix(sig);

  if(gdb_step(sess->pid, addr, sig)) {
    return gdb_pkt_perror(sess->fd, "gdb_step");
  }

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}

static int
gdb_response_attach(gdb_session_t *sess, const char *data, size_t size) {
  char buf[32];
  pid_t pid;

  if(sscanf(data, "vAttach;%x", &pid) != 1) {
    return -1;
  }

  if(gdb_attach(pid)) {
    return gdb_pkt_perror(sess->fd, "gdb_attach");
  }

  sess->pid = pid;
  sess->stdio = -1;

  if(gdb_waitpid(sess, buf, sizeof(buf))) {
    return gdb_pkt_perror(sess->fd, "gdb_waitpid");
  }

  return gdb_pkt_puts(sess->fd, buf);
}

static int
gdb_response_setfs(gdb_session_t *sess, const char *data, size_t size) {
  return gdb_pkt_puts(sess->fd, "F0");
}

static int
gdb_response_fsopen(gdb_session_t *sess, const char *data, size_t size) {
  char filename[PATH_MAX];
  char buf[PATH_MAX * 2];
  char *tok;
  int flags;
  int mode;
  int fd;

  data += 11;
  strcpy(buf, data);
  if(!(tok = strstr(buf, ","))) {
    return -1;
  }
  *tok = 0;

  if(gdb_hex2bin(buf, filename, sizeof(filename))) {
    return -1;
  }
  if(sscanf(tok + 1, "%x,%x", &flags, &mode) != 2) {
    return -1;
  }

  if((fd = open(filename, flags | O_CREAT, mode)) < 0) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", errno);
  }

  return gdb_pkt_printf(sess->fd, "F%x", fd);
}

static int
gdb_response_fsclose(gdb_session_t *sess, const char *data, size_t size) {
  int fd;

  if(sscanf(data, "vFile:close:%x", &fd) != 1) {
    return -1;
  }

  if(close(fd)) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", errno);
  } else {
    return gdb_pkt_puts(sess->fd, "F0");
  }
}

static int
gdb_response_fswrite(gdb_session_t *sess, const char *data, size_t size) {
  const char *tok;
  ssize_t len;
  off_t off = 0;
  void *buf;
  int fd;
  int r;

  if(sscanf(data, "vFile:pwrite:%x,%lx", &fd, &off) != 2) {
    return -1;
  }
  if(lseek(fd, off, SEEK_SET) == -1) {
    return gdb_pkt_printf(sess->fd, "F-1,%x", errno);
  }

  if(!(tok = strstr(data, ","))) {
    return -1;
  }
  if(!(tok = strstr(tok + 1, ","))) {
    return -1;
  }

  tok += 1;
  if((len = (size - (size_t)(tok - data))) < 0) {
    return -1;
  }
  if(!(buf = malloc(len))) {
    return -1;
  }

  memcpy(buf, tok, len);
  len = gdb_bin_unescape(buf, len);

  if((len = write(fd, buf, len)) == -1) {
    r = gdb_pkt_printf(sess->fd, "F-1,%x", errno);
  } else {
    r = gdb_pkt_printf(sess->fd, "F%x", len);
  }

  free(buf);

  return r;
}

static int
gdb_response_run(gdb_session_t *sess, const char *data, size_t size) {
  char filename[PATH_MAX];
  char *argv[] = { filename, 0 };
  int fds[2];

  data += 5;
  if(gdb_hex2bin(data, filename, sizeof(filename))) {
    return -1;
  }

  if(pipe(fds) == -1) {
    return gdb_pkt_perror(sess->fd, "pipe");
  }

  if(fcntl(fds[0], F_SETFL, O_NONBLOCK) == -1) {
    close(fds[0]);
    close(fds[1]);
    return gdb_pkt_perror(sess->fd, "fcntl");
  }

  if((sess->pid = gdb_spawn(argv, fds[1], &sess->baseaddr)) < 0) {
    close(fds[0]);
    close(fds[1]);
    return gdb_pkt_printf(sess->fd, "X-1,%d", errno);
  }

  close(fds[1]);
  sess->sig = SIGSTOP;
  sess->stdio = fds[0];

  printf("Attached to PID: %d, ELF: %s\n", sess->pid, filename);

  return gdb_pkt_printf(sess->fd, "S%02X", gdb_sig_fromposix(sess->sig));
}

static int
gdb_response(void *ctx, const char *data, size_t size) {
  gdb_session_t *sess = (gdb_session_t *)ctx;

  switch(data[0]) {
    case '!':
      return gdb_response_extended_mode(sess, data, size);

    case '?':
      return gdb_response_getsig(sess, data, size);

    case 'c':
    case 'C':
      return gdb_response_continue(sess, data, size);

    case 'D':
      return gdb_response_detach(sess, data, size);

    case 'g':
      return gdb_response_getregs(sess, data, size);

    case 'G':
      return gdb_response_setregs(sess, data, size);

    case 'k':
      return gdb_response_kill(sess, data, size);

    case 'm':
      return gdb_response_getmem(sess, data, size);

    case 'M':
      return gdb_response_setmem(sess, data, size);

    case 'p':
      return gdb_response_getreg(sess, data, size);

    case 'P':
      return gdb_response_setreg(sess, data, size);

    case 'q':
      if(STR_START_WITH(data, "qAttached")) {
        return gdb_response_attached(sess, data, size);
      }
      if(!strcmp(data, "qOffsets")) {
        return gdb_response_offsets(sess, data, size);
      }
      if(STR_START_WITH(data, "qSupported")) {
        return gdb_response_supported(sess, data, size);
      }
      if(STR_START_WITH(data, "qXfer")) {
        return gdb_response_transfer(sess, data, size);
      }
      return gdb_pkt_puts(sess->fd, "");

    case 's':
    case 'S':
      return gdb_response_step(sess, data, size);

    case 'v':
      if(STR_START_WITH(data, "vAttach")) {
        return gdb_response_attach(sess, data, size);
      }
      if(STR_START_WITH(data, "vFile:setfs")) {
        return gdb_response_setfs(sess, data, size);
      }
      if(STR_START_WITH(data, "vFile:open")) {
        return gdb_response_fsopen(sess, data, size);
      }
      if(STR_START_WITH(data, "vFile:close")) {
        return gdb_response_fsclose(sess, data, size);
      }
      if(STR_START_WITH(data, "vFile:pwrite")) {
        return gdb_response_fswrite(sess, data, size);
      }
      if(STR_START_WITH(data, "vRun")) {
        return gdb_response_run(sess, data, size);
      }

    default:
      return gdb_pkt_puts(sess->fd, "");
  }

  return -1;
}

void
gdb_response_session(int fd) {
  gdb_session_t sess
      = { .fd = fd, .pid = -1, .sig = 0, .stdio = -1, .baseaddr = 0 };

  while(1) {
    if(gdb_pkt_get(fd, gdb_response, &sess)) {
      break;
    }
  }

  if(sess.fd > 0) {
    close(sess.fd);
  }
  if(sess.stdio > 0) {
    close(sess.stdio);
  }
  if(sess.pid > 0) {
    kill(sess.pid, SIGKILL);
  }
}
