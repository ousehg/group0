#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "lib/float.h"
#include "devices/shutdown.h"
#include <string.h>

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful,
   -1 if a segfault occurred. */
static int get_user(const uint32_t* uaddr) {
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  /* 这里后续可以优化下，所有校验不通过的都走 SYS_EXIT 逻辑*/
  if (pagedir_get_page(thread_current()->pcb->pagedir, args) == NULL) {
    f->eax = -1;
    struct thread* cur = thread_current();
    cur->pcb->exit_code = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();
    return;
  }

  if (args[0] == SYS_HALT) {
    // 0
    shutdown_power_off();
  } else if (args[0] == SYS_EXIT) {
    // 1
    f->eax = args[1];
    struct thread* cur = thread_current();
    cur->pcb->exit_code = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  } else if (args[0] == SYS_EXEC) {
    // 2
    char* name;
    pid_t new_pid_t;

    if (pagedir_get_page(thread_current()->pcb->pagedir, args + 1) == NULL) {
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
      process_exit();
      return;
    }
    if (pagedir_get_page(thread_current()->pcb->pagedir, args + 2) == NULL) {
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
      process_exit();
      return;
    }

    void* last;
    for (last = (void*)args[1]; last < PHYS_BASE; last++) {
      if (pagedir_get_page(thread_current()->pcb->pagedir, last) == NULL) {
        printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
        process_exit();
        return;
      }
      if (get_user((uint32_t*)last) != '\0') {
        continue;
      }
      break;
    }
    if (last == PHYS_BASE) {
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
      process_exit();
      return;
    }

    name = (char*)args[1];
    new_pid_t = process_execute(name);
    // process_wait(new_pid_t);
    f->eax = new_pid_t;
  } else if (args[0] == SYS_WAIT) {
    // 3
    pid_t pid_t;

    pid_t = args[1];
    f->eax = process_wait(pid_t);
  } else if (args[0] == SYS_CREATE) {
    // 4
    char* name = (char*)args[1];
    if (pagedir_get_page(thread_current()->pcb->pagedir, name) == NULL) {
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
    }
    unsigned size = args[2];
    bool created = filesys_create(name, size);
    f->eax = created;
  } else if (args[0] == SYS_REMOVE) {
    // 5
    char* name = (char*)args[1];
    if (pagedir_get_page(thread_current()->pcb->pagedir, name) == NULL) {
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
    }
    bool removed = filesys_remove(name);
    f->eax = removed;
  } else if (args[0] == SYS_OPEN) {
    // 6
    char* name;
    int fd_table_size;
    struct file* file;
    struct fd_entry* fd_entry;

    name = (char*)args[1];
    if (!is_user_vaddr(name)) {
      thread_current()->pcb->exit_code = -1;
      process_exit();
    }
    if (pagedir_get_page(thread_current()->pcb->pagedir, name) == NULL) {
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
    }
    file = filesys_open(name);
    if (file == NULL) {
      f->eax = -1;
      return;
    }
    fd_table_size = list_size(thread_current()->pcb->fd_table);
    fd_entry = malloc(sizeof(*fd_entry));
    fd_entry->fd = fd_table_size + 3;
    fd_entry->file = file;
    list_push_front(thread_current()->pcb->fd_table, &fd_entry->elem);
    f->eax = fd_entry->fd;
  } else if (args[0] == SYS_FILESIZE) {
    // 7
    uint32_t fd;
    struct list_elem* e;
    struct fd_entry* fd_entry;
    struct list* fd_table;

    fd = args[1];
    fd_table = thread_current()->pcb->fd_table;

    switch (fd) {
      case 0:
        break;
      case 1:
        break;
      default:
        for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
          fd_entry = list_entry(e, struct fd_entry, elem);
          if (fd_entry->fd == fd) {
            f->eax = file_length(fd_entry->file);
            return;
          }
        }
        f->eax = -1;
    }
  } else if (args[0] == SYS_READ) {
    // 8
    uint32_t fd;
    size_t size;
    struct list_elem* e;
    struct fd_entry* fd_entry;
    struct list* fd_table;
    void* buffer;

    fd = args[1];
    buffer = (void*)args[2];
    if (!is_user_vaddr(buffer)) {
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
    }
    if (pagedir_get_page(thread_current()->pcb->pagedir, buffer) == NULL) {
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
    }
    fd_table = thread_current()->pcb->fd_table;
    size = args[3];

    switch (fd) {
      case 0:
        break;
      case 1:
        break;
      default:
        for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
          fd_entry = list_entry(e, struct fd_entry, elem);
          if (fd_entry->fd == fd) {
            f->eax = file_read(fd_entry->file, buffer, size);
            return;
          }
        }
        f->eax = -1;
    }
  } else if (args[0] == SYS_WRITE) {
    // 9
    uint32_t fd;
    size_t size;
    off_t wr;
    struct list_elem* e;
    struct fd_entry* fd_entry;
    struct list* fd_table;
    void* buffer;

    fd = args[1];
    buffer = (void*)args[2];
    if (pagedir_get_page(thread_current()->pcb->pagedir, buffer) == NULL) {
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
    }
    size = args[3];
    fd_table = thread_current()->pcb->fd_table;

    switch (fd) {
      case 0:
        break;
      case 1:
        putbuf((char*)buffer, size);
        break;
      default:;
        for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
          fd_entry = list_entry(e, struct fd_entry, elem);
          if (fd_entry->fd == fd) {
            wr = file_write(fd_entry->file, buffer, size);
            f->eax = wr;
            return;
          }
        }
        f->eax = -1;
    }
  } else if (args[0] == SYS_SEEK) {
    // 10
    uint32_t fd;
    unsigned position;
    struct list_elem* e;
    struct fd_entry* fd_entry;
    struct list* fd_table;

    fd = args[1];
    fd_table = thread_current()->pcb->fd_table;
    position = args[3];

    switch (fd) {
      case 0:
        break;
      case 1:
        break;
      default:
        for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
          fd_entry = list_entry(e, struct fd_entry, elem);
          if (fd_entry->fd == fd) {
            file_seek(fd_entry->file, position);
            return;
          }
        }
    }
  } else if (args[0] == SYS_TELL) {
    // 11
    uint32_t fd;
    struct list_elem* e;
    struct fd_entry* fd_entry;
    struct list* fd_table;
    fd = args[1];
    fd_table = thread_current()->pcb->fd_table;

    switch (fd) {
      case 0:
        break;
      case 1:
        break;
      default:
        for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
          fd_entry = list_entry(e, struct fd_entry, elem);
          if (fd_entry->fd == fd) {
            f->eax = file_tell(fd_entry->file);
            return;
          }
        }
        f->eax = -1;
    }
  } else if (args[0] == SYS_CLOSE) {
    // 12
    uint32_t fd;
    struct list_elem* e;
    struct fd_entry* fd_entry;
    struct list* fd_table;
    fd = args[1];
    fd_table = thread_current()->pcb->fd_table;
    switch (fd) {
      case 0:
        break;
      case 1:
        break;
      default:
        for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
          fd_entry = list_entry(e, struct fd_entry, elem);
          if (fd_entry->fd == fd) {
            file_close(fd_entry->file);
            list_remove(e);
            free(fd_entry);
            return;
          }
        }
        f->eax = -1;
    }
  } else if (args[0] == SYS_PRACTICE) {
    // 13
    f->eax = args[1] + 1;
  } else if (args[0] == SYS_COMPUTE_E) { // 14
    /* huz: Save user's FPU state. */
    uint8_t fpu_state[108];
    asm volatile("fsave (%0)" : : "g"(&fpu_state));
    int n = args[1];
    f->eax = sys_sum_to_e(n);
    /* huz: Restore user's FPU state. */
    asm volatile("frstor (%0)" : : "g"(&fpu_state));
  } else {
    printf("Unknown system call number: %d\n", args[0]);
    thread_exit();
  }
}
