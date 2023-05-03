#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/inode.h"
#include <string.h>

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    // 1
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  } else if (args[0] == SYS_WRITE) {
    // 9
    struct inode* inode = inode_open(args[1]);
    if (inode == NULL) {
      f->eax = -1;
      return;
    }
    void* buffer = (void*)args[2];
    if (buffer == NULL || !is_user_vaddr(buffer)) {
      f->eax = -1;
      return;
    }
    off_t wr = inode_write_at(inode, buffer, args[3], 0);
    f->eax = wr;
    printf("%s", (char*)buffer);
  } else if (args[0] == SYS_PRACTICE) {
    // 13
    f->eax = args[1] + 1;
  }
}
