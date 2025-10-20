# GDB Backtrace Forest Visualizer

A Python tool that processes GDB backtrace (`bt`) outputs and visualizes them as a call forest 🌲.

## Usage

```bash
python3 gdb_bt_forest.py test_bt.txt --threads -g name+file+line
```

Output:
```
=== Thread-2 :: 1 stacks ===
└── _start  [1 | 100.0%]
    └── __libc_start_main  [../csu/libc-start.c:308]  [1 | 100.0%]
        └── main  [test.c:10]  [1 | 100.0%]

=== Thread-1 :: 3 stacks ===
├── _start  [1 | 33.3%]
│   └── __libc_start_main  [../csu/libc-start.c:308]  [1 | 33.3%]
│       └── main  [test.c:10]  [1 | 33.3%]
├── clone  [../sysdeps/unix/sysv/linux/x86_64/clone.S:95]  [1 | 33.3%]
│   └── start_thread  [pthread_create.c:463]  [1 | 33.3%]
│       └── worker_thread  [test.c:25]  [1 | 33.3%]
│           └── sleep  [../sysdeps/unix/sysv/linux/sleep.c:138]  [1 | 33.3%]
│               └── nanosleep  [../sysdeps/unix/syscall-template.S:78]  [1 | 33.3%]
└── main  [test.c:10]  [1 | 33.3%]
    └── bar  [test.c:20]  [1 | 33.3%]
        └── foo  [test.c:15]  [1 | 33.3%]
```

## Author

ChatGPT and jiangyinzuo
