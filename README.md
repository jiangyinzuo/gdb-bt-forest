# GDB Backtrace Forest Visualizer

A Python tool that processes GDB backtrace (`bt`) outputs and visualizes them as a call forest 🌲.

## Usage

```bash
python3 gdb_bt_forest.py test_bt.txt --threads -g name+file+line
```

Output:
```
=== Thread-1 :: 3 stacks ===
├── _start  [2 | 66.7%]
│   └── __libc_start_main  [2 | 66.7%]
│       └── main  [2 | 66.7%]
└── main  [1 | 33.3%]
    └── bar  [1 | 33.3%]
        └── foo  [1 | 33.3%]

=== Thread-2 :: 1 stacks ===
└── clone  [1 | 100.0%]
    └── start_thread  [1 | 100.0%]
        └── worker_thread  [1 | 100.0%]
            └── sleep  [1 | 100.0%]
                └── nanosleep  [1 | 100.0%]
```

## Author

ChatGPT and jiangyinzuo
