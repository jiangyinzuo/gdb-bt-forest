# GDB Backtrace Forest Visualizer

A Python tool that processes GDB backtrace (`bt`) outputs and visualizes them as a call forest 🌲.

**Requirement:** Python 3.7+

## Usage

**Basic Usage**

```bash
python3 gdb_bt_forest.py test_bt1.txt --threads -g name+file+line
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

**Highlight Keyword**

```bash

python3 gdb_bt_forest.py --no-color test_bt1.txt | grep -E 'keyword|$'
# or using ripgrep
python3 gdb_bt_forest.py --no-color test_bt1.txt | rg --max-columns=0 --passthru 'keyword'
```

**Generate Mermaid Diagram**
```bash
python3 gdb_bt_forest.py dag_test_bt.txt --graph mermaid
```

## Author

ChatGPT and jiangyinzuo
