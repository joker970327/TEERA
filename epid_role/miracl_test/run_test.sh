#!/bin/bash

# -print0以null分割文件名
find . -maxdepth 1 -type f -executable -name "test_*.out" -print0 |
# IFS= 将分隔符IFS清空，让read命令不使用IFS进行单词分割
while IFS= read -r -d $'\0' file; do
    echo "==================== $file =================="
    "$file" # 执行文件
    
    # $?: 保存上一个命令的退出状态，0 表示成功，非零值表示错误
    if [ $? -ne 0 ]; then
        echo "ERROR: $file" >&2
    fi
done