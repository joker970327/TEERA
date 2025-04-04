# 文件说明
## miracl_test.cpp
定义不同曲线，循环100次进行pairing操作

## Makefile
使用不同的编译时的环境变量，重复编译miracl_test.cpp

## run_test.sh
运行在当前目录下搜索到的所有test_*.out文件

# 运行
``` 
make -k all
bash ./run_test.sh
 ```

 # 结果说明
 ## makefile
 目前在运行makefile的时候，KSS不能正确编译，在kss_pair.cpp文件下报错
 ```bash
 ../kss_pair.cpp: In member function ‘int PFC::spill(G2&, char*&)’:
../kss_pair.cpp:413:17: error: ‘to_binary’ was not declared in this scope; did you mean ‘from_binary’?
  413 |                 to_binary(a,bytes_per_big,&bytes[j],TRUE);
      |                 ^~~~~~~~~
      |                 from_binary
../kss_pair.cpp: In member function ‘int GT::spill(char*&)’:
../kss_pair.cpp:1360:17: error: ‘to_binary’ was not declared in this scope; did you mean ‘from_binary’?
 1360 |                 to_binary(x,bytes_per_big,&bytes[j],TRUE);
      |                 ^~~~~~~~~
      |                 from_binary
```
## run_test
在运行时MNT部分输出：No suitable curve available
其余曲线正常运行，输出运行时间以及时钟周期数