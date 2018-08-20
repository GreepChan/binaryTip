# 任意地址泄露
假设拥有一个可以 leak 任意地址信息的漏洞，那么我们可以泄露与 binary 相关的重要信息，比如某函数的got表项，来泄露服务器libc版本。通过泄露canary值来绕过栈溢出检测。但是canary的地址是栈地址，如何找到我们需要的栈地址呢？ 这里需要满足两个条件：

- 知道libc版本
- 存在任意地址泄露

在libc里面存在一个`environ` 符号，它的值和 `main`函数的第三个参数`char ** envp`相等，而且这个值是落在栈上的，所以我们可以利用这个symbol来leak 栈地址。本地计算偏移后，可以推算出远程的栈地址。

```
(gdb) list 1
1       #include <stdlib.h>
2       #include <stdio.h>
3
4       extern char **environ;
5
6       int main(int argc, char **argv, char **envp)
7       {
8           return 0;
9       }
(gdb) x/gx 0x7ffff7a0e000 + 0x3c5f38
0x7ffff7dd3f38 <environ>:       0x00007fffffffe230
(gdb) p/x (char **)envp
$12 = 0x7fffffffe230
```
同时 $12-0x10的地址上是argv[0],常用于SSP leak。
下面给出一个SSP leak的例题。（environ=libcbase+libc.dump('environ')）