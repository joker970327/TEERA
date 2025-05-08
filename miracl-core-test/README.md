**RA_epid_trans_test.c**

用于测试数据传递

1. 基准值生成：
- 随机 g1, g2，进行 pairing 操作得到 gt
- 随机 A, B，进行modadd操作得到 C
2. 写入文件
- 将 g1, g2, gt, A, B, C 转换为 octet
- 将 octet 的字节写入文件 RA_data.txt
3. 读取文件
- 从文件中读取 Bytes
- 将 Bytes 转换为 octet
- octet 转换得到 g1_r, g2_r, gt_r, A_r, B_r, C_r
4. 验证结果
- g1_r, g2_r, gt_r, A_r, B_r, C_r 分别与 g1, g2, gt, A, B, C 进行比较，验证输出输入转换的正确性
- g1_r, g2_r 进行 pairing 操作得到 gt_c，与 gt 进行比较，验证计算一致性
- A_r, B_r 进行 modadd 操作得到 C_c，与 C 进行比较，验证计算一致性
