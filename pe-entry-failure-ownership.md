# pe-parse 三入口失败行为与资源所有权分析

对象：pe-parser-library（`pe-parser-library/src/parse.cpp`、`src/buffer.cpp`，提交 166ced0）。
方法：基于实际代码走查 + 最小 PE 样本探针（ASan/UBSan，g++ 13.3，Linux）。探针源码在 `/tmp/peprobe/probe.cpp`，用 `-fsanitize=address,undefined` 编译库与探针后按子命令运行各场景。最小样本布局复用 `tests/directory_bounds_test.cpp` 的构造方式（e_lfanew=0x80，单节区 RVA 0x2000 / 文件偏移 0x200 / 大小 0x1200）。

## 1. 三个入口的所有权模型（代码依据）

三个入口最终都汇入 `ParsePEFromBuffer`（parse.cpp:2557），差异只在 bounded_buffer 的获取方式：

| 入口 | 缓冲区来源 | `copy` 标志 | 底层内存归属 |
|---|---|---|---|
| `ParsePEFromFile` (parse.cpp:2646) | `readFileToFileBuffer`：mmap 文件，`detail` 持有 fd（buffer.cpp:212-341） | `false` | 库拥有（munmap+close） |
| `ParsePEFromPointer` (parse.cpp:2657) | `makeBufferFromPointer`：对调用方内存的非拥有视图（buffer.cpp:323-340） | `true` | 调用方拥有 |
| `ParsePEFromBuffer` (parse.cpp:2557) | 调用方手工构造的 bounded_buffer | 取决于构造方式 | 包装结构归库，底层内存归属不变 |

关键事实：

- `copy` 字段名有误导性，实际语义是"释放包装时是否一并释放底层内存"。`deleteBuffer`（buffer.cpp:371-389）只在 `copy==false` 时 munmap/close，然后无条件 `delete detail; delete b`。
- `ParsePEFromBuffer` **无论成功还是失败都接管传入的 bounded_buffer**：所有失败路径都走 `DestructParsedPE`（parse.cpp:2668），其中 `deleteBuffer(p->fileBuffer)`（parse.cpp:2673）。这是实测确认的契约，但头文件与 README 均未文档化。
- `splitBufferByLength`（buffer.cpp:347-369）是唯一的长度闸门：`from > bufLen || len > bufLen - from` 时返回 nullptr；它产生的是 `copy=true` 的视图，节区、资源、调试数据全部是指向同一底层内存的视图。
- 解析期间产生的所有中间视图（ntBuf/ohb/fhb/remaining 等）在失败路径上均被正确释放，探针在合法调用序列下未观察到泄漏或重复释放。

## 2. 同一截断/恶意样本经三入口的实测结果

| 样本 | file | pointer | buffer | 说明 |
|---|---|---|---|---|
| S1 仅 "MZ" 2 字节 | nullptr, err=6 @readNtHeader:1216 | 同左 | 同左 | 三入口一致 |
| S2 DOS 头完整、无 NT 头（0x40） | nullptr, err=6 @readNtHeader:1216 | 同左 | 同左 | e_lfanew 读出为 0（值初始化），magic 校验失败 |
| S3 截断于可选头中部 | nullptr, err=6 @readOptionalHeader:1091 | 同左 | 同左 | 一致 |
| S4 无节表（NumberOfSections=1 但文件到此为止） | nullptr, err=3 @ParsePEFromBuffer:2593 | 同左 | 同左 | 内部 PEERR_READ 被覆盖为 PEERR_SECT |
| S5 空输入 | **err=1 PEERR_MEM** @readFileToFileBuffer:310 | **err=9 PEERR_MAGIC** @getHeader:1477 | 同 pointer | **唯一实测的入口间错误码差异** |
| M1 NumberOfSections=0xFFFF | nullptr, err=3 PEERR_SECT | 同左 | 同左 | 节表越界读被 readByte 拦截 |
| M2 节 SizeOfRawData 远超 EOF | nullptr, err=3 PEERR_SECT | 同左 | 同左 | GH#109 修复后 splitBufferByLength 返回 nullptr → 整体失败 |
| M3 调试目录 Size=0xFFFFFFFF、条目 SizeOfData 越节区 | **解析成功** | 同左 | 同左 | 坏条目被跳过（parse.cpp:1975-1985），但 GetPEErr 残留前一次失败值 |
| M4 .rsrc 数据 RVA 落在节区外 | **解析成功** | 同左 | 同左 | 产生伪有效资源，见 §4 |

结论：截断样本上三入口的解析行为完全一致（解析逻辑共享），差异只出现在缓冲区获取阶段。S5 的差异来自 `mmap(…, 0, …)` 返回 EINVAL 被当作 PEERR_MEM 上报，而指针/缓冲区入口的零长视图会走到 magic 校验报 PEERR_MAGIC——同一空输入、两种错误码，且 PEERR_MEM 是误标。

## 3. 差异归因：无效调用 vs 库侧缺陷

### 3.1 属于无效调用（调用方违反契约，库无法防御）

- `ParsePEFromPointer(nullptr, 100)`：返回 nullptr，err=1 PEERR_MEM。结果可预测，但错误码误标（参数错误报成内存不足）。
- `ParsePEFromBuffer(nullptr)`：返回 nullptr 且 **GetPEErr()==0（None）**，完全静默失败（own4 实测）。这是库未设错误码，但触发前提是空指针调用。
- `ParsePEFromBuffer(b)` 失败后调用方再 `deleteBuffer(b)`：ASan 报告 heap-use-after-free（buffer.cpp:376，own1 实测）。**失败也算接管**，重复释放责任在调用方，但契约未文档化是库的问题。
- 指针入口下调用方在 `DestructParsedPE` 之前释放底层内存，之后 `IterSec` 回调读到已释放内存：ASan heap-use-after-free（own2 实测）。parsed_pe 内所有节区/资源/调试数据都是视图，调用方必须保证底层内存活得比 parsed_pe 久。
- `sz` 大于实际分配长度：库无任何手段发现，会按声明长度越界读调用方内存。属契约违规。
- `DestructParsedPE` 后调用方再释放自己的 data 是安全的（own3 实测：库不碰调用方内存）；文件入口 `DestructParsedPE` 后映射失效，调用方本就无可释放之物。

### 3.2 属于库侧缺陷（合法调用下可观察）

- **全局错误状态粘滞**：`err`/`err_loc` 是全局变量（parse.cpp:498-499），成功路径不复位。own6 实测：先失败后成功，`GetPEErr()` 仍返回上一次失败的 6。M3/M4 解析成功时同样观察到残留 err=3。多线程下还会互相覆盖。
- **错误码被覆盖/误标**：`getExports`/`getRelocations`/`getDebugDir` 失败一律被覆盖为 PEERR_MAGIC（parse.cpp:2608/2616/2623）；`getImports`/`getSymbolTable` 失败甚至不设错误码，沿用旧值。dir-api B 实测：导出目录 VA 指向节内但内容垃圾 → 整个解析失败，报错 err=9 "Bad magic"，与 magic 无关，直接误导逆向分析方向。`getSections` 失败时内部更具体的 PEERR_READ/PEERR_ADDRESS 也被 PEERR_SECT 覆盖（parse.cpp:2593）。
- **伪有效资源**：资源数据 RVA 越节区时，解析回退到零长视图（parse.cpp:950-956），资源条目照常入列。M4 实测 `IterRsrc` 输出 `type=10, RVA=0x52000, size=0x1234, bufLen=0`——`size` 声称 0x1234 而缓冲区为空。消费方若按 `res.size` 读 `res.buf->buf` 即越界读（视图指向节区数据起点，读 0x1234 字节会越过节区甚至越过调用方缓冲区）。逆向工具会把这条资源当作"存在但内容为空"的有效结构。
- **空文件误标**：文件入口对空文件报 PEERR_MEM（mmap 长度 0 失败），与指针入口的 PEERR_MAGIC 不一致。
- **`readDosHeader` 返回值被忽略**（parse.cpp:1474）：截断的 DOS 头靠 `new parsed_pe()` 值初始化兜底（字段为 0），行为确定但脆弱；若哪天改为非值初始化即变成未初始化读取。
- **Windows 分支句柄泄漏**（仅代码审查，本次在 Linux 验证）：`readFileToFileBuffer` 中 `CreateFileMapping`/`MapViewOfFile` 失败路径未关闭已打开的句柄（buffer.cpp:266-293）。

## 4. 越界与重复释放的实际边界

- 库内部所有对样本字节的读取都经 `readByte/Word/Dword/Qword` 的 `offset + n - 1 >= bufLen` 检查（buffer.cpp:104-210），样本本身恶意不会导致库越界读；M1/M2/M3 在 ASan 下均无越界。
- 越界风险集中在**视图语义外溢**：(a) 调用方 `sz` 虚报；(b) 调用方提前释放底层内存（own2）；(c) 消费方信任伪有效资源的 `size` 字段（§3.2）。
- 重复释放风险集中在 `ParsePEFromBuffer` 的失败接管语义未文档化（own1），以及成功后将同一 buffer 再 `deleteBuffer`。
- 目录长度边界：`GetDataDirectoryEntry`（parse.cpp:2900-2964）对 DIR_SECURITY 用文件偏移、其余用 VA→节区映射，越界时干净地返回 false + PEERR_SIZE（dir-api A/C 实测），无崩溃；但解析期的导出/重定位/调试目录垃圾会导致**整体解析失败**而非跳过该目录（dir-api B），与调试目录"坏条目跳过"的宽松策略（parse.cpp:1975-1985）不一致。

## 5. 各入口失败后的可观察契约

| | ParsePEFromFile | ParsePEFromPointer | ParsePEFromBuffer |
|---|---|---|---|
| 返回值 | nullptr | nullptr | nullptr |
| 可能的 err | PEERR_OPEN(7) 文件不存在；PEERR_MEM(1) 空文件/mmap 失败；其余与解析阶段相同 | PEERR_MEM(1) 空指针；解析阶段错误 | 解析阶段错误；nullptr 入参时**不设错误** |
| 调用方资源责任 | 无（库已 munmap/close） | 保留 data 所有权，可立即释放或复用 | **不得再 deleteBuffer**（已被库释放）；底层数据仍归调用方 |
| 成功时的责任 | 仅 `DestructParsedPE` | data 必须活得比 parsed_pe 久；`DestructParsedPE` 不释放 data | 同指针入口；buffer 包装由 `DestructParsedPE` 释放 |

影响范围：文件入口失败的影响限于当次调用（无残留资源）；指针/缓冲区入口失败的影响是错误码语义（含粘滞与误标）会污染后续 `GetPEErr` 判断；伪有效资源与"目录垃圾 → PEERR_MAGIC"直接影响逆向分析结论的可靠性（把目录解析失败误判为文件损坏/加壳）。

## 6. 需要库侧调整的边界

1. `ParsePEFromBuffer` 对 nullptr 入参设 `PEERR_BUFFER`，消除静默失败。
2. 成功路径复位 `err`/`err_loc`（或文档化粘滞语义）；长期应把错误状态移入 per-context 结构以支持多线程。
3. 子系统失败不要一律覆盖为 PEERR_MAGIC/PEERR_SECT：保留内部错误码，或为目录解析失败新增专门错误码；`getImports`/`getSymbolTable` 失败必须设错误码。
4. 空文件 mmap 失败映射为 PEERR_OPEN 或 PEERR_SIZE；`makeBufferFromPointer(nullptr)` 改用 PEERR_BUFFER，统一三入口对空输入的错误语义。
5. 资源数据越界时不要生成 `size != bufLen` 的伪有效 resource：跳过该资源或将 `size` 归零，避免消费方按声明大小越界读。
6. 检查 `readDosHeader` 返回值，截断 DOS 头直接报 PEERR_READ。
7. 导出/重定位目录解析失败应与调试目录一致地降级为"跳过该目录"，或至少给出准确错误码，避免误报 PEERR_MAGIC。
8. 在 `parse.h` 注释与 README 中文档化 `ParsePEFromBuffer` 的失败接管语义和指针入口的调用方存续责任。
9. Windows 分支 `readFileToFileBuffer` 失败路径关闭已打开的 file/mapping 句柄。

## 附：复现方式

```
g++ -std=c++17 -g -O1 -fsanitize=address,undefined \
    -I pe-parser-library/include -c pe-parser-library/src/{parse,buffer,unicode_libicu}.cpp
g++ -std=c++17 -g -O1 -fsanitize=address,undefined \
    -I pe-parser-library/include /tmp/peprobe/probe.cpp parse.o buffer.o unicode_libicu.o \
    -o probe -licuuc -licudata
./probe all      # 截断/恶意样本 × 三入口
./probe own1     # ParsePEFromBuffer 失败后调用方 deleteBuffer → ASan UAF
./probe own2     # 调用方提前释放底层内存 → IterSec ASan UAF
./probe own6     # 错误状态粘滞
./probe dir-api  # 目录长度边界
```
