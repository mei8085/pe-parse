# PE 解析中重叠节区地址与目录边界的分析报告

分析对象：本仓库 `pe-parser-library/src/parse.cpp` 与 `pe-parser-library/src/buffer.cpp`，
核对依据：`tests/directory_bounds_test.cpp` 中构造的具体字节布局。

## 1. 地址换算链：文件偏移、RVA 与 VA

解析器在 `getSections()`（parse.cpp:1010）中为每个节区建立两条坐标系：

- **虚拟坐标**：`sectionBase = ImageBase + VirtualAddress`（64 位无符号，32/64 位可选头分别取
  对应 ImageBase）。RVA 到 VA 的换算是 `VA = ImageBase + RVA`（`rvaToVA`，parse.cpp:627）。
- **文件坐标**：`sectionData = splitBufferByLength(fileBegin, PointerToRawData, SizeOfRawData)`
  （parse.cpp:1064）。节区数据视图**只覆盖 `SizeOfRawData` 字节**，且必须完整落在文件内，
  否则 `splitBufferByLength` 返回 `nullptr`，整个解析以 `PEERR_SECT` 失败（GH#109 的修复，
  对应测试 "oversized section raw data range is rejected"：raw 范围取 `kFileSize-4` 起 5 字节，
  越出文件 1 字节即拒绝）。

VA 到节区的归属判定在 `getSecForVA()`（parse.cpp:613）：

```cpp
std::uint64_t low  = s.sectionBase;
std::uint64_t high = low + s.sec.Misc.VirtualSize;
if (v >= low && v < high) { ... }   // 半开区间 [base, base+VirtualSize)
```

注意 `high` 用的是 64 位加法，RVA 接近 4GB 边界（如测试中的节区 RVA `0xffffff00`）时
不会回绕——这是 "overflowing export directory range can contain forwarded exports"
测试能正确解析转发导出的前提。

## 2. 节区虚拟尾部的归属规则

归属判定只看 `Misc.VirtualSize`，由此产生三个重要推论：

1. **零填充尾（VirtualSize > SizeOfRawData）归属节区，但没有字节支撑。**
   RVA 落在 `[VirtualAddress + SizeOfRawData, VirtualAddress + VirtualSize)` 区间时，
   `getSecForVA` 成功（该 VA 被此节区"认领"），但随后对 `sectionData` 的任何读都因
   `offset >= bufLen` 失败（buffer.cpp 中 `readByte` 返回 `PEERR_ADDRESS`）。
   也就是说：加载器在内存中会把这段填零，而 pe-parse 把它当作"属于节区但读不到"。
   目录头落在这里 → 读取失败；后果因目录类型而异（见第 4 节）。

2. **VirtualSize < SizeOfRawData 时，原始数据的尾部不可达。**
   加载器实际会映射 `max(VirtualSize, SizeOfRawData)`（向上对齐到 SectionAlignment），
   而 pe-parse 只认 `VirtualSize`。RVA 落在 `[VirtualAddress + VirtualSize,
   VirtualAddress + SizeOfRawData)` 的目录会被判为"不属于任何节区"，
   `getSecForVA` 失败。这是与 Windows 加载器的第一处解析差。

3. **VirtualSize == 0 的节区不拥有任何 VA**（区间为空，归属判定即失败），
   而部分真实样本（corkami 测试集中的 `virtsectblXP.exe` 等）依赖加载器
   此时回退使用 SizeOfRawData 的行为——这类样本在 corkami 冒烟测试的
   已知失败清单 `kKnownPEFailure` 中。

另外，头部区域（RVA 小于第一个节区的 `VirtualAddress`，即 `SizeOfHeaders` 覆盖的范围）
不属于任何节区，位于头部内的目录在 pe-parse 中无法解析；Windows 加载器却会映射头部。
这是第二处解析差。

## 3. 重叠节区的归属规则

`getSections()` 在收集完节区后按 **`PointerToRawData`（文件偏移）排序**（parse.cpp:1078），
而不是按 `VirtualAddress` 或头表顺序。`getSecForVA` 线性扫描、**首个命中者胜出**，因此：

- 两个节区虚拟区间重叠时，**文件偏移较小的节区赢得重叠区**，目录读取的字节来自
  该节区的 `sectionData`。
- Windows 加载器按节区头表顺序映射，**后映射者覆盖先映射者**，即头表中靠后的节区
  赢得重叠区。

两者规则不同：攻击者可以构造一个文件偏移很小、但头表位置靠前的"影子节区"覆盖
正常节区的虚拟区间，使 pe-parse 从影子节区的原始字节解析目录，而加载器运行时
使用的是另一份字节。这是典型的**解析器差分（parser differential）**，可用于对
基于 pe-parse 的静态分析隐藏真实的导入/导出/重定位信息。

## 4. 用具体字节布局核对各目录的边界行为

测试布局（`makeMinimalPe`）：NT 头在 `0x80`，节区 RVA `0x2000`，原始偏移 `0x200`，
原始大小 `0x1200`，文件大小 `0x1400`；节区虚拟区间 `[0x2000, 0x3200)`，
`sectionEndRva() = 0x3200`。

### 4.1 底层切片原语：`splitBufferByLength`（buffer.cpp:359）

判定为 `from > bufLen || len > bufLen - from` 时返回 `nullptr`，减法写法避免了
`from + len` 的 32 位溢出。测试核对：

| 请求 | 结果 |
|---|---|
| `(4, 4)` on 8 字节缓冲 | 成功，恰好止于末尾 |
| `(8, 0)`（末尾空切片） | 成功，`bufLen == 0` |
| `(5, 4)` on 8 字节缓冲 | `nullptr`（越界 1 字节） |
| `(4, UINT32_MAX)` | `nullptr`（溢出安全） |

所有目录边界行为最终都归结到这一个"恰好止于边界合法、越界 1 字节即拒绝"的规则。

### 4.2 调试目录（DIR_DEBUG）

- 条目数 = `debugDir.Size / sizeof(debug_dir_entry)`，条目头用 `READ_DWORD` 宏读取，
  **任何字段越界 → `getDebugDir` 返回 false → 整个解析失败**（`PEERR_MAGIC`）。
- 条目数据：`splitBufferByLength(dataSec.sectionData, dataofft, SizeOfData)`。
  - 数据恰好止于节界（`SizeOfData=4, AddressOfRawData=0x3200-4`）→ **接受**，
    回调收到 `bufLen == 4`。
  - 越界 1 字节（`SizeOfData=5`）→ **跳过该条目及后续所有条目**（`break`），
    解析整体成功，调试条目数为 0。
  - `SizeOfData = 0xFFFFFFFF`（`dataofft + size` 会溢出）→ 同样被
    `splitBufferByLength` 的减法判定安全拦截，跳过。
- 条目 RVA 不属于任何节区 → 同样 `break` 跳过（注释明确说这是有意宽松，
  因为真实样本常有畸形调试条目）。

**不对称点**：目录条目头越界是致命的，条目数据越界是容忍的。

### 4.3 通用目录读取：`GetDataDirectoryEntry`（parse.cpp:2900）

- `DIR_SECURITY` 是特例：`VirtualAddress` 按规范是**文件偏移**而非 RVA，
  直接在 `fileBuffer` 上切片。
- 其余目录：`getSecForVA` 定位节区后，要求**整个 `[off, off+Size)` 完整落在
  该节区原始数据内**。测试核对：目录 `[0x31FC, 4)` 恰好止于节界 → 接受；
  大小改为 5 → 返回 false 且 `PEERR_SIZE`，输出清空。
- 这是**运行期 API**：拒绝只影响本次调用，不影响已完成的解析。
- `Size == 0` 直接 `PEERR_SIZE` 拒绝。

### 4.4 导出目录（DIR_EXPORT）

- 目录头、EAT、名称指针表、序号表各自独立经 `getSectionForRVA` 定位，
  可以分散在不同节区；表项索引用 `checkedTableOffset` 做溢出检查，
  EAT 索引限制在 `UINT16_MAX` 以内。
- **转发判定**（`rvaInDataDirectory`，parse.cpp:609）：EAT 中的符号 RVA 落在
  `[exportDir.VirtualAddress, +Size)` 内 → 当作转发字符串（C 字符串）读取；
  否则直接当作代码 RVA，`entry.addr = ImageBase + symRVA`，**不校验该 RVA
  是否属于任何节区**。
- 序号为空的 EAT 槽（`symRVA == 0`）静默跳过；纯序号导出、命名/序号混合
  导出均有测试覆盖。
- 失败传播：`parseExports` 失败时 `getExports` 返回 `exportDir.Size == 0`
  ——即**目录 VA 非零但 Size 为零的畸形情况被容忍**，Size 非零则整个解析失败。

### 4.5 导入目录（DIR_IMPORT）

- 模块名、查找表、符号名全部经 `getSecForVA` 解析，**任何一步失败 → 整个解析失败**。
  导入描述符与查找表均无数量上限，仅靠全零终止项或读取越界结束。
- 符号名逐字节读取直到 NUL，唯一边界是节区末尾。

### 4.6 重定位目录（DIR_BASERELOC）

- 循环条件是 `while (rvaofft < relocDir.Size)`，其中 `rvaofft` 是**节区内偏移**
  （`vaAddr - d.sectionBase`），却与**目录大小**比较。只有目录恰好从节区起始
  开始时这才正确；目录位于节区中部时会**静默提前终止**（少解析），
  是一处边界缺陷。
- `entryCount = (blockSize - 8) / 2`：`blockSize < 8` 时 32 位减法下溢为巨大值，
  随后读到节区末尾才由 `readWord` 失败终止，且**整个解析失败**。

### 4.7 资源目录（.rsrc）

- 递归深度限制为 3（防无限递归），`NameEntries + IDEntries` 决定条目数。
- 资源数据越界时**不报错**：`rdat.RVA < virtaddr`（减法下溢检测）或切片失败时，
  静默返回**零长度 buffer**（注释说明是为兼容加壳样本）。条目结构本身越界
  仍然致命（`PEERR_RESC`）。

### 4.8 符号表

- 直接使用 `PointerToSymbolTable` **文件偏移**在 `fileBuffer` 上读，与 RVA 换算无关，
  每次读取都有边界检查，越界即致命。

## 5. 严格拒绝与宽松逆向的取舍

| 行为 | 归类 | 理由 |
|---|---|---|
| 节区 raw 范围越出文件 → 整体拒绝（`PEERR_SECT`） | 严格 | 节区视图是一切后续解析的地基，地基不完整则所有地址换算都不可信 |
| 目录条目头越界（导入/重定位/调试条目头/导出 Size≠0）→ 整体失败 | 严格 | 结构性损坏会继续传播到后续每条记录，难以界定可信前缀 |
| 调试条目数据越界 → 跳过该条及后续，解析成功 | 宽松 | 调试信息对分析是可选的，真实样本常见畸形（代码注释明确说明） |
| 资源数据越界 → 返回空 buffer，保留条目元数据 | 宽松 | 兼容加壳样本；RVA/size 元数据仍有分析价值 |
| 导出目录 VA 非零但 Size==0 且解析失败 → 容忍 | 宽松 | 兼容现实中 Size 字段不准确的样本 |
| `GetDataDirectoryEntry` 越界 → 调用期拒绝，不影响解析结果 | 严格（局部） | 把决定权交给调用方，已解析状态不受污染 |
| 空 EAT 槽跳过、资源表空条目数合法 | 宽松 | 规范允许的常态 |

总体取向：**结构骨架严格、叶数据宽松**。骨架（节区表、目录条目头）出错时
宁可整体拒绝，因为继续解析会把不可信字节当结构解释；叶数据（调试负载、
资源负载）出错时降级为空/跳过，保住其余可分析内容。对逆向场景这是合理的
兼容取舍——但下面的例外需要注意。

## 6. 会把攻击者控制的数据误当有效结构的情形

1. **导出转发判定可被翻转**（影响最大）。`rvaInDataDirectory` 用的
   `exportDir.Size` 来自可选头、完全由攻击者控制：把 Size 改大可让正常的
   代码 RVA 落入目录范围而被当作转发字符串解析；改小可让转发字符串被当作
   代码地址。且字符串内容本身就是文件字节，`forwardName` 原样进入分析结果。

2. **导出地址不校验归属**。非转发的 EAT 条目直接 `addr = ImageBase + symRVA`，
   不检查该 RVA 是否落在任何节区内。任意垃圾 RVA 都会作为"有效导出地址"
   出现在结果中。

3. **重叠节区劫持目录来源**。结合第 3 节：攻击者放置一个 `PointerToRawData`
   更小、虚拟区间覆盖目标目录的影子节区，pe-parse 就会从攻击者挑选的
   原始字节解析导入/导出/重定位，而加载器看到的是另一份——静态分析与
   运行时行为被系统性分离。

4. **重定位循环的静默截断**。目录不在节区起始处时 `rvaofft < relocDir.Size`
   的比较会少解析重定位块，结果看似正常实则不完整；攻击者可借此让部分
   重定位从分析中消失而不触发任何错误。

5. **资源数据越界静默置空**。攻击者可以让资源条目元数据看似合法而负载为空，
   分析端无法区分"本来就没有数据"与"数据被刻意越界隐藏"。

6. **VirtualSize 与加载器映射语义的差距**（第 2 节推论 2、3）。攻击者把数据
   放在 `VirtualSize` 之外、加载器实际会映射的区域内，pe-parse 判其"不属于
   任何节区"而加载器照常使用——又一处可用于隐藏的解析差。

相对地，以下路径**不会**把越界数据当有效结构：`splitBufferByLength` 的
减法边界判定对所有切片调用（节区、调试数据、目录条目、DIR_SECURITY）都是
精确且溢出安全的；`checkedTableOffset` 保护了导出表索引；`readByte/readDword`
的 `offset >= bufLen` 检查保证任何读取都不会越过节区视图取到相邻节区或
堆外字节。越界的结局只有三种：整体拒绝、跳过条目、返回空数据——
风险集中在上面列出的"语义层面误解释"，而非内存安全或边界算术。
