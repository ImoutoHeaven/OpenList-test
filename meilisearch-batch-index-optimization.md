# [Feature] Meilisearch在自动更新索引开启情况下应该调用BatchIndex减少POST请求数量

## 问题背景

当 Meilisearch 作为搜索引擎时，OpenList 支持自动更新索引功能。在用户浏览目录时，系统会自动检测新增文件并将其添加到搜索索引中。

### 当前实现存在的问题

在 `internal/search/build.go` 的 `Update` 函数中（第202-268行），当检测到目录下有新增文件时，采用的是**逐个文件索引**的方式：

```go
for i := range objs {
    if toAdd.Contains(objs[i].GetName()) {
        if !objs[i].IsDir() {
            err = Index(ctx, parent, objs[i])  // ❌ 每个文件一个POST请求
            if err != nil {
                log.Errorf("update search index error while index new node: %+v", err)
                return
            }
        }
    }
}
```

**性能问题**：
- 假设一个目录有 100 个新文件
- 当前实现会向 Meilisearch 发送 **100 个独立的 POST 请求**
- 导致大量 HTTP 开销，索引更新缓慢

### Update 函数的触发机制

通过代码追踪发现：

```
用户浏览目录
  → op.List(ctx, storage, path)                    // fs.go:138
     → storage.List(ctx, dir, args)               // 获取目录下所有文件
        → HandleObjsUpdateHook(reqPath, files)    // fs.go:153，异步调用
           → Update(parent, objs)                 // build.go:202
```

- **触发时机**：每次用户浏览/列出一个目录时触发
- **传入参数 `objs`**：该目录下的**所有文件**（不是单个文件）
- **调用方式**：异步 goroutine

因此，`Update` 函数一次性接收到一个目录下的所有文件，完全具备批量索引的条件。

## 优化方案

### 方案描述

将逐个文件索引改为**批量索引**，利用已有的 `BatchIndex` 函数，该函数内部使用 Meilisearch SDK 的 `AddDocumentsInBatchesWithContext` 方法，会自动按照 **10,000 个文档**为单位进行分批处理。

### 修改细节

**位置**：`internal/search/build.go` 的 `Update` 函数（第245-276行）

**修改前**：
```go
for i := range objs {
    if toAdd.Contains(objs[i].GetName()) {
        if !objs[i].IsDir() {
            log.Debugf("add index: %s", path.Join(parent, objs[i].GetName()))
            err = Index(ctx, parent, objs[i])  // 逐个索引
            if err != nil {
                log.Errorf("update search index error while index new node: %+v", err)
                return
            }
        } else {
            // build index if it's a folder
            ...
        }
    }
}
```

**修改后**：
```go
// collect files to add in batch
var toAddObjs []ObjWithParent
for i := range objs {
    if toAdd.Contains(objs[i].GetName()) {
        if !objs[i].IsDir() {
            log.Debugf("add index: %s", path.Join(parent, objs[i].GetName()))
            toAddObjs = append(toAddObjs, ObjWithParent{
                Parent: parent,
                Obj:    objs[i],
            })
        } else {
            // build index if it's a folder
            ...
        }
    }
}
// batch index all files at once
if len(toAddObjs) > 0 {
    err = BatchIndex(ctx, toAddObjs)
    if err != nil {
        log.Errorf("update search index error while batch index new nodes: %+v", err)
        return
    }
}
```

### 技术实现说明

**调用链**：
```
Update 函数
  └─> BatchIndex(ctx, toAddObjs)  // search/search.go:71
       └─> instance.BatchIndex(ctx, searchNodes)  // 转换为 []model.SearchNode
            └─> m.Client.Index(m.IndexUid).AddDocumentsInBatchesWithContext(ctx, documents, 10000)
                // meilisearch/search.go:103
```

**自动分批机制**：
- `AddDocumentsInBatchesWithContext` 的第三个参数为 `10000`
- Meilisearch Go SDK 会自动将文档数组切分为每批最多 10,000 个文档
- 例如：如果有 25,000 个文件，会自动分成 3 个 POST 请求（10,000 + 10,000 + 5,000）

## 性能提升

### 场景对比

**场景**：用户浏览一个包含 100 个新文件的目录

| 实现方式 | POST 请求数 | 网络开销 | 索引速度 |
|---------|------------|---------|---------|
| **修改前** | 100 次 | 高（100次HTTP往返） | 慢 |
| **修改后** | 1 次 | 低（1次HTTP往返） | 快 |

**场景**：用户浏览一个包含 25,000 个新文件的目录

| 实现方式 | POST 请求数 | 网络开销 |
|---------|------------|---------|
| **修改前** | 25,000 次 | 极高 |
| **修改后** | 3 次（自动分批） | 低 |

### 优化效果

1. **大幅减少 HTTP 请求数量**：从 N 次减少到 ⌈N/10000⌉ 次
2. **降低网络开销**：减少 TCP 连接建立、TLS 握手等开销
3. **提升索引速度**：批量操作减少了网络延迟的累积影响
4. **减少服务器负载**：Meilisearch 服务器处理批量请求更高效

## 兼容性说明

### 不影响其他索引场景

1. **BuildIndex**（初次构建索引）：
   - 位置：`build.go:33-188`
   - 已经使用批量索引机制（通过消息队列收集后批量发送）
   - **不受本次修改影响**

2. **文件夹索引**：
   - 当检测到新增的是文件夹时，调用 `BuildIndex` 递归构建
   - **不受本次修改影响**

### 向后兼容

- 修改仅涉及内部实现，不改变对外接口
- 不影响现有配置和使用方式
- 完全向后兼容

## 其他说明

### 关于 Index 函数的未来

当前 `Index` 函数（`search/search.go:54-64`）的实现：
```go
func Index(ctx context.Context, parent string, obj model.Obj) error {
    // ...
    return instance.Index(ctx, model.SearchNode{...})
}
```

而 `instance.Index` 在 Meilisearch 实现中（`meilisearch/search.go:80-82`）：
```go
func (m *Meilisearch) Index(ctx context.Context, node model.SearchNode) error {
    return m.BatchIndex(ctx, []model.SearchNode{node})  // 内部也调用 BatchIndex
}
```

**建议**：
- 可考虑将 `Index` 函数标记为废弃（deprecated）
- 统一使用 `BatchIndex` 作为索引接口
- 或保留 `Index` 作为便捷方法（wrapper）

## 总结

通过将 `Update` 函数中的逐个文件索引改为批量索引，可以显著减少 POST 请求数量，提升自动索引更新的性能，且不影响其他功能和向后兼容性。这是一个低风险、高收益的优化。
