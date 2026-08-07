# TraceLens 开发分支与协作约定

## 分支职责

```text
main
└── 稳定、可发布版本

dev
└── 集成开发与测试分支

feat/*
└── 具体功能开发分支
```

- `main` 只保留经过验证的稳定版本。
- `dev` 用于合并多个功能、联调和阶段性测试。
- `feat/*` 用于实际开发，不直接在 `main` 或 `dev` 上长期开发。
- 文档改动可以使用 `docs/*` 分支；小型文档改动也可以和对应功能放在同一个功能分支中。
- 紧急线上修复使用 `hotfix/*`，合并到 `main` 后同步回 `dev`。

## 推荐工作流

### 1. 从 `dev` 创建功能分支

```bash
git switch dev
git pull --ff-only origin dev
git switch -c feat/process-tracking
```

分支命名建议：

```text
feat/<功能名>
fix/<问题名>
docs/<文档主题>
refactor/<重构主题>
hotfix/<紧急修复>
```

### 2. 在功能分支开发并推送

```bash
git add <files>
git commit -m "feat: add process tracking"
git push -u origin feat/process-tracking
```

提交应保持小而清晰，代码和必要的文档、测试尽量一起提交。

### 3. 创建 Pull Request

功能分支完成后，创建：

```text
feat/* → dev
```

合并前至少确认：

- 构建或测试通过；
- 相关文档已更新；
- 没有把调试文件、日志、数据库或密钥提交进仓库；
- PR 描述说明了改动内容、验证方式和已知限制。

### 4. 从 `dev` 发布到 `main`

当 `dev` 完成一个可交付阶段并通过整体验证后，创建：

```text
dev → main
```

合并到 `main` 后，可以按需要创建版本标签，并继续在 `dev` 上开展下一阶段工作。

## 文档目录约定

```text
docs/
├── road_map.md
├── development_workflow.md
├── architecture.md
├── deployment.md
└── decisions/
```

- `road_map.md`：产品目标、MVP 范围和阶段规划。
- `development_workflow.md`：分支、提交和 PR 约定。
- `architecture.md`：系统架构和模块边界。
- `deployment.md`：构建、运行和部署说明。
- `decisions/`：重要技术决策记录，采用一事一文的方式保存。

## TraceLens 当前分支状态

当前基线为：

```text
main: c4e60b1 docs: add TraceLens roadmap
dev:  从 main 创建，作为后续开发集成分支
```

后续新功能默认从 `dev` 创建功能分支，完成后通过 PR 合并回 `dev`，不要直接提交到 `main`。
