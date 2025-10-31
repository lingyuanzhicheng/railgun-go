# 使用Go官方镜像作为构建环境
FROM golang:1.19-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的工具
RUN apk add --no-cache git

# 复制go.mod和go.sum文件（如果存在）
COPY go.* ./

# 下载依赖
RUN go mod download || true

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o railgun .

# 使用轻量级的alpine镜像作为最终镜像
FROM alpine:latest

# 安装必要的工具
RUN apk --no-cache add ca-certificates tzdata

# 设置时区
ENV TZ=Asia/Shanghai

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/railgun .

# 复制静态资源
COPY --from=builder /app/static ./static
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/database ./database

# 暴露端口
EXPOSE 8080

# 设置入口点
CMD ["./railgun"]
