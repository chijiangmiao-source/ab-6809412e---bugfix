.PHONY: help up build verify test smoke clean

help:
	@echo "make build   构建镜像"
	@echo "make up      构建并启动 web（宿主机端口由 HOST_PORT 配置，默认 8080）"
	@echo "make verify  构建镜像并运行单次 verify 容器，透传其退出码"
	@echo "make test    宿主机直接运行 pytest"

build:
	docker compose build

up:
	docker compose up --build web

# verify 单次容器：pytest + HTTP 冒烟 + 0<=-1 证书核对；退出码透传给调用方
verify:
	docker compose build
	docker compose up --abort-on-container-exit --exit-code-from verify

test:
	python3 -m pytest -q

smoke:
	curl -fsS http://localhost:$${HOST_PORT:-8080}/healthz

clean:
	docker compose down -v
