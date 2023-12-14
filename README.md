# Hyperledger Fabric 国密化改造

The origin README.md is [README_ORIGIN.md](README_ORIGIN.md)

## 环境配置

- 尝试使用 Fabric：
  - [安装依赖，暂时安装前两个就行](https://hyperledger-fabric.readthedocs.io/en/latest/getting_started.html)
  - [尝试使用，以检查环境配置](https://hyperledger-fabric.readthedocs.io/en/latest/test_network.html)
- 尝试编译 Fabric
  - clone 本项目
  - images/** 中的 Dockerfile 需要修改：在安装完 Golang 之后添加官方国内镜像（已改完，仅作说明）
  - [安装依赖](https://hyperledger-fabric.readthedocs.io/en/latest/dev-setup/devenv.html)
  - 编译全部：`make dist-clean all`
