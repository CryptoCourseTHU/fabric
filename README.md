# Hyperledger Fabric 国密化改造

The origin README.md is [README_ORIGIN.md](README_ORIGIN.md)

## 环境配置

- 尝试使用 Fabric：
  - [安装依赖，暂时安装前两个就行](https://hyperledger-fabric.readthedocs.io/en/latest/getting_started.html)
  - [尝试使用，以检查环境配置](https://hyperledger-fabric.readthedocs.io/en/latest/test_network.html)
- 尝试编译 Fabric
  - clone 本项目
  - images/** 中的 Dockerfile 需要修改：在安装完 Golang 之后添加官方国内镜像（已改完，仅作说明）

  ```dockerfile
  RUN curl -sL https://go.dev/dl/go${GO_VER}.${TARGETOS}-${TARGETARCH}.tar.gz | tar zxf - -C /usr/local
  ENV PATH="/usr/local/go/bin:$PATH"
  RUN go env -w GOPROXY='https://goproxy.cn,direct'
  ```

  - [安装依赖](https://hyperledger-fabric.readthedocs.io/en/latest/dev-setup/devenv.html)，主要是`make gotools`。基于硬件加密的依赖可能单元测试会用到，但和国密改造关系不大。
  - 编译全部：`make dist-clean all`

## 改造思路

- 开源 国密算法库（SM2/3/4）：<https://github.com/tjfoc/gmsm>
- 需要改造的部分主要是 BCCSP （区块链加密服务提供者）
  - 主要位于 `bccsp/**`。
  - 其他部分需要使用加密服务时，通过 工厂模式 ( `factory.GetDefault()` ) 获得一个 BCCSP 实例，并将其通过传入 MSP （主要就是`msp/**`）的封装函数来使用
    - MSP：Membership Service Provider
    - MSP 用来通过识别不同节点的角色，来提供鉴权服务（因为 Fabric 是联盟链）
    - 在 服务运行时 表现为一个 msp 文件夹，在源码中表现为 `msp package`
    - [对BCCSP的说明](https://hyperledgercn.github.io/hyperledgerDocs/blockchain-crypto-service-provider_zh/#bccsp)
- 从 `GetDefault()` 看起，分为两部分：
  - 正常情况下在 GetDefault 之前需要调用 initFactory，该函数会根据 config YAML 文件给 defaultBCCSP 赋值。
  - 在测试中可能 不会调用 initFactory，所以返回 bootBCCSP
  - 所以首先需要将以上两部分改为 实例化 一个国密 BCCSP

  ```go
  // GetDefault returns a non-ephemeral (long-term) BCCSP
  func GetDefault() bccsp.BCCSP {
  if defaultBCCSP == nil {
    logger.Debug("Before using BCCSP, please call InitFactories(). Falling back to bootBCCSP.")
    bootBCCSPInitOnce.Do(func() {
      var err error
      bootBCCSP, err = (&SWFactory{}).Get(GetDefaultOpts())
      if err != nil {
        panic("BCCSP Internal error, failed initialization with GetDefaultOpts!")
      }
    })
    return bootBCCSP
  }
  return defaultBCCSP
  }
  ```

- 实现一个 国密 BCCSP
  - 基本上是模仿 sw（原有的基于软件的加密实现）实现 gm
  - 顺着 调用顺序：`factory.InitFactory() -> SWFactory.Get -> NewWithParams(new.go) -> New()(impl.go)(获得CTF实例) -> 返回 NewWithParams(注册所有功能的所有实现)`
  - 在 sw factory 中，最终构建了一个 CTF （CTF struct 是 BCCSP interface 的一个实现）
  - CTF 中为每个功能构建了一个 映射表
    - 通过传入 key（如 Encrypt） 或者 option（如 Hash）来选择对应的实现
    - 通过 option/key 的动态类型（ `reflect.Type` ）来判断选择那种实现（SHA或SM2这种），在通过 option/key 的具体值来选择实现的可变细节
  - （尝试新建一个 gm factory 调用 sw 的底层实现，从抽象到具体逐层替换并测试？
