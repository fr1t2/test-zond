---
outline: deep
---
# Installing on Windows

::: info
Tested on Windows 10 and Windows 11
:::

This page contains instructions for installing the Zond node on Windows.

## Downloading binaries

The Zond node & PoS validator are available as pre-compiled binaries for some operating systems. The latest releases can be seen and downloaded from the [go-zond releases page](https://github.com/theQRL/go-zond/releases/) and [qrysm releases page](https://github.com/theQRL/qrysm/releases/) on GitHub.

## Building from Source

### Dependencies

The Zond node requires the following dependencies to be installed:

- [Git for Windows](https://git-scm.com/download/win)
- [Golang for Windows](https://golang.org/dl/) v1.21 or later
- [TDM-GCC](https://jmeubank.github.io/tdm-gcc/articles/2021-05/10.3.0-release)*

*_This dependency to be removed in the future._


The following commands should be entered separately, line-by-line, in Windows Command Prompt (i.e. cmd.exe)

### Clone the Zond repositories

```cmd.exe
git clone https://github.com/theQRL/go-zond.git
git clone https://github.com/theQRL/qrysm.git
```

### Build go-zond (the Execution Engine) with Golang v1.21 or later

```cmd.exe
cd go-zond
go build .\cmd\gzond
copy gzond.exe ..\
cd ..
```

### Ensure Golang v1.20 is available to build the Consensus Engine

```cmd.exe
go install golang.org/dl/go1.20@latest
go1.20 download
```

### Build qrsym (Consensus Engine) with Golang v1.20

```cmd.exe
cd qrysm
go1.20 build -o ../qrysmctl.exe ./cmd/qrysmctl
go1.20 build -o ../beacon-chain.exe ./cmd/beacon-chain
go1.20 build -o ../validator.exe ./cmd/validator
```
