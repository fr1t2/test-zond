---
outline: deep
---
# Installing on Windows

This page contains instructions for installing the Zond node on Windows.

## Downloading binaries

The Zond node & PoS validator are available as pre-compiled binaries for Windows. The latest release can be downloaded from the [releases page](https://theqrl.org/downloads/). **===TBD===**

## Building from Source

### Dependencies

The Zond node requires the following dependencies to be installed:

- [Git for Windows](https://git-scm.com/download/win)
- [Golang for Windows](https://golang.org/dl/) v1.21 or later
- MinGW [direct install](https://sourceforge.net/projects/mingw-w64/files/latest/download) or via [Chocolatey](https://chocolatey.org/packages/mingw)*

*_This dependency to be removed in the future._

### Clone the Zond repositories

```cmd.exe
git clone https://github.com/theQRL/go-zond.git
git clone https://github.com/theQRL/qrysm.git
```

### Build the Zond node with Golang v1.21 or later

```cmd.exe
cd go-zond
go build .\cmd\gzond
copy build\bin\cmd\gzond.exe ..\
cd ..
```

### Ensure Golang v1.20 is available to build the validator

```cmd.exe
go install golang.org/dl/go1.20@latest
go1.20 download
```

### Build the validator

```cmd.exe
cd qrysm
go1.20 build -o=../qrysmctl.exe ./cmd/qrysmctl
go1.20 build -o=../beacon-chain.exe ./cmd/beacon-chain
go1.20 build -o=../validator.exe ./cmd/validator
```