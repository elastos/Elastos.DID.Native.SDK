# Elastos DID Native SDK

|Linux && Mac|Windows|
|:-:|:-:|
|[![Build Status](https://github.com/elastos/Elastos.DID.Native.SDK/workflows/CI/badge.svg)](https://github.com/elastos/Elastos.DID.Native.SDK/actions)| |

## Introduction

**Elastos DID (Decentralized Identifier) framework** is a set of C APIs for Elastos DID that is compatible with W3C DIDs specs.

DID (Decentralized identifier) is a new type of identifier that enables verifiable, decentralized digital identity. A DID identifies any subject (e.g., a person, organization, thing, data model, abstract entity, etc.) that the controller of the DID decides that it identifies.

## Table of Contents

- [Elastos DID Native SDK](#elastos-DID-native-sdk)
  - [Introduction](#introduction)
  - [Table of Contents](#table-of-contents)
  - [Usage](#usage)
  - [Build on Ubuntu / Debian / Linux Host](#build-on-ubuntu--linux-host)
    - [1. Brief introduction](#1-brief-introduction)
    - [2. Install Pre-Requirements](#2-install-pre-requirements)
    - [3. Build to run on host (Ubuntu / Debian / Linux)](#3-build-to-run-on-host-ubuntu--debian--linux)
    - [4. Run DIDTest](#4-run-didtest)
      - [4.1. Normal Test](#5-normal-test)
      - [4.2. Stress Test](#5-stress-test)
      - [4.3. Dummy Test](#5-dummy-test)
    - [5. Cross-compilation for Android Platform](#5-cross-compilation-for-android-platform)
  - [Build on macOS Host](#build-on-macos-host)
    - [1. Brief introduction](#1-brief-introduction-2)
    - [2. Install Pre-Requirements](#2-install-pre-requirements-2)
    - [3. Build to run on host](#3-build-to-run-on-host-1)
    - [4. Run DIDTest](#4-run-didtest-2)
      - [4.1. Normal Test](#5-normal-test)
      - [4.2. Stress Test](#5-stress-test)
      - [4.3. Dummy Test](#5-dummy-test)
    - [5. Cross-compilation for Android Platform](#5-cross-compilation-for-android-platform-1)
    - [6. Cross-compilation for iOS Platform](#6-cross-compilation-for-ios-platform)
  - [Build on Windows Host](#build-on-windows-host)
    - [1. Brief introduction](#1-brief-introduction-3)
    - [2. Set up Environment](#2-set-up-environment)
    - [3. Build to run on host](#3-build-to-run-on-host-2)
    - [4. Run Elashell or Elatests](#4-run-elashell-or-elatests-3)
  - [Build API Documentation](#build-api-documentation)
    - [Build on Ubuntu / Debian / Linux Host](#build-on-ubuntu--debian--linux-host-1)
      - [1. Install Pre-Requirements](#1-install-pre-requirements)
      - [2. Build](#2-build)
      - [3. View](#3-view)
  - [Contribution](#contribution)
  - [Acknowledgments](#acknowledgments)
  - [License](#license)

## Usage

**CMake** is used to build, test, and package the Elastos DID project in an operating system and compiler independent manner.

Confident knowledge of CMake is required.

At the time of this writing, The compilation of sources works on **macOS**, **Linux** (Ubuntu, Debian, etc.), and **Windows** (support later) and provides the option to cross-compile for target systems of **iOS**, **Android**, and **RaspberryPi** (support later).

## Build on Ubuntu / Debian / Linux Host

### 1. Brief introduction

On Ubuntu / Debian / Linux, besides the compilation for the host itself, cross-compilation is possible for the following targets:

- Android with architectures of **armv7a**, **arm64**, and simulators of **x86/x86_64** are supported.
- RaspberryPi with architecture **armv7l** only will be supported later.

### 2. Install Pre-Requirements

To generate Makefiles by using **configure** or **cmake** and manage dependencies of the DID project certain packages must be installed on the host before compilation.

Run the following commands to install the prerequisite utilities:

```shell
sudo apt-get update
sudo apt-get install -f build-essential autoconf automake autopoint libtool flex bison libncurses5-dev cmake pkg-config
```

Download this repository using Git:

```shell
git clone https://github.com/elastos/Elastos.DID.Native.SDK
```

### 3. Build to run on host (Ubuntu / Debian / Linux)

To compile the project from source code for the target to run on Ubuntu / Debian / Linux, carry out the following steps:

Open a new terminal window.

Navigate to the previously downloaded folder that contains the source code of the DID project.

```shell
cd YOUR-PATH/Elastos.DID.Native.SDK
```

Enter the 'build' folder.

```shell
cd build
```

Create a new folder with the target platform name, then change the directory.

```shell
mkdir linux
cd linux
```

Generate the Makefile in the current directory:

*Note: Please see custom options below.*

```shell
cmake ../..
```

***

Optional (Generate the Makefile): To be able to build a distribution with a specific build type **Debug/Release**, as well as with customized install location of distributions, run the following commands:

```shell
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=YOUR-INSTALL-PATH ../..
```
**Tips**:  Must update cmake version larger than 3.13, if enable python (-DENABLE_PYTHON=TURE) on Linux platform!

***

Build the program:

*Note: If "make" fails due to missing permissions, use "sudo make" instead.*

```shell
make
```

Install the program:

*Note: If "make install" fails due to missing permissions, use "sudo make install" instead.*

```shell
make install
```

Create distribution package:

*Note: If "make dist" fails due to missing permissions, use "sudo make dist" instead.*

```shell
make dist
```

### 4. Run DIDTest

DIDTest is a shell program to imitate every DID flow and to prove DID API. The output is displayed in the terminal for a simple evaluation of test results.

DIDTest supports three modules: normal test, stress test, and dummy test.

To run DIDTest, first, extract the distribution package created previously and enter the extracted folder. Then, change the directory to the 'bin' folder.

```shell
cd YOUR-DISTRIBUTION-PACKAGE-PATH/bin
```

#### 4.1 Normal Test

Run DIDTest as normal module, including dummy test cases and IDChain Transaction test cases. Run normal module, test case needs SPV wallet to pay coins for IDChain Transaction. So the first thing is creating an SPV wallet. Detailed operation is as follow:

```shell
$ ./wallet -d YOUR-WALLET-DATA-DIRECTORY -n NETWOR-NAME
Wallet data directory: YOUR-WALLET-DATA-DIRECTORY
-> wallet $ create YOUR-WALLET-NAME
```

'YOUR-WALLET-DATA-DIRECTORY': wallet data directory with the given path;

'YOUR-WALLET-NAME': a new wallet with given name.

After entering the 'create' command, you also need to choose the mnemonic language, mnemonic word count, passphrase for encoring mnemonic, and payment password. After finishing a
series of operations, you have a new SPV wallet.

Second, open your test case folder:

```shell
cd YOUR-PATH/Elastos.DID.Native.SDK/tests
```

Modify 'walletdir', 'walletId' and 'walletpass' in constant.c file with your wallet parameter.

Third, rebuild the DID project as above operation. (make && make install)

Finally, Then, change the directory to the 'bin' folder.

```shell
cd YOUR-DISTRIBUTION-PACKAGE-PATH/bin
./didtest
```

#### 4.2 Stress Test

At the same time, DIDTest supports the stress test. Use Available commands in the shell can be listed by using the command **help**. Specific command usage descriptions can be displayed by using **help [Command]**, where [Command] must be replaced with the particular command name.

For example:

```shell
./didtest -s 100 -m memcheck
```

#### 4.3 Dummy Test

Run DIDTest without IDChain Transaction. This module does not need an SPV wallet. If you don't have an SPV wallet or only want to run essential DID functions, you can choose this module.

```shell
./didtest --dummy
```

### 5. Cross-compilation for Android Platform

COMING SOON

### 6. Cross-compilation for Raspberry Pi

COMING SOON

## Build on Raspberry Pi（support later)

COMING SOON

## Build on macOS Host

### 1. Brief introduction

On macOS, besides the compilation for the host itself, cross-compilation is possible for the following targets:

- Android with architectures of **armv7a**, **arm64**, and simulators of **x86/x86_64** are supported.
- iOS platforms to run on **iPhone-arm64** and **iPhoneSimulator-x86_64**.

### 2. Install Pre-Requirements

packages must be installed on the host before compilation.

The following packages related to **configure** and **cmake** must be installed on the host before compilation either by installation through the package manager **homebrew** or by building from source:

Note: Homebrew can be downloaded from the [Homebrew web site](https://brew.sh/).

Install packages with Homebrew:

```shell
brew install autoconf automake libtool shtool pkg-config gettext cmake
```

Please note that **homebrew** has an issue with linking **gettext**. If you have an issue with the execution of **autopoint**, fix it by running:

```shell
brew link --force gettext
```

Download this repository using Git:

```shell
git clone https://github.com/elastos/Elastos.DID.Native.SDK
```

### 3. Build to run on host

To compile the project from source code for the target to run on MacOS, carry out the following steps:

Open a new terminal window.

Navigate to the previously downloaded folder that contains the source code of the DID project.

```shell
cd YOUR-PATH/Elastos.DID.Native.SDK
```

Enter the 'build' folder.

```shell
cd build
```

Create a new folder with the target platform name, then change directory.

```shell
mkdir macos
cd macos
```

Generate the Makefile in the current directory:

*Note: Please see custom options below.*

```shell
cmake ../..
```

***

Optional (Generate the Makefile): To be able to build a distribution with a specific build type **Debug/Release**, as well as with customized install location of distributions, run the following commands:

```shell
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=YOUR-INSTALL-PATH ../..
```

***

Build the program:

*Note: If "make" fails due to missing permissions, use "sudo make" instead.*

```shell
make
```

Install the program:

*Note: If "make install" fails due to missing permissions, use "sudo make install" instead.*

```shell
make install
```

Create distribution package:

*Note: If "make dist" fails due to missing permissions, use "sudo make dist" instead.*

```shell
make dist
```

### 4. Run DIDTest

DIDTest is a shell program to imitate every DID flow and to prove DID API . The output is displayed in the terminal for a simple evaluation of test results.

DIDTest supports three modules: normal test, stress test and dummy test.

To run DIDTest, first extract the distribution package created previously and enter the extracted folder. Then, change directory to the 'bin' folder.

```shell
cd YOUR-DISTRIBUTION-PACKAGE-PATH/bin
```

#### 4.1 Normal Test

Run DIDTest as normal module, including dummy test cases and IDChain Transaction test case. Run normal module, test case needs spv wallet to pay coins for IDChain Transaction. So the first thing is creating spv wallet, detail operation is as follow:

```shell
$ ./wallet -d YOUR-WALLET-DATA-DIRECTORY -n NETWOR-NAME
Wallet data directory: YOUR-WALLET-DATA-DIRECTORY
-> wallet $ create YOUR-WALLET-NAME
```

'YOUR-WALLET-DATA-DIRECTORY' : wallet data directory with given path;

'YOUR-WALLET-NAME' : a new wallet with given name.

After inputing 'create' command, you also need choose the mnemonic language, mnemonic word count, passphrase for encoring mnemonic and payment password. After finishing a
series of operation, you has a new spv wallet.

Second, open your test case folder:

```shell
cd YOUR-PATH/Elastos.DID.Native.SDK/tests
```

Modify 'walletdir', 'walletId' and 'walletpass' in constant.c file with your wallet parameter.

Third, rebuild the DID project as above operation. (make && make install)

Finally, Then, change directory to the 'bin' folder.

```shell
cd YOUR-DISTRIBUTION-PACKAGE-PATH/bin
./didtest
```

#### 4.2 Stress Test

At the same time, DIDTest support stress test. Use Available commands in the shell can be listed by using the command **help**. Specific command usage descriptions can be displayed by using **help [Command]** where [Command] must be replaced with the specific command name.

For example:

```shell
./didtest -s 100 -m memcheck
```

#### 4.3 Dummy Test

Run DIDTest without IDChain Transaction, this module does not need spv wallet. If you no spv wallet or only want to run basic DID functions, you can choose this module.

```shell
./didtest --dummy
```

### 5. Cross-compilation for Android Platform

COMING SOON

### 6. Cross-compilation for iOS Platform

With CMake, Elastos DID can be cross-compiled to run on iOS as a target platform, while compilation is carried out on a MacOS host with XCode.

**Prerequisite**: MacOS version must be **9.0** or higher.

Open a new terminal window.

Navigate to the previously downloaded folder that contains the source code of the DID project.

```shell
cd YOUR-PATH/Elastos.DID.Native.SDK
```

Enter the 'build' folder.

```shell
cd build
```

Create a new folder with the target platform name, then change directory.

```shell
mkdir ios
cd ios
```

To generate the required Makefile in the current directory, please make sure to first replace 'YOUR-IOS-PLATFORM' with the correct option.

-DIOS_PLATFORM accepts the following target architecture options:

- iphoneos
- iphonesimulator

Replace 'YOUR-IOS-PLATFORM' with the path to the extracted NDK folder.

Run the command with the correct options described above:

```shell
cmake -DIOS_PLATFORM=YOUR-IOS-PLATFORM -DCMAKE_TOOLCHAIN_FILE=../../cmake/iOSToolchain.cmake ../..

```

Build the program:

*Note: If "make" fails due to missing permissions, use "sudo make" instead.*

```shell
make
```

Install the program:

*Note: If "make install" fails due to missing permissions, use "sudo make install" instead.*

```shell
make install
```

Create distribution package:

*Note: If "make dist" fails due to missing permissions, use "sudo make dist" instead.*

```shell
make dist
```

## Build on Windows Host

### 1. Brief introduction

With CMake, Elastos DID can be cross-compiled to run only on Windows as target platform, while compilation is carried out on a Windows host.  Now only support 64-bit (32-bit later) target versions are supported.

### 2. Set up Environment

**Prerequisites**:

- Visual Studio IDE is required. The Community version can be downloaded at [Visual Studio downloads](https://visualstudio.microsoft.com/downloads/) for free.
- Download and install "Visual Studio Command Prompt (devCmd)" from [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=ShemeerNS.VisualStudioCommandPromptdevCmd).
- Install 'Desktop development with C++' Workload

Start the program 'Visual Studio Installer'.
***
Alternative:
Start Visual Studio IDE.
In the menu, go to "Tools >> Get Tools and Features", it will open the Visual Studio Installer.
***

Make sure 'Desktop development with C++' Workload is installed.

On the right side, make sure in the 'Installation details' all of the following are installed:

- "Windows 8.1 SDK and UCRT SDK" <- might have to be selected additionally
- "Windows 10 SDK (10.0.17134.0)" <- might have to be selected additionally
- "VC++ 2017 version 15.9 ... tools"
- "C++ Profiling tools"
- "Visual C++ tools for CMake"
- "Visual C++ ATL for x86 and x64"

Additional tools are optional, some additional ones are installed by default with the Workload.

After modifications, restarting of Visual Studio might be required.

### 3. Build to run on a host

To compile the project from source code for the target to run on Windows, carry out the following steps:

In Visual Studio, open Visual Studio Command Prompt from the menu "Tools >> Visual Studio Command Prompt". It will open a new terminal window.

***
Note: To build for a 32-bit target , select `x86 Native Tools Command Console` to run building commands, otherwise, select `x64 Native Tools Command Console` for a 64-bit target.
***

Navigate to the previously downloaded folder that contains the source code of the DID project.

```shell
cd YOUR-PATH/Elastos.DID.Native.SDK
```

Enter the 'build' folder.

```shell
cd build
```

Create a new folder with the target platform name, then change directory.

```shell
mkdir win
cd win
```

Generate the Makefile in the current directory:

```shell
cmake -G "NMake Makefiles" -DCMAKE_INSTALL_PREFIX=outputs ..\..
```

Build the program:

```shell
nmake
```

Install the program:

```shell
nmake install
```

Create distribution package:

```shell
nmake dist
```

### 4. Run DIDTest

DIDTest is a shell program to imitate every DID flow and to prove DID API . The output is displayed in the terminal for a simple evaluation of test results.

DIDTest supports two modules: normal test (dummy test) and stress test.

***
**NOTICE**: How to enable the HTTPS did resolver on Windows 
OpenSSL does not support using the Windows "CA certificate store", so the cURL will fail on the SSL certificates verification. To enable the HTTPS support in DID SDK, the application should provide the Mozilla CA certificate store in PEM format, then the DID SDK will use this CA store to verify the SSL certificates. 
1. Download the Mozilla CA certificate store in PEM format from https://curl.se/ca/cacert.pem, and bundle it inside the application's distribution package. 
2. Set an environment variable 'CURLOPT_CAINFO' to the full path of the cert store when the application launchs, the DID SDK will use this variable get the cert store file.
***

To run DIDTest, first extract the distribution package created previously and enter the extracted folder. Then, change directory to the 'bin' folder.

```shell
cd YOUR-DISTRIBUTION-PACKAGE-PATH/bin
```

#### 4.1 Normal Test (Dummy Test)

In Windows, the Normal test does not support IDChain Transaction, so the normal module is equal to dummy module. 


```shell
./didtest
```
or
```shell
./didtest --dummy
```

#### 4.2 Stress Test

At the same time, DIDTest supports stress tests. Use Available commands in the shell can be listed by using the command **help**. Specific command usage descriptions can be displayed by using **help [Command]** where [Command] must be replaced with the specific command name.

For example:

```shell
./didtest -s 100 -m memcheck
```

## Contribution

We welcome contributions to the Elastos DID Project.

## Acknowledgments

A sincere thank you to all teams and projects that we rely on directly or indirectly.

## License

This project is licensed under the terms of the [MIT license](https://github.com/elastos/Elastos.DID.Native.SDK/blob/master/LICENSE).

