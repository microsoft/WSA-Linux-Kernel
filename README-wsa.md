# Project

This repo is for:

  Windows Subsystem for Android kernel sources.

## Building WSA kernel

WSA uses kernel tags instead of branches(Rolling LTS model)

1. Install a Ubuntu 18.04 desktop distribution or Install Ubuntu 18.04 desktop in WSL

2. Install the following dependencies.
```shell
sudo apt install -y --no-install-recommends bc bison build-essential ca-certificates flex git gnupg libelf-dev libssl-dev lsb-release software-properties-common wget libncurses-dev binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu nuget
```

3. Setup LLVM

	```shell
	export LLVM_VERSION=10
	wget https://apt.llvm.org/llvm.sh
	chmod +x llvm.sh
	sudo ./llvm.sh $LLVM_VERSION
	rm ./llvm.sh
	sudo ln -s --force /usr/bin/clang-$LLVM_VERSION /usr/bin/clang
	sudo ln -s --force /usr/bin/ld.lld-$LLVM_VERSION /usr/bin/ld.lld
	sudo ln -s --force /usr/bin/llvm-objdump-$LLVM_VERSION /usr/bin/llvm-objdump
	sudo ln -s --force /usr/bin/llvm-ar-$LLVM_VERSION /usr/bin/llvm-ar
	sudo ln -s --force /usr/bin/llvm-nm-$LLVM_VERSION /usr/bin/llvm-nm
	sudo ln -s --force /usr/bin/llvm-strip-$LLVM_VERSION /usr/bin/llvm-strip
	sudo ln -s --force /usr/bin/llvm-objcopy-$LLVM_VERSION /usr/bin/llvm-objcopy
	sudo ln -s --force /usr/bin/llvm-readelf-$LLVM_VERSION /usr/bin/llvm-readelf
	sudo ln -s --force /usr/bin/clang++-$LLVM_VERSION /usr/bin/clang++
	```
 
4. Clone the kernel and Checkout kernel tag
	```shell
	cd ~
	git clone https://github.com/microsoft/WSA-Linux-Kernel.git
	export KERNEL_ROOT=~/WSA-Linux-Kernel/
	cd WSA-Linux-Kernel
	git checkout android-lts/latte/5.10.117.2
	```

5. Build the kernel

	Kernel configs for wsa are found in $KERNEL_ROOT/configs/wsa/ folder.
	```shell
	[Note: 
		- $KERNEL_ROOT : is the location of WSA kernel sources
		- $(nproc) : “nproc” command is a tool that is used to count the number of available processing units available to the current processes.
	]
	```

	```
	- config-wsa-5.10 - Kernel config for x86_64
	- config-wsa-arm64-5.10 - kernel config arm64
	```
 
	Build WSA ARM64 kernel
	------------------

	```shell
	cp configs/wsa/config-wsa-arm64-5.10 $KERNEL_ROOT/.config

	make -j`nproc` LLVM=1 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu Image
	```

	```
	After compilation you can find the compiled version at the following location:

	arch/arm64/boot/Image
	```

	Build WSA x86_64 kernel
	-------------------

	```shell
	cp configs/wsa/config-wsa-5.10 $KERNEL_ROOT/.config

	make -j`nproc` LLVM=1 bzImage
	```

	```
	After compilation you can find the compiled version at the following location:

	arch/x86/boot/bzImage
	```

## Info

This repo is for:

Reporting of issues found within and when using Windows Subsystem for Android. Please read Contributing section before making an issue submission.

Do not open Github issues for Windows crashes or security issues. Please directall Windows crashes and security issues to secure@microsoft.com. Issues with 
security vulnerabilities may be edited to hide the vulnerability details.
 
## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
