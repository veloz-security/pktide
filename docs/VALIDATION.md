# 검증 기록

검증일: 2026-10-07. 대상: pktide 0.1.0. Linux 빌드: GCC 12.5.0, Debian bookworm 기반 Linux/amd64 컨테이너. Mac 빌드: Apple Clang, macOS 26.2, 배포 대상 macOS 11.0.

## 실행 결과

| 환경 | 바이너리 | 확인 항목 | 결과 |
|---|---|---|---|
| CentOS 3.1, 실제 `2.4.21-15.0.2.EL.c0` x86_64 커널, QEMU system TCG | x86_64 | PCAP 필터, Ethernet/SLL live 캡처, 저장·재읽기, socket 통계, SIGINT/SIGTERM | 통과 |
| CentOS 3.1, 실제 `2.4.21-9.0.1.EL.c0` i686 커널, QEMU system TCG | i386 | 위와 동일 | 통과 |
| CentOS 4.0, 실제 `2.6.9-5.0.3.EL` x86_64 커널, QEMU system TCG | x86_64 | PCAP 필터, Ethernet/SLL live 캡처, 저장·재읽기, socket 통계, SIGINT/SIGTERM | 통과 |
| CentOS 4.0, 실제 `2.6.9-5.0.3.EL` i686 커널, QEMU system TCG | i386 | 위와 동일 | 통과 |
| Linux `7.0.14-orbstack-00380-ga7e0a2dc9535`, arm64 호스트에서 amd64 실행 변환 | x86_64 | CLI 13개 통과/1개 Mac 전용 skip, live 4개 그룹 | 통과 |
| 같은 현대 Linux 커널, arm64 네이티브 QEMU user-mode | i386 | CLI 13개 통과/1개 Mac 전용 skip, live 4개 그룹 | 통과 |
| macOS arm64 Clang, ASan + UBSan | 공통 C parser | 패킷 100,000개, 필터 10,000개 생성 입력, 숫자/IP 변환 | 통과 |
| ELF 구조 검사 | 두 배포 파일 | 정적 ELF, 아키텍처, interpreter/dynamic segment 없음, NX stack | 통과 |
| macOS 시스템 tcpdump | 저장 PCAP | pktide가 쓴 파일의 재읽기 | 통과 |
| macOS 26.2, Apple Silicon 네이티브 | Universal의 arm64 코드 | CLI 14개 그룹, PCAP 재읽기/필터, 인터페이스 목록 | 통과 |
| 같은 Mac, Rosetta 2 | Universal의 x86_64 코드 | CLI 14개 그룹 | 통과 |
| Mac ASan + UBSan | BPF 레코드 처리 | batch/padding/길이/중단/잘린 레코드/RAW 매핑 | 통과 |
| Mach-O 및 codesign 검사 | Universal 파일 | arm64+x86_64, PIE, macOS 11 target, libSystem만 의존, ad-hoc 서명 | 통과 |
| Mac `/dev/bpf*` | 실제 live 캡처 | root/장치 읽기 권한 필요 | **미검증: 현재 권한 없음** |

CLI 그룹에는 프로토콜/주소/포트/논리 필터, 단편, 모든 truncation 길이, PCAP endian/시간 단위/링크 타입, 잘못된 길이/형식/옵션, 출력 파일 보호, binary stdout 검사를 포함합니다. Live 그룹은 테스트 컨테이너의 IPv4/IPv6 loopback에 자체 생성한 UDP만 사용하며, 권한 없는 캡처 거부도 확인합니다. 실제 2.4.21/2.6.9 VM의 live 검증은 IPv4 loopback입니다. IPv6는 해당 VM에서 PCAP 해석까지 확인했습니다.

pktide 0.1.0 배포 파일로 2.4.21, 2.6.9, 현대 커널의 검증을 실행했습니다. BSD NULL/LOOP 형식은 Linux/Mac의 공통 decoder에서 읽으며, 테스트에서 양쪽 byte order와 BSD IPv6 family 값도 확인합니다.

## macOS 빌드와 검증

```sh
make macos
make test
python3 tests/test_cli.py --binary dist/pktide-macos --runner 'arch -x86_64'
make sanitize
```

`dist/pktide-macos`는 arm64/x86_64 Universal Mach-O 한 파일입니다. `otool -L`에서 시스템 `/usr/lib/libSystem.B.dylib`만 확인했고, `codesign --verify --strict --all-architectures`도 통과했습니다. 개발용 ad-hoc 서명이며 Apple Developer ID 서명/공증은 아닙니다. macOS 11은 빌드 target이며 11~25의 실제 Mac별 실행 검증을 의미하지 않습니다.

macOS 26.2에서 `-D`, PCAP 처리, 필터, BSD loopback 해석, 저장 PCAP의 시스템 tcpdump 재읽기를 확인했습니다. arm64와 Rosetta x86_64에서 각각 14개 테스트가 통과했습니다. [Mac native 기록](validation/macos-native.txt), [Rosetta 기록](validation/macos-rosetta.txt)을 참조하세요.

`/dev/bpf*`는 root 전용(0600)이었고 `sudo -n`도 인증을 요구했습니다. `-i lo0 -c 1` 실행에서 정확한 권한 오류를 반환하는 것은 확인했습니다. 실제 BPF 장치 캡처·BPF 통계·캡처 중 종료 신호는 이 Mac에서 **미검증**입니다. 장치 권한을 변경하지 않았습니다. BPF batch parser의 합성 입력 검사는 실제 장치 검증을 대체하지 않습니다.

권한이 있는 로컬 터미널에서 live 회귀 테스트를 실행할 수 있습니다:

```sh
sudo python3 tests/test_live.py --binary dist/pktide-macos
```

이는 loopback `lo0`에서 테스트 자체가 생성하는 IPv4/IPv6 UDP, PCAP 저장/재읽기, SIGINT/SIGTERM 종료를 검사합니다. `-i any`는 Mac에서 지원하지 않으며 명시적 오류로 안내합니다.

현대 커널 시험에는 CPU 실행 변환이 개입했습니다. 구형 커널 시험은 QEMU user-mode가 아니라 **실제 2.4.21/2.6.9 커널을 부팅한 system VM**입니다. RHEL 3~현재의 모든 릴리스와 실제 NIC를 개별 인증한 결과는 아닙니다. RHEL의 SELinux enforcing 정책, 물리 NIC/offload, 고속 부하, 2038년 이후 i386은 통과 범위에 포함하지 않습니다.

32비트 `rt_sigaction` + legacy `sigreturn` 프레임의 차이는 VM 시험에서 발견해 수정했습니다. i386에서는 handler가 반환한 뒤 신호 번호를 pop하고 syscall 119로 복귀해야 합니다. 이 회귀를 잡기 위해 SIGINT/SIGTERM 검증을 유지합니다.

Apple Silicon에서 **amd64 QEMU 자체를 다시 실행 변환하는 중첩 구성**은 QEMU 내부 `rcu_read_unlock` assertion으로 시그널 테스트에 실패했습니다. arm64 네이티브 QEMU와 실제 i686 VM으로 분리 검증해 통과했습니다. QEMU user-mode의 `SOL_PACKET/PACKET_STATISTICS` 미지원은 socket 통계 필드 생략으로 처리하며, 실제 구형 VM에서는 통계 조회도 통과했습니다.

## 일반 테스트 재현

```sh
docker build --platform linux/amd64 -t pktide-builder:local .
docker run --rm --platform linux/amd64 --network none \
  -v "$PWD:/work" -w /work pktide-builder:local \
  sh -c 'make both && make test && make test-live'

# 호스트 컴파일러의 AddressSanitizer/UndefinedBehaviorSanitizer
make sanitize
```

Docker가 기본 CAP_NET_RAW를 제거하도록 설정돼 있으면 `--cap-add NET_RAW`를 지정합니다. 테스트는 외부 네트워크가 필요 없습니다. 빌더 이미지 생성 단계에는 패키지 다운로드가 필요합니다.

## 실제 Linux 2.4.21 / 2.6.9 VM 재현

프로젝트 루트에서 실행합니다. VM runner 이미지는 **호스트의 기본 아키텍처**로 빌드합니다.

```sh
docker run --rm --platform linux/amd64 --network none \
  -v "$PWD:/work" -w /work pktide-builder:local \
  sh -c 'make both && make vm-init && make ARCH=i386 vm-init'

docker build -f tests/vm.Dockerfile -t pktide-vm:local .

# Linux 2.4.21 / RHEL 3급
docker run --rm -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/run_vm.py --profile centos3 --arch x86_64
docker run --rm -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/run_vm.py --profile centos3 --arch i386

# Linux 2.6.9 / RHEL 4급 (기본 프로필)
docker run --rm -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/run_vm.py --arch x86_64
docker run --rm -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/run_vm.py --arch i386
```

처음에는 CentOS vault의 공개 커널 RPM을 다운로드하고 SHA-256을 검사합니다. 이후 `build/vm/` 캐시가 있으면 `--network none`을 추가해 실행할 수 있습니다. VM에는 네트워크 장치, 호스트 디스크, 공유 폴더를 연결하지 않습니다. 테스트용 `/init`, pktide, 합성 PCAP을 담은 ramdisk로 부팅합니다. 구형 커널의 BIOS 메모리 맵 호환성을 위해 `pc-i440fx-2.0`과 128MiB를 사용합니다.

2.4 커널에는 추가 filesystem feature를 끈 8MiB ext2 initrd를 사용하고 2.6에는 cpio initramfs를 사용합니다. 테스트용 2.4 프로필은 `CONFIG_PACKET=y`, `CONFIG_EXT2_FS=y`를 확인합니다. 이는 작은 테스트 루트에 2.4 모듈 로더가 없기 때문이며, 실제 서버에서 AF_PACKET을 모듈로 제공하는 구성을 금지하는 조건은 아닙니다.

2.4.21 x86_64의 boot protocol은 2.02입니다. QEMU 7.2의 [linuxboot 코드](https://github.com/qemu/qemu/blob/v7.2.22/pc-bios/optionrom/linuxboot.S)는 2.03 미만에서도 offset `0x22c`에 값을 써 이 커널의 setup 명령을 덮어씁니다. runner는 해당 프로토콜에만 ISOLINUX로 만든 읽기 전용 부팅 ISO를 사용합니다. **커널과 pktide 바이너리는 수정하지 않습니다.** ISO와 ext2 생성은 검증 환경에만 필요하며 배포 파일에는 영향을 주지 않습니다.

| RPM | SHA-256 |
|---|---|
| `kernel-2.4.21-15.0.2.EL.c0.x86_64.rpm` | `485914b519f3c63acb0d3ad9fcc76c0c001679d2c78bad21bc720c0a96cd67f9` |
| `kernel-2.4.21-9.0.1.EL.c0.i686.rpm` | `4a8432e9341d8401d05764de67391b5277b501acb1172167ed1588c0d6ec2f67` |
| `kernel-2.6.9-5.0.3.EL.x86_64.rpm` | `562d5b76b89873f7afd33469b680b1b312bca11018970c6803f5fa886923f387` |
| `kernel-2.6.9-5.0.3.EL.i686.rpm` | `1a1a86be59d4c7f5d5690a04209eadb0aceb6497a227d8f0572ace2221f3982c` |

소스 위치: [CentOS 3.1 x86_64](https://vault.centos.org/3.1/os/x86_64/RedHat/RPMS/), [CentOS 3.1 i386](https://vault.centos.org/3.1/os/i386/RedHat/RPMS/), [CentOS 4.0 x86_64](https://vault.centos.org/4.0/os/x86_64/CentOS/RPMS/), [CentOS 4.0 i386](https://vault.centos.org/4.0/os/i386/CentOS/RPMS/). 위 해시는 이번 실행에서 받은 파일의 재현성 고정 값이며, 별도의 RPM GPG 공급망 검증 결과를 의미하지 않습니다.

전체 부팅 로그는 2.4의 `build/vm/centos3/{x86_64,i386}/console.log`, 2.6의 `build/vm/{x86_64,i386}/console.log`에 있습니다. 바이너리 해시를 포함한 요약은 [2.4 64비트](validation/centos3-x86_64.txt), [2.4 32비트](validation/centos3-i386.txt), [2.6 64비트](validation/legacy-x86_64.txt), [2.6 32비트](validation/legacy-i386.txt)에 있습니다. 성공 시 커널 버전·아키텍처, `PKTIDE_VM_SUCCESS`, 두 live capture의 일치 건수/커널 통계가 모두 확인돼야 runner가 성공합니다.

## 현대 커널의 i386 테스트 재현

위에서 호스트 아키텍처로 만든 VM runner 이미지의 QEMU user-mode를 사용합니다. 이는 커널을 부팅하는 VM 시험과 별개의 검사입니다.

```sh
docker run --rm --network none --cap-add NET_RAW \
  -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/test_cli.py --binary dist/pktide-i386 --runner qemu-i386
docker run --rm --network none --cap-add NET_RAW \
  -v "$PWD:/work" -w /work pktide-vm:local \
  python3 tests/test_live.py --binary dist/pktide-i386 --runner qemu-i386
```

## 배포 판단

현재 결과는 “RHEL 3급 2.4.21과 RHEL 4급 2.6.9에서 실행되는 동일한 정적 바이너리가 현대 Linux 환경에서도 동작한다”는 범위를 뒷받침합니다. 2.4.21보다 오래된 커널은 지원 범위에 포함하지 않습니다. 운영 배포 전에는 실제 대상 CPU/커널/인터페이스에서 `--version`, `-D`, 짧은 `-c` 캡처 및 tcpdump 재읽기를 확인하세요. 모든 RHEL 버전의 무조건적인 호환 인증은 아닙니다.
