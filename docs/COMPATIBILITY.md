# 호환성 설계

Linux의 정적 ELF와 macOS의 Universal Mach-O를 별도 산출물로 제공합니다. 공통 C decoder/filter/PCAP 코드는 공유하고, 캡처와 런타임 I/O만 플랫폼별로 분리했습니다.

## 기준

최소 Linux 대상은 **2.4.21, RHEL 3급**입니다. [Red Hat의 릴리스·커널 표](https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates)는 RHEL 3 GA를 2.4.21 계열로 기록합니다. 실제 시험에는 CentOS 3.1의 x86_64 `2.4.21-15.0.2.EL.c0`, i686 `2.4.21-9.0.1.EL.c0`를 사용했습니다.

기존의 오래된 syscall만 사용하는 구현이 두 커널에서도 동작해 런타임에 별도의 2.4 전용 분기는 필요하지 않았습니다. `PT_LINUX_MIN`은 검증된 하한을 표시하며, 커널 버전 문자열만으로 실행을 차단하지 않습니다. 2.4.0~2.4.20, 2.2, 2.0은 미검증으로 지원 대상에 포함하지 않습니다. 1990년대 Red Hat Linux 4.x와 RHEL 4도 구분합니다.

신형 libc를 정적으로 링크했다는 사실만으로 구형 커널과의 호환성이 확보되지는 않습니다. 이번 구현은 libc를 링크하지 않고 필요한 Linux ABI만 직접 사용합니다. Linux 커널의 [userspace ABI 문서](https://www.kernel.org/doc/html/latest/admin-guide/abi.html)는 syscall을 장기간 유지되는 인터페이스로 설명합니다. 이 점을 호환 설계의 근거로 사용하되, 정책·아키텍처·커널 설정까지 무조건 호환된다고 가정하지 않습니다.

## 런타임 시스템 호출

| 기능 | x86_64 | i386 |
|---|---|---|
| 파일 I/O | `read`, `write`, `open`, `close` | 동일 |
| 패킷 소켓 | `socket`, `bind`, `recvfrom`, `setsockopt`, `getsockopt` | 기존 `socketcall` multiplexor |
| 수신 대기 | `poll` | `poll` |
| 인터페이스/타임스탬프 | `ioctl` | `ioctl` |
| 시각 fallback | `gettimeofday` | 기존 32비트 `gettimeofday` |
| 종료 신호 | `rt_sigaction`, `rt_sigreturn` | `rt_sigaction`, `sigreturn` |
| 프로세스 종료 | `exit` | `exit` |

`openat`, `getrandom`, `statx`, `recvmmsg`, `epoll`, `io_uring`, eBPF, vDSO에 의존하지 않습니다. 런타임 syscall 번호와 레이아웃은 `src/linux_abi.h`, 호출 규약은 `src/start.S`에 모았습니다. x86 CPU의 little endian ABI만 지원합니다. 32비트 64비트 정수의 10진수 출력도 직접 처리하여 libgcc의 `__udivdi3` 의존성을 피했습니다.

i386에서는 `rt_sigaction`으로 등록해도 `SA_SIGINFO`가 없는 handler에는 legacy signal frame이 전달됩니다. 따라서 신호 번호를 stack에서 pop한 뒤 `sigreturn(119)`으로 복귀합니다. x86_64의 `rt_sigreturn(15)`와 구분하며 실제 구형 커널의 SIGINT/SIGTERM 테스트로 확인합니다. 프레임 위치 계산은 [커널 i386 signal 구현](https://github.com/torvalds/linux/blob/v2.6.12/arch/i386/kernel/signal.c)의 `sys_sigreturn`과 `setup_frame`에 설명돼 있습니다.

`AF_PACKET`은 [Linux packet(7)](https://www.man7.org/linux/man-pages/man7/packet.7.html)에 기술된 오래된 인터페이스입니다. `SOCK_RAW`는 Ethernet, `SOCK_DGRAM`은 전체 인터페이스의 SLL 구성에 사용합니다. 수신은 protocol 0인 소켓을 인터페이스에 bind한 다음 시작해, bind 전에 다른 인터페이스의 패킷이 큐에 들어오는 것을 피합니다.

promiscuous 모드는 전역 인터페이스 플래그를 직접 수정하지 않고 `PACKET_ADD_MEMBERSHIP`으로 소켓 수명에 연결합니다. 프로세스/소켓이 종료되면 커널이 membership을 해제합니다. `SIOCGSTAMP`로 커널 수신 시각을 요청하고 실패하면 수신 직후 `gettimeofday`로 대체합니다. `PACKET_STATISTICS`는 조회 시 초기화되는 카운터를 주기적으로 읽어 64비트 누계로 합산합니다.

## 빌드 산출물

- `-nostdlib -static -no-pie`: 동적 로더·공유 라이브러리 없음
- 기본 `x86-64` 또는 `i486` 명령어 집합 사용; `-march=native` 사용 안 함
- 진입점 `_start`에서 커널이 전달한 argc/argv를 읽음
- GNU stack를 실행 불가로 표시, writable/executable load segment 금지
- 런타임 malloc/TLS/환경변수/로캘 조회 없음
- 커널 syscall wrapper 외 외부 심볼을 요구하지 않음

`tests/verify_elf.py`는 ELF 구조 자체를 검사해 interpreter와 dynamic segment 부재, 머신 타입, NX stack 등을 확인합니다. 이것은 실제 구형 커널 실행 시험을 대체하지 않습니다. 실제 검증 결과는 [VALIDATION.md](VALIDATION.md)를 참조하세요.

## 검증 해석

최신 컨테이너에서 오래된 userspace 이미지를 실행해도 커널은 호스트 커널입니다. 따라서 오래된 userspace 컨테이너만으로 해당 커널의 호환성을 주장할 수 없습니다. `tests/run_vm.py`는 CentOS 3.1의 2.4.21과 CentOS 4.0의 2.6.9를 QEMU system VM에서 부팅하고 동일한 배포 바이너리를 실행합니다. 2.4는 ext2 initrd, 2.6은 cpio initramfs를 사용합니다. 이 결과는 시험한 벤더 커널에 대한 것으로 모든 vanilla/벤더 패치 조합이나 RHEL 공급자 인증을 의미하지는 않습니다.

## macOS

`make macos`는 Apple Clang으로 `-arch arm64 -arch x86_64 -mmacosx-version-min=11.0`을 사용해 Universal 실행 파일을 만듭니다. [Apple의 Universal binary 설명](https://developer.apple.com/documentation/apple-silicon/building-a-universal-macos-binary)에 따른 아키텍처별 코드가 한 파일에 들어 있습니다. 직접 만든 Linux syscall wrapper를 Mac에서 재사용하지 않고 macOS의 기본 `libSystem` API를 사용합니다. 추가 설치할 라이브러리는 없으며 `libpcap`도 링크하지 않습니다. `tests/verify_macos.py`가 아키텍처, deployment target, PIE, 의존 라이브러리, 서명을 검사합니다.

캡처는 SDK의 `<net/bpf.h>`를 사용합니다. `/dev/bpfN`을 읽기 전용·nonblocking으로 열고, `BIOCSBLEN` → `BIOCSETIF` → `BIOCGDLT` → `BIOCIMMEDIATE` 순서로 설정합니다. Ethernet의 promiscuous 모드는 해당 BPF descriptor를 닫을 때 해제됩니다. `poll`로 수신을 기다리며, 하나의 read에 들어 있는 여러 BPF 레코드를 `BPF_WORDALIGN` 기준으로 순회합니다. 각 header 길이와 캡처 길이를 확인한 후에만 공통 parser로 넘깁니다.

Darwin의 `DLT_RAW=12`와 PCAP의 `LINKTYPE_RAW=101`을 구분합니다. loopback의 `DLT_NULL=0`은 4바이트 host-endian address family를 포함하고, `DLT_LOOP=108`은 network-endian입니다. BSD IPv6 family 값 24/28/30을 읽을 수 있습니다. Linux에서도 Mac의 NULL/LOOP PCAP을 다시 읽을 수 있습니다.

Mac BPF 통계는 누적 counter이므로 이전 값과의 차이를 64비트 누계에 더합니다. Linux의 조회 시 reset되는 통계와 구분합니다. BPF read 버퍼는 최대 512KiB, 개별 저장 패킷은 공통 제한인 65535바이트입니다. 기존 BPF 헤더의 timestamp 초 필드는 32비트 signed이므로 2038년 이후의 live timestamp는 이번 구현 범위 밖입니다.

Mac에서는 인터페이스 한 개를 지정하며 기본 `en0`입니다. `any`를 다른 의미로 바꾸지 않고 명시적으로 거부합니다. 실제 live 검증 범위와 권한 제약은 [VALIDATION.md](VALIDATION.md#macos-빌드와-검증)에 기록했습니다.
