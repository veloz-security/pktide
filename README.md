# pktide

RHEL 3급 Linux 2.4.21부터 현대 Linux, macOS를 대상으로 하는 C 패킷 모니터입니다. tcpdump처럼 실시간 패킷을 요약하고, 필터링하고, PCAP으로 저장하거나 다시 읽습니다.

**Linux는 CPU 아키텍처당 정적 실행 파일 하나, Mac은 Apple Silicon과 Intel을 함께 담은 Universal 실행 파일 하나입니다.** Linux 빌드는 glibc, musl, libpcap, libgcc, 동적 로더 없이 시스템 호출을 직접 사용합니다. Mac 빌드는 macOS 기본 `libSystem`만 동적으로 사용하고 `/dev/bpf`로 캡처합니다. 두 버전 모두 추가 라이브러리 설치가 필요 없습니다.

```sh
# 64비트 Linux 서버에서 실행
chmod +x pktide-x86_64
sudo ./pktide-x86_64 -i eth0 'tcp port 443'

# 100개를 새 PCAP 파일에 저장
sudo ./pktide-x86_64 -i eth0 -c 100 -w capture.pcap 'tcp or udp'

# 전체 인터페이스, UDP 53번 포트
sudo ./pktide-x86_64 -i any 'udp port 53'

# 저장 파일 분석: root 불필요
./pktide-x86_64 -r capture.pcap 'src host 192.0.2.10'
./pktide-x86_64 -r capture.pcap -X -c 5
```

`eth0`는 실제 인터페이스 이름으로 바꾸세요. `-D`로 목록을 볼 수 있습니다. 32비트 Linux에서는 `pktide-i386`을 사용합니다. Windows는 지원하지 않습니다.

## 다운로드

[GitHub Releases](https://github.com/devwooops/pktide/releases)에서 운영체제와 CPU에 맞는 파일을 받으세요.

- Linux x86_64: `pktide-x86_64`
- Linux i386/i486 이상: `pktide-i386`
- macOS Apple Silicon / Intel: `pktide-macos`

릴리스에 포함된 `SHA256SUMS`로 파일 무결성을 확인할 수 있습니다. 다운로드한 파일에는 `chmod +x 파일명`으로 실행 권한을 부여하세요.

## Mac에서 실행

```sh
# Xcode Command Line Tools가 설치된 Mac에서 네이티브 빌드
make macos

# arm64 + x86_64를 담은 파일 하나
./dist/pktide-macos --version
./dist/pktide-macos -D
sudo ./dist/pktide-macos -i en0 -c 100 -w capture.pcap 'tcp port 443'

# localhost 트래픽
sudo ./dist/pktide-macos -i lo0 'tcp or udp'

# 파일 읽기는 sudo 불필요
./dist/pktide-macos -r capture.pcap -X -c 5
```

macOS 11 이상을 빌드 대상으로 설정했습니다. 실제 실행 검증은 macOS 26.2의 arm64와 Rosetta x86_64에서 수행했습니다. `make`도 Mac에서는 이 빌드를 선택합니다. 실행 파일은 시스템 `libSystem`을 사용하므로 Linux 파일처럼 완전 정적 링크된 파일은 아닙니다.

Mac 캡처는 한 인터페이스를 지정합니다. 기본값은 `en0`이며 `-i any`는 지원하지 않습니다. 인터페이스는 `-D`로 확인하세요. root 또는 `/dev/bpf*` 읽기 권한이 필요합니다. 현재 개발 Mac에서는 이 권한이 없어 **실제 BPF live 캡처는 검증하지 못했으며**, PCAP·필터·BPF 레코드 처리와 권한 오류 처리를 검증했습니다. 자세한 결과는 [Mac 검증 기록](docs/VALIDATION.md#macos-빌드와-검증)에 있습니다.

## 기능

- Ethernet, Linux cooked capture v1(SLL), RAW IP, BSD NULL/LOOP PCAP 읽기
- IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, ARP, VLAN/QinQ 요약
- IPv4 옵션, IPv6 확장 헤더, IP 단편의 경계 검사
- 숫자 IP/포트 필터, `and`, `or`, `not`, 괄호, 생략된 `and`
- 실시간 캡처, PCAP 읽기/쓰기, 패킷 수 제한, snaplen, hex/ASCII 출력
- little/big endian 및 micro/nanosecond PCAP 읽기; microsecond PCAP 쓰기
- Ctrl-C/SIGTERM 종료, 처리 건수/바이트와 Linux socket 또는 macOS BPF drop 통계
- 이름 조회 없음: DNS 트래픽이나 NSS 라이브러리 의존성이 생기지 않음
- 패킷 처리는 고정 크기 버퍼 사용. 백그라운드 서비스 없음

출력 예:

```text
1700000000.123456 IP 192.0.2.10:12345 > 198.51.100.20:443 TCP [S] length=54
pktide: seen=11 matched=3 matched_bytes=210
```

타임스탬프는 Unix epoch 초.마이크로초입니다. TCP 플래그는 `F S R P A U E C`입니다. 체크섬 검증이나 스트림 재조립은 수행하지 않습니다.

## 호환성 범위

| 실행 파일 | CPU / ABI | 최소 목표 |
|---|---|---|
| `dist/pktide-x86_64` | 기본 x86-64 / Linux LP64 | Linux 2.4.21, RHEL 3급 |
| `dist/pktide-i386` | i486 이상 / Linux i386 | Linux 2.4.21, RHEL 3급 |
| `dist/pktide-macos` | Universal Mach-O / arm64 + x86_64 | macOS 11.0 |

동일한 Linux 아키텍처에서는 배포판별로 다시 빌드하지 않습니다. 32비트 파일을 64비트 커널에서 실행하려면 해당 커널의 IA32 호환 지원이 필요합니다. Linux ARM, POWER, s390, IA-64는 이번 구현 대상에 포함하지 않습니다. Mac은 별도의 Mach-O 파일을 사용합니다.

Linux 하한은 실제 CentOS 3.1의 2.4.21 커널에서 두 아키텍처의 캡처·저장·종료를 확인한 기준입니다. 2.4.0~2.4.20과 2.2/2.0은 미검증이며 지원 범위에 포함하지 않습니다. 모든 중간 릴리스를 개별 시험한 것은 아닙니다.

Linux 커널에 `AF_PACKET`이 있어야 하고, 실시간 캡처에는 root 또는 `CAP_NET_RAW`가 필요합니다. 컨테이너의 seccomp/capability 정책도 시스템 호출을 허용해야 합니다. 구형 시스템에서는 root 실행을 사용합니다. ABI 설계만으로 모든 RHEL 릴리스·장치·정책 조합의 동작을 보증할 수는 없습니다. 실제 실행 결과와 재현 방법은 [검증 기록](docs/VALIDATION.md)에 구분해 기록합니다.

## 빌드

현대 Linux x86 GCC/binutils에서:

```sh
make both
make verify
make ARCH=i386 verify
```

헤더, libc 또는 32비트 libc 개발 패키지는 필요 없습니다. 컴파일러가 x86 `-m32` 코드 생성과 ELF i386 링킹을 지원하면 됩니다. 배포 서버에서 빌드할 필요가 없으며 RHEL 3/4의 옛 GCC 자체는 빌드 환경으로 검증하지 않았습니다.

macOS/ARM 머신에서 Docker로 **Linux 파일**을 빌드:

```sh
docker build --platform linux/amd64 -t pktide-builder:local .
docker run --rm --platform linux/amd64 --network none \
  -v "$PWD:/work" -w /work pktide-builder:local make both
```

생성된 `dist/pktide-x86_64` 또는 `dist/pktide-i386` 하나만 대상 서버로 복사합니다. Docker와 Python은 개발/검증 도구이며 대상 서버의 실행 의존성이 아닙니다.

## 옵션과 필터

| 옵션 | 의미 |
|---|---|
| `-i IFACE` | 인터페이스, Linux 기본값 `any`, Mac 기본값 `en0` |
| `-D` | 운영체제의 인터페이스 목록 |
| `-r FILE` | PCAP 입력. `-`는 stdin |
| `-w FILE` | PCAP 출력. 새 파일만 생성, 권한 0600. `-`는 stdout |
| `-c N` | 필터에 일치한 N개 후 종료 |
| `-s N` | 출력/저장 길이 1–65535, 기본 65535 |
| `-B KiB` | 커널 수신 버퍼 요청, 기본 2048 KiB; 커널 설정에 따라 제한됨 |
| `-p` | 지정 인터페이스의 promiscuous 모드 비활성화 |
| `-q` | 패킷별 텍스트 생략 |
| `-X` | 캡처 바이트를 hex/ASCII로 표시 |
| `-n`, `-nn` | 호환 옵션. 이름 조회는 항상 비활성화 |

옵션은 필터보다 앞에 지정합니다. 각 옵션을 따로 쓰세요. `-c10`, `-ieth0` 형태도 지원합니다. `-w -`일 때 텍스트는 stderr로 보내므로 stdout에는 PCAP만 나옵니다. 통계는 항상 stderr로 보냅니다. 기존 출력 파일이나 심볼릭 링크를 덮어쓰지 않습니다. 파일을 읽으며 같은 파일에 쓸 수 없습니다.

```sh
pktide-x86_64 -i eth0 '(tcp port 80 or tcp port 443) and not host 192.0.2.5'
pktide-x86_64 -i any 'ip6 and dst host 2001:db8::2'
pktide-x86_64 -r trace.pcap 'vlan and udp'
pktide-x86_64 -r trace.pcap -w - -q 'tcp' > filtered.pcap
```

지원 프리미티브: `tcp`, `udp`, `icmp`, `icmp6`, `arp`, `ip`, `ip6`, `vlan`, `[src|dst] port N`, `[src|dst] host NUMERIC_IP`. 우선순위는 `not > and > or`입니다. `&&`, `||`, `!`도 토큰으로 사용할 수 있습니다. 필터는 최대 4095바이트, 128노드, 명시적인 중첩 32단계까지입니다. IPv6는 축약 표기와 IPv4-mapped 표기를 입력할 수 있습니다.

필터는 사용자 공간에서 적용합니다. `-s`로 줄이기 전에 수신한 바이트로 필터를 판단하며, 텍스트와 PCAP에는 `-s` 제한을 적용합니다. 파일 입력에서 이미 잘린 헤더는 복원하지 않습니다. 첫 번째가 아닌 IP 단편은 `port`에 일치시키지 않습니다. `host`는 파싱 가능한 IPv4 ARP 주소에도 일치하고 `ip`는 ARP에 일치하지 않습니다.

## 운영상 한계

- tcpdump 전체 기능/문법의 대체품은 아닙니다. 커널 BPF/eBPF **필터 컴파일**, DNS 이름 필터, `net`, 포트 범위, 프로토콜별 상세 분석, 회전 저장, 원격 전송은 미구현입니다. Mac의 BPF 장치 캡처와 커널 필터 컴파일은 별개입니다.
- 고속 링크에서 무손실을 보장하지 않습니다. 사용자 공간 필터·동기 출력 구조이므로 `-q -w FILE`을 쓰고 Linux의 `socket_drops` 또는 Mac의 `bpf_drops`를 확인하세요. 하드웨어/드라이버 손실은 이 통계에 포함되지 않을 수 있습니다.
- Linux의 `any`는 SLL v1이며 promiscuous 모드를 요청하지 않습니다. 이름을 지정한 Linux 캡처는 Ethernet/loopback만 지원하며 loopback의 송신 중복은 제외합니다. Mac은 인터페이스 하나의 Ethernet/NULL/LOOP/RAW를 지원하며 `any`는 미구현입니다.
- NIC VLAN offload가 제거한 태그와 FCS는 복원하지 않습니다. GRO/GSO/TSO 때문에 보이는 길이/패킷은 실제 wire frame과 다를 수 있습니다. VLAN 필터는 수신 바이트에 태그가 있을 때 동작합니다.
- 최대 캡처/입력 레코드는 65535바이트입니다. IPv6 jumbogram, PCAPNG, SLL2, 무선 radiotap, 암호화된 페이로드, IP/TCP 재조립은 지원하지 않습니다. 최대 VLAN 8개, IPv6 확장 헤더 16개를 해석합니다.
- i386의 레거시 time ABI와 macOS 기본 BPF 헤더의 32비트 초 필드는 2038년 이후 live timestamp를 지원하지 않습니다. Linux x86_64도 classic PCAP 초 필드 범위를 넘는 날짜는 기록할 수 없습니다. 나노초 입력은 마이크로초로 절삭해 출력합니다.
- `seen`은 사용자 공간에서 처리한 패킷, `matched`/`matched_bytes`는 필터 일치 건수/원래 길이입니다. 커널 통계에는 loopback 중복과 큐에 남은 패킷도 포함될 수 있습니다. 통계가 지원되지 않으면 socket 통계 필드를 표시하지 않습니다.

## 개발 검증

```sh
make test                    # 현재 플랫폼의 바이너리 검사 + PCAP/필터/오류 처리
make test-live               # 자체 생성 loopback 트래픽, 캡처 권한 필요
make PLATFORM=linux ARCH=i386 RUNNER=qemu-i386 test
make sanitize               # ASan + UBSan, 호스트 C 컴파일러 사용
```

32비트 실제 커널 검증과 사용자 모드 에뮬레이터의 제약은 [검증 기록](docs/VALIDATION.md)을 보세요. 구현상 ABI 결정은 [호환성 설계](docs/COMPATIBILITY.md)에 설명했습니다.

## 라이선스

[MIT License](LICENSE).
