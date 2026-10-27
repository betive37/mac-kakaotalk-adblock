# macOS KakaoTalk 광고 차단 패치

KakaoTalk 26.9.0 (2006)의 기존 비광고 분기를 사용하는, 복원 가능한 macOS 실행 파일 패치입니다.

`install.sh` 하나에 패치 엔진이 포함되어 있습니다. 추가 소스 다운로드, pip 설치, 상주 프로세스가 필요하지 않습니다. 기본 대상은 **`/Applications/KakaoTalk.app`**입니다.


## 지원 대상과 요구 사항

| 항목 | 지원 값 |
|---|---|
| Bundle ID | `com.kakao.KakaoTalkMac` |
| 버전 / 빌드 | `26.9.0` / `2006` |
| 실행 파일 architecture | `x86_64`, `arm64` |
| 원본 실행 파일 SHA-256 | `456e1a3ed7a87168888bdb8c6e4894764a028e62c0af68562a760d9909d2bb65` |
| 실행 환경 | macOS, Python 3.9 이상, macOS 기본 `codesign`·`lipo`·`pgrep` 등 |

다른 버전·빌드·해시, 불완전한 패치, 예상하지 못한 Mach-O 구조는 거부합니다. 업데이트된 앱에 같은 오프셋을 임의로 적용하지 마세요. Python은 자동 설치하지 않습니다.

재서명 후 아키텍처별 코드 영역의 시작 위치·정렬이 달라져도 파일에 기록된 실제 위치에서 패치와 코드 무결성을 검사합니다. 잘못된 CPU 종류, 겹치는 영역, 파일 범위를 벗어난 영역, 잘못된 정렬은 거부합니다. 줄어든 서명 뒤의 잔여 바이트는 원래 서명 예약 크기 안에서 다음 코드 영역과 겹치지 않는 부분에 한해 값이 모두 0인지 별도로 검사하지 않습니다.

원본 실행 파일의 전체 해시 검사, 광고 차단 코드와 허용된 서명·배치 메타데이터 외의 변경 검사, macOS `codesign --verify --deep --strict` 검증, 원본 권한(entitlements) 보존 검사는 유지합니다. 패치 적용 중 재서명 검증 실패 시 원본으로 복원합니다. macOS 26.7.1에서 Apple `lipo`로 재배치한 실제 서명 앱의 상태 확인·재서명·원본 복원을 검증했습니다. macOS 27.2의 보고된 오류가 해결됐는지는 해당 환경에서 확인이 필요합니다.

## 설치

카카오톡을 먼저 직접 종료하세요. 도구는 프로세스를 강제로 종료하지 않습니다. 앱과 백업 경로에 대한 쓰기 권한이 필요하며, 권한 오류가 나도 자동으로 `sudo`를 실행하지 않습니다.

### GitHub에서 받아 실행

```sh
curl -fsSL https://raw.githubusercontent.com/betive37/mac-kakaotalk-adblock/main/install.sh | sh
```

상태 확인과 원상 복원:

```sh
curl -fsSL https://raw.githubusercontent.com/betive37/mac-kakaotalk-adblock/main/install.sh | sh -s -- status
curl -fsSL https://raw.githubusercontent.com/betive37/mac-kakaotalk-adblock/main/install.sh | sh -s -- restore
```

프로젝트 소스는 [MIT License](LICENSE), Copyright (c) 2026 betive37입니다. 카카오톡 앱·독점 실행 파일·백업은 배포물이나 MIT 라이선스 적용 대상에 포함되지 않습니다.
