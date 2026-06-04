# 연구 한계

본 연구의 핵심 정량 비교는 로컬 실습용 화상회의 웹 클라이언트와 OWASP ZAP Baseline Scan 결과를 중심으로 수행되었다.

추가로 Docker 기반 Jitsi Meet self-hosted 환경에서 웹, Prosody, Jicofo, Jitsi Videobridge, Jibri 컨테이너 기동, 인증/JWT, ICE 후보, Nmap, ZAP Baseline 결과를 보조 검증하였다. 이 검증을 통해 실제 화상회의 스택에서 게스트 입장 정책, JWT 권한 해석, TURN relay 미사용, 웹 보안 헤더 미흡, Jibri recorder 구성 문제가 남는다는 점을 확인했다.

다만 장기 부하, TURN relay 강제, 실제 녹화 파일 생성, 모바일 앱, 운영망 로그와 개인정보 정책까지 일반화하려면 별도 운영 환경 검증이 필요하다. 6주 내 학부 수준 연구라는 조건에서는 STRIDE 기반 설계 위협과 ZAP 기반 실행 환경 경고를 동일한 OWASP Top 10 기준으로 매핑하고, 보안 헤더 적용 전후 경고 감소와 Jitsi Meet 구성요소별 실제 점검 결과까지 확인했다는 점에서 실증적 의미가 있다.
