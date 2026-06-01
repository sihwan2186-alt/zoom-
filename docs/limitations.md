# 연구 한계

본 연구는 로컬 실습용 화상회의 웹 클라이언트와 OWASP ZAP Baseline Scan 결과를 중심으로 수행되었다.

따라서 실제 운영형 Jitsi Meet 전체 구성요소인 TURN, XMPP, Jicofo, Jitsi Videobridge, 녹화 저장소, 인증 서버 전체를 검증한 결과로 일반화하기에는 제한이 있다.

다만 6주 내 학부 수준 연구라는 조건에서는 STRIDE 기반 설계 위협과 ZAP 기반 실행 환경 경고를 동일한 OWASP Top 10 기준으로 매핑하고, 보안 헤더 적용 전후 경고 감소를 확인했다는 점에서 실증적 의미가 있다.
